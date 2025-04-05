package dirbrute

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zarni99/bbrecon/pkg/config"
	"github.com/zarni99/bbrecon/pkg/output"
)

type Scanner struct {
	Target		string
	Config		config.DirBruteConfig
	Timeout		int
	Results		[]DirResult
	mutex		sync.Mutex
	httpClient	*http.Client
	successCodes	map[int]bool
}

type DirResult struct {
	Target		string		`json:"target"`
	Path		string		`json:"path"`
	URL		string		`json:"url"`
	StatusCode	int		`json:"status_code"`
	ContentType	string		`json:"content_type,omitempty"`
	ContentLength	int64		`json:"content_length"`
	ResponseTime	time.Duration	`json:"response_time"`
}

func NewScanner(target string, cfg config.DirBruteConfig, timeout int) *Scanner {
	successCodes := make(map[int]bool)
	for _, code := range cfg.StatusCodes {
		successCodes[code] = true
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:	true,
	}

	client := &http.Client{
		Transport:	transport,
		Timeout:	time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !cfg.FollowRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &Scanner{
		Target:		target,
		Config:		cfg,
		Timeout:	timeout,
		Results:	[]DirResult{},
		mutex:		sync.Mutex{},
		httpClient:	client,
		successCodes:	successCodes,
	}
}

func (s *Scanner) Run() ([]output.Finding, error) {
	var findings []output.Finding
	var wg sync.WaitGroup
	var resultsLock sync.Mutex

	target := s.Target
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	target = strings.TrimSuffix(target, "/")

	wordlist, err := loadWordlist(s.Config.WordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %v", err)
	}

	totalPaths := 0
	for _, word := range wordlist {
		if word == "" {
			continue
		}

		totalPaths++

		for _, ext := range s.Config.Extensions {
			if !strings.HasSuffix(word, ext) {
				totalPaths++
			}
		}
	}

	fmt.Println()
	fmt.Printf("Starting to check %d paths...\n", totalPaths)

	semaphore := make(chan struct{}, s.Config.Concurrency)

	var checkedPaths int32
	var foundPaths int32

	stopProgress := make(chan bool)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				checked := atomic.LoadInt32(&checkedPaths)
				found := atomic.LoadInt32(&foundPaths)
				progress := float64(checked) / float64(totalPaths) * 100
				fmt.Printf("\rProgress: %.2f%% (%d/%d paths checked, %d found)",
					progress, checked, totalPaths, found)
			case <-stopProgress:
				return
			}
		}
	}()

	for _, word := range wordlist {
		if word == "" {
			continue
		}

		if !strings.HasPrefix(word, "/") {
			word = "/" + word
		}

		wordlist := []string{word}
		for _, ext := range s.Config.Extensions {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}

			if !strings.HasSuffix(word, ext) {
				wordlist = append(wordlist, word+ext)
			}
		}

		for _, path := range wordlist {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(path string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				url := target + path
				found, result := s.checkPath(url)

				atomic.AddInt32(&checkedPaths, 1)

				if found {
					atomic.AddInt32(&foundPaths, 1)

					resultsLock.Lock()
					s.Results = append(s.Results, result)

					severity := "info"
					if strings.Contains(path, "admin") || strings.Contains(path, "login") ||
						strings.Contains(path, "config") || strings.Contains(path, "backup") {
						severity = "medium"
					}

					if result.StatusCode == 200 &&
						(strings.HasSuffix(path, ".bak") || strings.HasSuffix(path, ".swp") ||
							strings.HasSuffix(path, ".old") || strings.HasSuffix(path, ".backup")) {
						severity = "high"
					}

					finding := output.NewFinding(
						"Directory",
						target,
						"Directory Brute-Force",
						fmt.Sprintf("Found resource: %s (Status: %d)", path, result.StatusCode),
						severity,
						map[string]interface{}{
							"url":			url,
							"path":			path,
							"status_code":		result.StatusCode,
							"content_type":		result.ContentType,
							"content_length":	result.ContentLength,
							"response_time":	result.ResponseTime.String(),
						},
					)

					findings = append(findings, finding)
					resultsLock.Unlock()
				}
			}(path)
		}
	}

	wg.Wait()

	checked := atomic.LoadInt32(&checkedPaths)
	found := atomic.LoadInt32(&foundPaths)
	fmt.Printf("\rProgress: 100.00%% (%d/%d paths checked, %d found)\n",
		checked, totalPaths, found)

	close(stopProgress)

	return findings, nil
}

func (s *Scanner) checkPath(url string) (bool, DirResult) {
	result := DirResult{
		Target:	s.Target,
		URL:	url,
		Path:	strings.TrimPrefix(url, s.Target),
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, result
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	startTime := time.Now()
	resp, err := s.httpClient.Do(req)
	responseTime := time.Since(startTime)
	result.ResponseTime = responseTime

	if err != nil {
		return false, result
	}
	defer resp.Body.Close()

	if !s.successCodes[resp.StatusCode] {
		return false, result
	}

	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.ContentLength = resp.ContentLength

	return true, result
}

func loadWordlist(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())

		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return words, nil
}

func GenerateWordlist(target string, technologies []string) []string {
	var wordlist []string

	commonPaths := []string{
		"/",
		"/robots.txt",
		"/sitemap.xml",
		"/favicon.ico",
		"/.well-known/security.txt",
		"/crossdomain.xml",
		"/clientaccesspolicy.xml",
		"/admin",
		"/login",
		"/wp-login.php",
		"/administrator",
		"/phpmyadmin",
		"/server-status",
		"/phpinfo.php",
		"/.git/HEAD",
		"/.env",
		"/.htaccess",
		"/config.php",
		"/backup",
		"/backup.zip",
		"/backup.tar.gz",
		"/db.sql",
		"/database.sql",
	}

	wordlist = append(wordlist, commonPaths...)

	for _, tech := range technologies {
		techLower := strings.ToLower(tech)

		switch {
		case strings.Contains(techLower, "wordpress"):
			wpPaths := []string{
				"/wp-admin/",
				"/wp-content/",
				"/wp-content/uploads/",
				"/wp-content/plugins/",
				"/wp-content/themes/",
				"/wp-config.php",
				"/wp-login.php",
				"/xmlrpc.php",
			}
			wordlist = append(wordlist, wpPaths...)

		case strings.Contains(techLower, "joomla"):
			joomlaPaths := []string{
				"/administrator/",
				"/components/",
				"/modules/",
				"/templates/",
				"/configuration.php",
				"/htaccess.txt",
			}
			wordlist = append(wordlist, joomlaPaths...)

		case strings.Contains(techLower, "drupal"):
			drupalPaths := []string{
				"/sites/default/",
				"/sites/default/settings.php",
				"/sites/default/files/",
				"/modules/",
				"/themes/",
				"/CHANGELOG.txt",
				"/core/CHANGELOG.txt",
				"/includes/",
			}
			wordlist = append(wordlist, drupalPaths...)

		case strings.Contains(techLower, "laravel"):
			laravelPaths := []string{
				"/.env",
				"/storage/",
				"/public/",
				"/artisan",
				"/routes/web.php",
				"/vendor/",
			}
			wordlist = append(wordlist, laravelPaths...)

		case strings.Contains(techLower, "django"):
			djangoPaths := []string{
				"/admin/",
				"/static/",
				"/media/",
				"/django-admin/",
			}
			wordlist = append(wordlist, djangoPaths...)

		case strings.Contains(techLower, "php"):
			phpPaths := []string{
				"/index.php",
				"/phpinfo.php",
				"/info.php",
				"/config.php",
				"/php.ini",
			}
			wordlist = append(wordlist, phpPaths...)
		}
	}

	uniqueMap := make(map[string]bool)
	var uniqueWords []string

	for _, word := range wordlist {
		if !uniqueMap[word] {
			uniqueMap[word] = true
			uniqueWords = append(uniqueWords, word)
		}
	}

	return uniqueWords
}
