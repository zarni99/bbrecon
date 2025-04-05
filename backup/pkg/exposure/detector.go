package exposure

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Finding struct {
	Type        string                 `json:"type"`
	URL         string                 `json:"url"`
	Value       string                 `json:"value"`
	Severity    string                 `json:"severity"`
	Additional  map[string]interface{} `json:"additional,omitempty"`
	POC         string                 `json:"poc,omitempty"`
	LineNumber  int                    `json:"line_number,omitempty"`
	StatusCode  int                    `json:"status_code,omitempty"`
	ContentType string                 `json:"content_type,omitempty"`
	Confidence  string                 `json:"confidence,omitempty"`
	Evidence    []string               `json:"evidence,omitempty"`
}

type Detector struct {
	Client   *http.Client
	Patterns map[string]*regexp.Regexp
	Findings []Finding
	mu       sync.Mutex
}

func NewDetector() *Detector {
	return &Detector{
		Client:   &http.Client{Timeout: time.Second * 10},
		Patterns: initPatterns(),
		Findings: make([]Finding, 0),
	}
}

func initPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{

		"AWS_KEY":         regexp.MustCompile(`(?i)(AKIA[A-Z0-9]{16}|aws_access_key_id|aws_secret_access_key)`),
		"GITHUB_TOKEN":    regexp.MustCompile(`(?i)(gh[pos]_[a-zA-Z0-9]{36}|github_token|gh_token)`),
		"STRIPE_KEY":      regexp.MustCompile(`(?i)(sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24})`),
		"GOOGLE_API":      regexp.MustCompile(`(?i)(AIza[0-9A-Za-z\\-_]{35}|google_api_key|google_cloud_key)`),
		"SLACK_TOKEN":     regexp.MustCompile(`(?i)(xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`),
		"DISCORD_TOKEN":   regexp.MustCompile(`(?i)(discord[._]token|discord[._]webhook)`),
		"NPM_TOKEN":       regexp.MustCompile(`(?i)(npm_[A-Za-z0-9]{36}|npm[._]token|npmtoken)`),
		"DOCKER_AUTH":     regexp.MustCompile(`(?i)(docker[._]auth|docker[._]config|dockercfg)`),
		"SSH_KEY":         regexp.MustCompile(`(?i)(ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}|-----BEGIN( RSA| OPENSSH)? PRIVATE KEY-----)`),
		"PGP_KEY":         regexp.MustCompile(`(?i)(-----BEGIN PGP (PRIVATE|PUBLIC) KEY BLOCK-----)`),
		"CLOUDFLARE_KEY":  regexp.MustCompile(`(?i)([0-9a-fA-F]{37}|cloudflare[._]key|cf[._]key)`),
		"MAILCHIMP_KEY":   regexp.MustCompile(`(?i)([0-9a-f]{32}-us[0-9]{1,2}|mailchimp[._]api[._]key)`),
		"GITLAB_PAT":      regexp.MustCompile(`(?i)(glpat-[0-9a-zA-Z\-_]{20}|gitlab[._]token)`),
		"AZURE_KEY":       regexp.MustCompile(`(?i)([0-9a-zA-Z]{88}|azure[._]key|azure[._]token)`),
		"GCP_SERVICE_KEY": regexp.MustCompile(`(?i)("type": "service_account"|gcp[._]credentials|google[._]credentials)`),
		"HEROKU_API":      regexp.MustCompile(`(?i)(heroku[._]api[._]key|heroku[._]token)`),
		"TWILIO_KEY":      regexp.MustCompile(`(?i)(SK[0-9a-fA-F]{32}|twilio[._]token|twilio[._]key)`),
		"SENDGRID_KEY":    regexp.MustCompile(`(?i)(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}|sendgrid[._]api[._]key)`),
		"SQUARE_KEY":      regexp.MustCompile(`(?i)(sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[0-9A-Za-z\-_]{43}|square[._]key)`),
		"PAYPAL_KEY":      regexp.MustCompile(`(?i)(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}|paypal[._]key)`),
		"ENV_FILE":        regexp.MustCompile(`(?i)(\.env.*|env\..*|application\.properties|application\.ya?ml|config\.ya?ml|\.env\.(dev|prod|stage|local|test))`),
		"CONFIG_FILE":     regexp.MustCompile(`(?i)(config\.(js|json|xml|ya?ml|ini|conf)|settings\.(js|json|xml|ya?ml|ini|conf)|configuration\.(js|json|xml|ya?ml|ini|conf))`),
		"BACKUP_FILE":     regexp.MustCompile(`(?i)(\.(bak|backup|old|temp|tmp|swp|save|~)$|[._]copy$)`),
		"LOG_FILE":        regexp.MustCompile(`(?i)(\.(log|logs)$|error[._]log|access[._]log|debug[._]log|.*\.log\.[0-9]+)`),
		"DB_FILE":         regexp.MustCompile(`(?i)(\.(sql|sqlite|db|database)$|dump\.sql|database\.sql|db\.json)`),
		"DOCKER_FILE":     regexp.MustCompile(`(?i)(Dockerfile|docker-compose\.ya?ml|\.dockerignore|docker[._]config\.json)`),
		"KUBE_CONFIG":     regexp.MustCompile(`(?i)(kubeconfig|kube[._]config|\.kube/config|kubelet\.conf)`),
		"CERT_FILE":       regexp.MustCompile(`(?i)(\.(crt|key|pem|csr|crl|p12|pfx|jks|keystore|cert)$|ssl/.*\.key)`),
		"PASSWORD_FILE":   regexp.MustCompile(`(?i)(\.htpasswd|\.htaccess|passwd|shadow|master\.key|passwords\.(txt|xml|json))`),
		"WP_CONFIG":       regexp.MustCompile(`(?i)(wp-config\.php|wordpress/.*config.*\.php)`),
		"GIT_CONFIG":      regexp.MustCompile(`(?i)(\.git/config|\.gitconfig|\.git-credentials)`),
		"SSH_CONFIG":      regexp.MustCompile(`(?i)(\.ssh/config|authorized_keys|known_hosts|id_rsa|id_dsa)`),
		"CACHE_FILE":      regexp.MustCompile(`(?i)(\.cache/.*|\.npm/.*|\.yarn/.*|composer\.lock|package-lock\.json|yarn\.lock)`),
		"HISTORY_FILE":    regexp.MustCompile(`(?i)(\.bash_history|\.zsh_history|\.shell_history|\.mysql_history|\.psql_history)`),
	}
}

func (d *Detector) Detect(url string) error {
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	// Check common paths for sensitive files
	paths := []string{
		"/.git/config",
		"/.env",
		"/config.js",
		"/config.json",
		"/wp-config.php",
		"/.htpasswd",
		"/credentials.json",
		"/database.yml",
		"/settings.py",
	}

	var wg sync.WaitGroup
	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			d.checkPath(url + p)
		}(path)
	}

	// Check JavaScript files
	jsFiles, err := d.findJavaScriptFiles(url)
	if err == nil {
		for _, jsFile := range jsFiles {
			wg.Add(1)
			go func(js string) {
				defer wg.Done()
				d.analyzeJavaScript(js)
			}(jsFile)
		}
	}

	wg.Wait()
	return nil
}

func (d *Detector) checkPath(url string) {
	resp, err := d.Client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 403 {
		contentType := resp.Header.Get("Content-Type")

		// Determine severity and confidence based on file type
		severity, confidence := d.determineSeverityAndConfidence(url)

		// Verify content and collect evidence if possible
		evidence := []string{}

		// For text-based content types, verify content before adding to findings
		if strings.Contains(contentType, "text") ||
			strings.Contains(contentType, "javascript") ||
			strings.Contains(contentType, "json") ||
			strings.Contains(contentType, "xml") ||
			strings.Contains(contentType, "html") {

			// Clone the response body so we can read it twice
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			// Use one copy for verification
			bodyReader1 := io.NopCloser(bytes.NewBuffer(bodyBytes))
			verified, snippets := d.verifyContent(url, contentType, bodyReader1)

			if verified {
				confidence = "High"
				evidence = snippets
			} else if confidence != "Low" {
				confidence = "Medium"
			}

			// Use the other copy for content analysis
			bodyReader2 := io.NopCloser(bytes.NewBuffer(bodyBytes))
			if confidence != "Low" {
				d.analyzeContent(url, bodyReader2)
			}
		}

		d.mu.Lock()
		d.Findings = append(d.Findings, Finding{
			Type:        "Sensitive File",
			URL:         url,
			Severity:    severity,
			POC:         fmt.Sprintf("curl -i '%s'", url),
			StatusCode:  resp.StatusCode,
			ContentType: contentType,
			Confidence:  confidence,
			Evidence:    evidence,
		})
		d.mu.Unlock()
	}
}

// determineSeverityAndConfidence evaluates the URL to determine appropriate severity and confidence
func (d *Detector) determineSeverityAndConfidence(url string) (string, string) {
	// Default values
	severity := "HIGH"
	confidence := "Medium"

	// Check for high-risk, high-confidence patterns
	highRiskPatterns := []string{
		"/.env",
		"/.git/config",
		"/wp-config.php",
		"/.htpasswd",
		"/credentials.json",
		"/id_rsa",
		"/id_dsa",
		"/.ssh/id_rsa",
		"/authorized_keys",
	}

	// Check for medium-risk patterns
	mediumRiskPatterns := []string{
		"/config.js",
		"/config.json",
		"/settings.py",
		"/database.yml",
		"/application.properties",
		"/application.yaml",
		"/application.yml",
	}

	for _, pattern := range highRiskPatterns {
		if strings.Contains(url, pattern) {
			return "HIGH", "Medium"
		}
	}

	for _, pattern := range mediumRiskPatterns {
		if strings.Contains(url, pattern) {
			return "MEDIUM", "Medium"
		}
	}

	return severity, confidence
}

// verifyContent performs deeper analysis on file contents to confirm it's actually sensitive
func (d *Detector) verifyContent(url string, contentType string, reader io.Reader) (bool, []string) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // Increase buffer size for larger files

	evidence := []string{}
	matchCount := 0
	totalChecks := 0

	// Read up to 25 lines
	lineCount := 0
	for scanner.Scan() && lineCount < 25 {
		line := scanner.Text()
		lineCount++

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Check file-specific patterns
		if strings.Contains(url, ".env") {
			totalChecks++
			// Look for KEY=VALUE pattern common in .env files
			if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=.+`).MatchString(line) {
				matchCount++
				if len(evidence) < 3 {
					evidence = append(evidence, line)
				}
			}
		} else if strings.Contains(url, "config.js") || strings.Contains(url, "config.json") {
			totalChecks++
			// Look for config structure in JS/JSON files
			configPattern := regexp.MustCompile(`(["']?(api[Kk]ey|secret|password|key|token|auth|credential|pwd)["']?\s*:)`)
			if configPattern.MatchString(line) {
				matchCount++
				if len(evidence) < 3 {
					evidence = append(evidence, line)
				}
			}
		} else if strings.Contains(url, ".git/config") {
			totalChecks++
			// Look for git config patterns
			if regexp.MustCompile(`\[remote|\[core|\[user`).MatchString(line) ||
				strings.Contains(line, "url = ") {
				matchCount++
				if len(evidence) < 3 {
					evidence = append(evidence, line)
				}
			}
		} else if strings.Contains(url, "wp-config.php") {
			totalChecks++
			// Look for WordPress config patterns
			if regexp.MustCompile(`define\(\s*['"]DB_|define\(\s*['"]AUTH`).MatchString(line) {
				matchCount++
				if len(evidence) < 3 {
					evidence = append(evidence, line)
				}
			}
		} else if strings.Contains(url, ".htpasswd") {
			totalChecks++
			// Look for htpasswd format (user:hash)
			if regexp.MustCompile(`^[^:]+:\$\w+\$`).MatchString(line) {
				matchCount++
				if len(evidence) < 3 {
					evidence = append(evidence, line)
				}
			}
		} else if strings.Contains(url, "database.yml") || strings.Contains(url, "settings.py") {
			totalChecks++
			// Look for database connection strings or settings
			if regexp.MustCompile(`(database|username|password|host|port|adapter):`).MatchString(line) ||
				regexp.MustCompile(`(DATABASE|SECRET_KEY|PASSWORD|USERNAME) = `).MatchString(line) {
				matchCount++
				if len(evidence) < 3 {
					evidence = append(evidence, line)
				}
			}
		} else {
			// Generic sensitive pattern check for other files
			totalChecks++
			sensitivePatterns := []*regexp.Regexp{
				regexp.MustCompile(`(?i)(api_?key|apikey|secret|password|credential|token|auth)`),
				regexp.MustCompile(`(?i)(username|user|login|email).{0,20}(=|:).{0,20}['"][^'"]{3,}['"]`),
				regexp.MustCompile(`(?i)(password|secret|token|key).{0,20}(=|:).{0,20}['"][^'"]{3,}['"]`),
				regexp.MustCompile(`(?i)(BEGIN|PRIVATE KEY|ssh-rsa)`),
			}

			for _, pattern := range sensitivePatterns {
				if pattern.MatchString(line) {
					matchCount++
					if len(evidence) < 3 {
						evidence = append(evidence, line)
					}
					break
				}
			}
		}
	}

	// Consider it verified if enough matching patterns found
	if totalChecks > 0 && float64(matchCount)/float64(totalChecks) > 0.25 {
		return true, evidence
	}

	return false, evidence
}

// analyzeContent scans file content for sensitive information patterns
func (d *Detector) analyzeContent(url string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // Increase buffer size

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for patternName, pattern := range d.Patterns {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) > 0 {
				value := matches[0]
				if len(matches) > 1 && matches[1] != "" {
					value = matches[1]
				}

				// Evaluate entropy of the value to reduce false positives
				// Skip low-entropy values that are likely not real secrets
				if d.isLikelySecret(value, patternName) {
					d.mu.Lock()
					d.Findings = append(d.Findings, Finding{
						Type:       patternName,
						URL:        url,
						Value:      value,
						Severity:   "HIGH",
						LineNumber: lineNum,
						POC:        d.generatePOC(patternName, value),
						Confidence: "High",
						Evidence:   []string{line},
					})
					d.mu.Unlock()
				}
			}
		}
	}
}

// isLikelySecret evaluates if a string is likely to be a real secret based on entropy and context
func (d *Detector) isLikelySecret(s string, patternName string) bool {
	// Skip very short strings that are likely false positives
	if len(s) < 8 && !strings.HasPrefix(patternName, "ENV_") &&
		!strings.HasPrefix(patternName, "CONFIG_") &&
		!strings.HasPrefix(patternName, "FILE_") {
		return false
	}

	// Skip common false positives
	falsePositives := []string{
		"example", "placeholder", "yourkey", "your-key", "your_key",
		"your-token", "your_token", "yourtoken", "yourpassword",
		"your-password", "your_password", "undefined", "null", "example.com",
	}

	for _, fp := range falsePositives {
		if strings.Contains(strings.ToLower(s), fp) {
			return false
		}
	}

	// For certain types, always consider them valuable
	if strings.HasPrefix(patternName, "AWS_") ||
		strings.HasPrefix(patternName, "GOOGLE_") ||
		strings.HasPrefix(patternName, "GITHUB_") ||
		strings.HasPrefix(patternName, "SSH_") ||
		strings.HasPrefix(patternName, "PGP_") {
		return true
	}

	// Calculate Shannon entropy for strings that might be secrets
	// Higher entropy = more random = more likely to be a real secret
	if d.calculateEntropy(s) >= 3.5 {
		return true
	}

	return false
}

// calculateEntropy calculates the Shannon entropy of a string
// Higher values indicate more randomness, which is typical of secrets
func (d *Detector) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, c := range s {
		charCounts[c]++
	}

	entropy := 0.0
	for _, count := range charCounts {
		freq := float64(count) / float64(len(s))
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

func (d *Detector) generatePOC(patternName, value string) string {
	switch patternName {
	case "AWS_KEY":
		return "aws sts get-caller-identity --access-key " + value
	case "GITHUB_TOKEN":
		return "curl -H 'Authorization: Bearer " + value + "' https://api.github.com/user"
	case "JWT_TOKEN":
		return "curl -H 'Authorization: Bearer " + value + "' https://api.example.com"
	default:
		return ""
	}
}

func (d *Detector) findJavaScriptFiles(baseURL string) ([]string, error) {
	resp, err := d.Client.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	jsFiles := make([]string, 0)
	scanner := bufio.NewScanner(resp.Body)
	jsPattern := regexp.MustCompile(`(?i)src=["']([^"']+\.js)["']`)

	for scanner.Scan() {
		matches := jsPattern.FindAllStringSubmatch(scanner.Text(), -1)
		for _, match := range matches {
			if len(match) > 1 {
				jsFile := match[1]
				if !strings.HasPrefix(jsFile, "http") {
					if strings.HasPrefix(jsFile, "/") {
						jsFile = baseURL + jsFile
					} else {
						jsFile = baseURL + "/" + jsFile
					}
				}
				jsFiles = append(jsFiles, jsFile)
			}
		}
	}

	return jsFiles, nil
}

func (d *Detector) analyzeJavaScript(url string) {
	resp, err := d.Client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	d.analyzeContent(url, resp.Body)
}
