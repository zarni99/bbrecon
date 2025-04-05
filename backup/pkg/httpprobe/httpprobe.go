package httpprobe

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zarni99/bbrecon/pkg/config"
	"github.com/zarni99/bbrecon/pkg/output"
)

type Progress interface {
	UpdateProgress(current, total int, result *ProbeResult)
}

type ProbeProgress struct {
	Total          int
	Current        int
	Found          int
	StartTime      time.Time
	LastResult     *ProbeResult
	LastUpdateTime time.Time
	Speed          float64
	ETA            time.Duration
	mu             sync.Mutex
}

func NewProbeProgress(total int) *ProbeProgress {
	return &ProbeProgress{
		Total:          total,
		StartTime:      time.Now(),
		LastUpdateTime: time.Now(),
	}
}

func (p *ProbeProgress) UpdateProgress(current, total int, result *ProbeResult) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.Current = current
	now := time.Now()

	duration := now.Sub(p.LastUpdateTime).Seconds()
	if duration > 0 {
		p.Speed = float64(current-p.Current) / duration
	}

	if p.Speed > 0 {
		remainingItems := float64(total - current)
		p.ETA = time.Duration(remainingItems/p.Speed) * time.Second
	}

	if result != nil {
		p.Found++
		p.LastResult = result
	}

	p.LastUpdateTime = now
}

func (p *ProbeProgress) GetStats() (current, total, found int, speed float64, eta time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Current, p.Total, p.Found, p.Speed, p.ETA
}

type Prober struct {
	Config  config.HTTPProbeConfig
	Targets []string
	Timeout int
	Results []ProbeResult
	mutex   sync.Mutex
}

type ProbeResult struct {
	Target          string             `json:"target"`
	StatusCode      int                `json:"status_code"`
	ContentType     string             `json:"content_type,omitempty"`
	Title           string             `json:"title,omitempty"`
	Headers         map[string]string  `json:"headers,omitempty"`
	Technologies    []TechnologyResult `json:"technologies,omitempty"`
	ResponseSize    int64              `json:"response_size"`
	TLS             *TLSInfo           `json:"tls,omitempty"`
	ResponseTime    time.Duration      `json:"response_time"`
	FaviconHash     string             `json:"favicon_hash,omitempty"`
	WebServer       string             `json:"web_server,omitempty"`
	SecurityHeaders map[string]bool    `json:"security_headers,omitempty"`
	HTTPVersion     string             `json:"http_version,omitempty"`
	RedirectURL     string             `json:"redirect_url,omitempty"`
	ScreenshotPath  string             `json:"screenshot_path,omitempty"`
	StatusLine      string             `json:"status_line,omitempty"`
	ContentLanguage string             `json:"content_language,omitempty"`
	IP              string             `json:"ip,omitempty"`
	Port            int                `json:"port"`
	Scheme          string             `json:"scheme"`
	Host            string             `json:"host"`
	Path            string             `json:"path"`
	Query           string             `json:"query,omitempty"`
	Severity        string             `json:"severity"`
}

type TechnologyResult struct {
	Name        string            `json:"name"`
	Version     string            `json:"version,omitempty"`
	Category    string            `json:"category,omitempty"`
	Confidence  int               `json:"confidence"`
	Website     string            `json:"website,omitempty"`
	CPE         string            `json:"cpe,omitempty"`
	DetectedBy  string            `json:"detected_by,omitempty"`
	Description string            `json:"description,omitempty"`
	Icon        string            `json:"icon,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

type TLSInfo struct {
	Version            string   `json:"version"`
	Issuer             string   `json:"issuer"`
	Subject            string   `json:"subject"`
	DNSNames           []string `json:"dns_names,omitempty"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
}

type TechFingerprint struct {
	Category    string
	Patterns    []string
	HeaderRules map[string]string
	Version     func(string, map[string]string) string
}

// TechFingerprints struct represents the technology fingerprint database
type TechFingerprints struct {
	Technologies []TechFingerprintData `json:"technologies"`
}

// TechFingerprintData struct represents a technology fingerprint
type TechFingerprintData struct {
	Name              string            `json:"name"`
	Category          string            `json:"category"`
	Website           string            `json:"website"`
	DetectionPatterns DetectionPatterns `json:"detectionPatterns"`
	VersionRegex      string            `json:"versionRegex"`
}

// DetectionPatterns contains patterns for detecting technologies
type DetectionPatterns struct {
	Headers map[string]string `json:"headers"`
	HTML    []string          `json:"html"`
	Scripts []string          `json:"scripts"`
}

func NewProber(targets []string, cfg config.HTTPProbeConfig, timeout int) *Prober {
	return &Prober{
		Config:  cfg,
		Targets: targets,
		Timeout: timeout,
		Results: []ProbeResult{},
		mutex:   sync.Mutex{},
	}
}

func (p *Prober) Run(progress ...Progress) ([]output.Finding, error) {
	var findings []output.Finding
	var wg sync.WaitGroup
	var progressTracker Progress
	var current int32
	resultsMap := make(map[string][]ProbeResult)
	resultsMutex := sync.Mutex{}

	if len(progress) > 0 && progress[0] != nil {
		progressTracker = progress[0]
	}

	var allTargets []string
	domainSet := make(map[string]bool)

	for _, target := range p.Targets {

		domain := target
		if strings.HasPrefix(domain, "http://") {
			domain = strings.TrimPrefix(domain, "http://")
		} else if strings.HasPrefix(domain, "https://") {
			domain = strings.TrimPrefix(domain, "https://")
		}

		if idx := strings.Index(domain, "/"); idx != -1 {
			domain = domain[:idx]
		}

		if _, exists := domainSet[domain]; !exists {
			domainSet[domain] = true

			if p.Config.HTTPSOnly {
				allTargets = append(allTargets, "https://"+domain)
			} else {
				allTargets = append(allTargets, "http://"+domain, "https://"+domain)
			}
		}
	}

	totalTargets := len(allTargets)
	debugPrint("Testing %d URLs (%d domains with both protocols)", totalTargets, len(domainSet))

	semaphore := make(chan struct{}, p.Config.Concurrency)
	resultsChan := make(chan ProbeResult, totalTargets)

	go func() {
		for result := range resultsChan {
			resultsMutex.Lock()

			parsedURL, err := neturl.Parse(result.Target)
			if err == nil {
				host := parsedURL.Host
				resultsMap[host] = append(resultsMap[host], result)
			}

			resultsMutex.Unlock()
		}
	}()

	for _, url := range allTargets {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(url string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result, err := p.probe(url)
			if err != nil {

				return
			}

			newCurrent := atomic.AddInt32(&current, 1)
			if progressTracker != nil {
				progressTracker.UpdateProgress(int(newCurrent), totalTargets, &result)
			}

			resultsChan <- result

			p.mutex.Lock()
			p.Results = append(p.Results, result)
			p.mutex.Unlock()
		}(url)
	}

	wg.Wait()
	close(resultsChan)

	resultsMutex.Lock()
	defer resultsMutex.Unlock()

	for host, results := range resultsMap {

		var bestResult ProbeResult

		var successResults []ProbeResult
		for _, r := range results {
			if r.StatusCode >= 200 && r.StatusCode < 400 {
				successResults = append(successResults, r)
			}
		}

		if len(successResults) > 0 {

			httpsFound := false
			for _, r := range successResults {
				if strings.HasPrefix(r.Target, "https://") {
					bestResult = r
					httpsFound = true
					break
				}
			}

			if !httpsFound && len(successResults) > 0 {
				bestResult = successResults[0]
			}
		} else if len(results) > 0 {

			bestResult = results[0]
		} else {

			continue
		}

		finding := output.NewFinding(
			"httpprobe",
			bestResult.Target,
			"Web Application",
			fmt.Sprintf("Found web application: %s [%d] [%d bytes]", bestResult.Target, bestResult.StatusCode, bestResult.ResponseSize),
			getSeverityFromStatusCode(bestResult.StatusCode),
			map[string]interface{}{
				"url":            bestResult.Target,
				"status_code":    bestResult.StatusCode,
				"content_type":   bestResult.ContentType,
				"title":          bestResult.Title,
				"content_length": bestResult.ResponseSize,
				"response_time":  bestResult.ResponseTime.Milliseconds(),
				"server":         bestResult.Headers["Server"],
				"technologies":   bestResult.Technologies,
				"tls":            bestResult.TLS,
				"host":           host,
			},
		)

		// Update the description to include technologies if available
		if len(bestResult.Technologies) > 0 {
			techNames := make([]string, 0, len(bestResult.Technologies))
			for _, tech := range bestResult.Technologies {
				if tech.Version != "" {
					techNames = append(techNames, fmt.Sprintf("%s (%s)", tech.Name, tech.Version))
				} else {
					techNames = append(techNames, tech.Name)
				}
			}

			finding.Description = fmt.Sprintf("Found web application: %s [%d] [%d bytes] [Technologies: %s]",
				bestResult.Target,
				bestResult.StatusCode,
				bestResult.ResponseSize,
				strings.Join(techNames, ", "))
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func (p *Prober) probe(targetURL string) (ProbeResult, error) {
	result := ProbeResult{
		Target:          targetURL,
		Headers:         make(map[string]string),
		SecurityHeaders: make(map[string]bool),
		Severity:        "info",
	}

	parsedURL, err := neturl.Parse(targetURL)
	if err != nil {
		return result, err
	}

	result.Scheme = parsedURL.Scheme
	result.Host = parsedURL.Host
	result.Path = parsedURL.Path
	result.Query = parsedURL.RawQuery

	hostParts := strings.Split(parsedURL.Host, ":")
	if len(hostParts) > 1 {
		result.Port, _ = strconv.Atoi(hostParts[1])
	} else {
		if parsedURL.Scheme == "https" {
			result.Port = 443
		} else {
			result.Port = 80
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: false,
		MaxIdleConns:      100,
		MaxConnsPerHost:   100,
		IdleConnTimeout:   30 * time.Second,
	}

	if p.Config.HTTP2Enabled {
		transport.ForceAttemptHTTP2 = true
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(p.Config.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !p.Config.FollowRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= p.Config.MaxRedirects {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	method := "GET"
	if len(p.Config.Methods) > 0 {
		method = p.Config.Methods[0]
	}

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return result, err
	}

	req.Header.Set("User-Agent", p.Config.UserAgent)
	req.Header.Set("Accept", "*/*")

	for _, header := range p.Config.Headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	startTime := time.Now()
	resp, err := client.Do(req)
	responseTime := time.Since(startTime)
	result.ResponseTime = responseTime

	if err != nil {
		debugPrint("Error probing %s: %v", targetURL, err)
		return result, err
	}

	defer resp.Body.Close()

	debugPrint("Probed %s: %d %s", targetURL, resp.StatusCode, resp.Status)

	result.StatusLine = fmt.Sprintf("%s %d %s", resp.Proto, resp.StatusCode, resp.Status)

	result.HTTPVersion = strings.TrimPrefix(resp.Proto, "HTTP/")

	if loc := resp.Header.Get("Location"); loc != "" {
		result.RedirectURL = loc
	}

	statusCodeFound := false
	if len(p.Config.StatusCodes) == 0 {

		statusCodeFound = true
	} else {
		for _, code := range p.Config.StatusCodes {
			if resp.StatusCode == code {
				statusCodeFound = true
				break
			}
		}
	}

	result.StatusCode = resp.StatusCode
	result.Severity = getSeverityFromStatusCode(resp.StatusCode)

	if statusCodeFound {

		for name, values := range resp.Header {
			result.Headers[name] = strings.Join(values, ", ")
		}

		result.ContentType = resp.Header.Get("Content-Type")
		result.ContentLanguage = resp.Header.Get("Content-Language")

		if server := resp.Header.Get("Server"); server != "" {
			result.WebServer = server
		}

		securityHeaders := map[string]string{
			"Strict-Transport-Security": "",
			"Content-Security-Policy":   "",
			"X-Content-Type-Options":    "",
			"X-Frame-Options":           "",
			"X-XSS-Protection":          "",
		}

		for header := range securityHeaders {
			result.SecurityHeaders[header] = resp.Header.Get(header) != ""
		}

		if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
			if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
				result.ResponseSize = size
			}
		}

		if strings.HasPrefix(targetURL, "https://") && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			result.TLS = &TLSInfo{
				Version:            getTLSVersion(resp.TLS.Version),
				Issuer:             cert.Issuer.CommonName,
				Subject:            cert.Subject.CommonName,
				DNSNames:           cert.DNSNames,
				NotBefore:          cert.NotBefore.Format(time.RFC3339),
				NotAfter:           cert.NotAfter.Format(time.RFC3339),
				SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			}
		}

		if method == "GET" {
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			if err != nil {

			} else {

				if result.ResponseSize == 0 {
					result.ResponseSize = int64(len(body))
				}

				if p.Config.ExtractTitle {
					result.Title = extractTitle(string(body))
				}

				if p.Config.ExtractTechnologies {
					result.Technologies = detectTechnologies(resp.Header, body)
				}
			}
		}

		if p.Config.ExtractFavicon && method == "GET" {
			faviconHash, err := extractFaviconHash(targetURL, client)
			if err == nil {
				result.FaviconHash = faviconHash
			}
		}

		if p.Config.ScreenshotEnabled && method == "GET" {

		}

		return result, nil
	}

	debugPrint("Status code %d not in target list but host is live: %s", resp.StatusCode, targetURL)
	return result, nil
}

func extractTitle(body string) string {
	titleStart := strings.Index(strings.ToLower(body), "<title>")
	if titleStart == -1 {
		return ""
	}

	titleStart += 7
	titleEnd := strings.Index(strings.ToLower(body[titleStart:]), "</title>")
	if titleEnd == -1 {
		return ""
	}

	return strings.TrimSpace(body[titleStart : titleStart+titleEnd])
}

func getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

func detectTechnologies(headers http.Header, body []byte) []TechnologyResult {
	var technologies []TechnologyResult

	// Load and use the technology fingerprint database
	techFingerprints, err := loadTechFingerprints()
	if err == nil && len(techFingerprints.Technologies) > 0 {
		bodyStr := string(body)

		// Process each technology fingerprint
		for _, tech := range techFingerprints.Technologies {
			confidence := 0
			detected := false

			// Check headers
			for headerName, headerPattern := range tech.DetectionPatterns.Headers {
				if value := headers.Get(headerName); value != "" {
					if headerPattern == "" || strings.Contains(value, headerPattern) {
						confidence += 30
						detected = true
					}
				}
			}

			// Check HTML patterns
			for _, pattern := range tech.DetectionPatterns.HTML {
				if pattern == "" {
					continue
				}
				re, err := regexp.Compile("(?i)" + pattern)
				if err != nil {
					continue
				}
				if re.MatchString(bodyStr) {
					confidence += 20
					detected = true
				}
			}

			// Check script patterns
			for _, pattern := range tech.DetectionPatterns.Scripts {
				if pattern == "" {
					continue
				}
				re, err := regexp.Compile("(?i)" + pattern)
				if err != nil {
					continue
				}
				if re.MatchString(bodyStr) {
					confidence += 20
					detected = true
				}
			}

			// If technology is detected with sufficient confidence, add it
			if detected && confidence >= 20 {
				version := ""
				// Check for version if a regex pattern is provided
				if tech.VersionRegex != "" {
					re, err := regexp.Compile(tech.VersionRegex)
					if err == nil {
						matches := re.FindStringSubmatch(bodyStr)
						if len(matches) > 1 {
							version = matches[1]
						}
					}
				}

				technologies = append(technologies, TechnologyResult{
					Name:       tech.Name,
					Version:    version,
					Category:   tech.Category,
					Confidence: confidence,
				})
			}
		}

		// If technologies were found using the database, return them
		if len(technologies) > 0 {
			return technologies
		}
	}

	// Fallback to basic detection if fingerprint database failed or found nothing
	headerChecks := map[string]TechnologyResult{
		"X-Powered-By":     {Category: "Framework"},
		"X-AspNet-Version": {Name: "ASP.NET", Category: "Framework"},
		"X-Runtime":        {Category: "Framework"},
	}

	for header, tech := range headerChecks {
		if value := headers.Get(header); value != "" {
			tech.Name = value
			technologies = append(technologies, tech)
		}
	}

	if server := headers.Get("Server"); server != "" {
		technologies = append(technologies, TechnologyResult{
			Name:     "Web Server",
			Version:  server,
			Category: "Server",
		})
	}

	if bytes.Contains(body, []byte("wp-content")) {
		technologies = append(technologies, TechnologyResult{
			Name:     "WordPress",
			Category: "CMS",
		})
	}

	if bytes.Contains(body, []byte("jquery")) {
		technologies = append(technologies, TechnologyResult{
			Name:     "jQuery",
			Category: "JavaScript Framework",
		})
	}

	return technologies
}

func extractVersionForTech(body string, tech string) string {

	switch tech {
	case "React":

		reactVersionPattern := regexp.MustCompile(`React v([0-9]+\.[0-9]+\.[0-9]+)`)
		matches := reactVersionPattern.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}

		reactVersionPattern = regexp.MustCompile(`react@([0-9]+\.[0-9]+\.[0-9]+)`)
		matches = reactVersionPattern.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}

	case "Next.js":

		nextVersionPattern := regexp.MustCompile(`next/([0-9]+\.[0-9]+\.[0-9]+)`)
		matches := nextVersionPattern.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}

		nextDataPattern := regexp.MustCompile(`"buildId":"([^"]+)"`)
		matches = nextDataPattern.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}

	case "Vue.js":
		vueVersionPattern := regexp.MustCompile(`Vue\.js v([0-9]+\.[0-9]+\.[0-9]+)`)
		matches := vueVersionPattern.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}

		vueVersionPattern = regexp.MustCompile(`vue@([0-9]+\.[0-9]+\.[0-9]+)`)
		matches = vueVersionPattern.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}

	case "jQuery":
		jqueryVersionPattern := regexp.MustCompile(`jquery[^\/]*?([0-9]+\.[0-9]+\.[0-9]+)`)
		matches := jqueryVersionPattern.FindStringSubmatch(strings.ToLower(body))
		if len(matches) > 1 {
			return matches[1]
		}
	}

	versionPattern := regexp.MustCompile(fmt.Sprintf(`%s[\s\/]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`, strings.ToLower(tech)))
	matches := versionPattern.FindStringSubmatch(strings.ToLower(body))
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func getCategoryForTech(tech string) string {
	categories := map[string]string{
		"React":              "javascript-frameworks",
		"Next.js":            "javascript-frameworks",
		"Vue.js":             "javascript-frameworks",
		"Angular":            "javascript-frameworks",
		"jQuery":             "javascript-libraries",
		"Bootstrap":          "css-frameworks",
		"Tailwind CSS":       "css-frameworks",
		"GSAP":               "javascript-libraries",
		"Lodash":             "javascript-libraries",
		"Axios":              "javascript-libraries",
		"Swiper":             "javascript-libraries",
		"AOS":                "javascript-libraries",
		"Moment.js":          "javascript-libraries",
		"Webpack":            "build-tools",
		"Google Font API":    "font-scripts",
		"Google Analytics":   "analytics",
		"Google Tag Manager": "tag-managers",
		"Vercel":             "paas",
		"HSTS":               "security",
	}

	if category, exists := categories[tech]; exists {
		return category
	}
	return "other"
}

func getDescriptionForTech(tech string) string {
	descriptions := map[string]string{
		"React":              "A JavaScript library for building user interfaces",
		"Next.js":            "A React framework for production",
		"Vue.js":             "A progressive JavaScript framework for building UIs",
		"Angular":            "A platform for building mobile and desktop web applications",
		"jQuery":             "A fast, small, and feature-rich JavaScript library",
		"Bootstrap":          "The most popular HTML, CSS, and JS library in the world",
		"Tailwind CSS":       "A utility-first CSS framework",
		"GSAP":               "Animation library for JavaScript",
		"Lodash":             "A modern JavaScript utility library",
		"Axios":              "Promise based HTTP client for the browser and node.js",
		"Swiper":             "Mobile touch slider library",
		"AOS":                "Animate On Scroll library",
		"Moment.js":          "Parse, validate, manipulate, and display dates and times",
		"Webpack":            "Static module bundler for modern JavaScript applications",
		"Google Font API":    "Library of free licensed fonts",
		"Google Analytics":   "Web analytics service",
		"Google Tag Manager": "Tag management system",
		"Vercel":             "Platform for frontend frameworks and static sites",
		"HSTS":               "HTTP Strict Transport Security",
	}

	if description, exists := descriptions[tech]; exists {
		return description
	}
	return ""
}

func getWebsiteForTech(tech string) string {
	websites := map[string]string{
		"React":              "https://reactjs.org/",
		"Next.js":            "https://nextjs.org/",
		"Vue.js":             "https://vuejs.org/",
		"Angular":            "https://angular.io/",
		"jQuery":             "https://jquery.com/",
		"Bootstrap":          "https://getbootstrap.com/",
		"Tailwind CSS":       "https://tailwindcss.com/",
		"GSAP":               "https://greensock.com/gsap/",
		"Lodash":             "https://lodash.com/",
		"Axios":              "https://axios-http.com/",
		"Swiper":             "https://swiperjs.com/",
		"AOS":                "https://michalsnik.github.io/aos/",
		"Moment.js":          "https://momentjs.com/",
		"Webpack":            "https://webpack.js.org/",
		"Google Font API":    "https://fonts.google.com/",
		"Google Analytics":   "https://analytics.google.com/",
		"Google Tag Manager": "https://tagmanager.google.com/",
		"Vercel":             "https://vercel.com/",
	}

	if website, exists := websites[tech]; exists {
		return website
	}
	return ""
}

func extractVersionFromMetaTag(body string, tech string) string {
	pattern := fmt.Sprintf("<meta[^>]*name=\"generator\"[^>]*content=\"%s\\s*([0-9\\.]+)[^\"]*\"", tech)
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractVersionFromHeader(header string, tech string) string {
	pattern := fmt.Sprintf("%s/?\\s*([0-9\\.]+)", tech)
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(header)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractVersionFromString(s string, prefix string) string {
	pattern := fmt.Sprintf("%s/?\\s*([0-9\\.]+)", prefix)
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(s)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func containsPatternInHeaders(headers map[string]string, pattern string) bool {
	patternLower := strings.ToLower(pattern)
	for name, value := range headers {
		if strings.Contains(strings.ToLower(name), patternLower) ||
			strings.Contains(strings.ToLower(value), patternLower) {
			return true
		}
	}
	return false
}

func getSeverityFromStatusCode(statusCode int) string {
	switch {
	case statusCode >= 500:
		return "high"
	case statusCode >= 400:
		return "medium"
	case statusCode >= 300:
		return "low"
	default:
		return "info"
	}
}

func extractFaviconHash(targetURL string, client *http.Client) (string, error) {
	parsedURL, err := neturl.Parse(targetURL)
	if err != nil {
		return "", err
	}

	faviconURL := fmt.Sprintf("%s://%s/favicon.ico", parsedURL.Scheme, parsedURL.Host)

	req, err := http.NewRequest("GET", faviconURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("favicon not found: %d", resp.StatusCode)
	}

	faviconData, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", err
	}

	hash := md5.Sum(faviconData)
	return hex.EncodeToString(hash[:]), nil
}

func debugPrint(format string, args ...interface{}) {

	if os.Getenv("DEBUG") == "true" {
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("%s %s\n", "[DEBUG] ["+timestamp+"]", fmt.Sprintf(format, args...))
	}
}

func formatDuration(d time.Duration) string {
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}

func (p *Prober) EnhancedSingleProbe(target string) (*ProbeResult, error) {

	result := ProbeResult{}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	p.Config.ExtractTitle = true
	p.Config.ExtractTechnologies = true
	p.Config.ExtractCertInfo = true
	p.Config.ExtractFavicon = true
	p.Config.HTTP2Enabled = true
	p.Config.HTTP3Enabled = true
	p.Config.FollowRedirect = true
	p.Config.MaxRedirects = 10

	client := &http.Client{
		Timeout: time.Duration(30) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	requestStartTime := time.Now()
	resp, err := client.Get(target)
	if err != nil && strings.HasPrefix(target, "https://") {

		target = "http://" + strings.TrimPrefix(target, "https://")
		resp, err = client.Get(target)
	}

	if err != nil {
		return nil, fmt.Errorf("error connecting to target: %v", err)
	}
	defer resp.Body.Close()

	parsedURL, _ := neturl.Parse(target)
	result.Host = parsedURL.Host
	result.Scheme = parsedURL.Scheme
	result.Path = parsedURL.Path
	result.Query = parsedURL.RawQuery

	result.StatusCode = resp.StatusCode
	result.StatusLine = resp.Status
	result.ResponseTime = time.Since(requestStartTime)

	if host, _, err := net.SplitHostPort(parsedURL.Host); err != nil {
		result.IP = resolveIP(parsedURL.Host)
	} else {
		result.IP = resolveIP(host)
	}

	result.Headers = make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			result.Headers[k] = v[0]
		}
	}

	if server := resp.Header.Get("Server"); server != "" {
		result.WebServer = server
	}

	result.ContentType = resp.Header.Get("Content-Type")
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		result.ResponseSize = int64(len(body))

		if strings.Contains(result.ContentType, "text/html") {
			titleRegex := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
			if matches := titleRegex.FindSubmatch(body); len(matches) > 1 {
				result.Title = string(matches[1])
			}
		}
	}

	if resp.TLS != nil {
		result.TLS = &TLSInfo{
			Version:            getTLSVersion(resp.TLS.Version),
			Issuer:             resp.TLS.PeerCertificates[0].Issuer.CommonName,
			Subject:            resp.TLS.PeerCertificates[0].Subject.CommonName,
			NotBefore:          resp.TLS.PeerCertificates[0].NotBefore.Format(time.RFC3339),
			NotAfter:           resp.TLS.PeerCertificates[0].NotAfter.Format(time.RFC3339),
			SignatureAlgorithm: resp.TLS.PeerCertificates[0].SignatureAlgorithm.String(),
		}
		if len(resp.TLS.PeerCertificates[0].DNSNames) > 0 {
			result.TLS.DNSNames = resp.TLS.PeerCertificates[0].DNSNames
		}
	}

	result.SecurityHeaders = make(map[string]bool)
	result.SecurityHeaders["X-Frame-Options"] = resp.Header.Get("X-Frame-Options") != ""
	result.SecurityHeaders["X-XSS-Protection"] = resp.Header.Get("X-XSS-Protection") != ""
	result.SecurityHeaders["X-Content-Type-Options"] = resp.Header.Get("X-Content-Type-Options") != ""
	result.SecurityHeaders["Strict-Transport-Security"] = resp.Header.Get("Strict-Transport-Security") != ""
	result.SecurityHeaders["Content-Security-Policy"] = resp.Header.Get("Content-Security-Policy") != ""
	result.SecurityHeaders["Referrer-Policy"] = resp.Header.Get("Referrer-Policy") != ""

	result.Technologies = detectTechnologies(resp.Header, body)

	return &result, nil
}

func resolveIP(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

// loadTechFingerprints loads technology fingerprints from the JSON file
func loadTechFingerprints() (TechFingerprints, error) {
	var fingerprints TechFingerprints

	// Try to load from the config directory
	data, err := os.ReadFile("config/tech-fingerprints.json")
	if err != nil {
		// Try relative path as fallback
		data, err = os.ReadFile("../config/tech-fingerprints.json")
		if err != nil {
			return fingerprints, err
		}
	}

	err = json.Unmarshal(data, &fingerprints)
	return fingerprints, err
}
