package jsanalyzer

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/zarni99/bbrecon/pkg/config"
	"github.com/zarni99/bbrecon/pkg/output"
)

type Analyzer struct {
	Config		config.JSAnalyzerConfig
	Target		string
	BaseURL		*url.URL
	Timeout		int
	Results		[]Finding
	mutex		sync.Mutex
	patterns	[]*regexp.Regexp
	Silent		bool
	InSagaMode	bool
}

type Finding struct {
	Target		string			`json:"target"`
	Source		string			`json:"source"`
	Type		string			`json:"type"`
	Value		string			`json:"value"`
	Context		string			`json:"context"`
	LineNumber	int			`json:"line_number,omitempty"`
	Severity	string			`json:"severity"`
	Category	string			`json:"category,omitempty"`
	Description	string			`json:"description"`
	Metadata	map[string]interface{}	`json:"metadata,omitempty"`
}

const (
	TypeEndpoint	= "endpoint"
	TypeAPI		= "api"
	TypeURL		= "url"
	TypeSecret	= "secret"
	TypeSensitive	= "sensitive"
	LogLevelSilent	= 0
	LogLevelError	= 1
	LogLevelWarning	= 2
	LogLevelInfo	= 3
	LogLevelDebug	= 4
)

func NewAnalyzer(target string, cfg config.JSAnalyzerConfig, timeout int, silent bool, inSagaMode bool) (*Analyzer, error) {
	baseURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	if baseURL.Scheme == "" {
		baseURL.Scheme = "http"
	}

	var patterns []*regexp.Regexp
	for _, pattern := range cfg.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern '%s': %v", pattern, err)
		}
		patterns = append(patterns, re)
	}

	if len(patterns) == 0 {
		defaultPatterns := []*regexp.Regexp{
			regexp.MustCompile(`(https?:\/\/[^\s'"]+)`),
			regexp.MustCompile(`['"]\/[^'"]{3,}['"]`),
			regexp.MustCompile(`(?:api|v[0-9]+)\/[^'"\s]{3,}`),
			regexp.MustCompile(`(?:\/api|\/v[0-9]+)\/[^'"\s\/]{3,}(?:\/[^'"\s\/]+){1,}`),
			regexp.MustCompile(`(?i)\/graphql\b`),
			regexp.MustCompile(`(?i)\/oauth\b`),

			regexp.MustCompile(`(?i)['"][a-zA-Z0-9_-]{20,}['"]`),
			regexp.MustCompile(`(?i)key\s*[=:]\s*['"][^'"]{8,}['"]`),
			regexp.MustCompile(`(?i)secret\s*[=:]\s*['"][^'"]{8,}['"]`),
			regexp.MustCompile(`(?i)token\s*[=:]\s*['"][^'"]{8,}['"]`),
			regexp.MustCompile(`(?i)password\s*[=:]\s*['"][^'"]{6,}['"]`),
			regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
			regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),
			regexp.MustCompile(`(?i)xox[a-zA-Z]-[a-zA-Z0-9-]{10,}`),

			regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),

			regexp.MustCompile(`(?i)mongodb(\+srv)?:\/\/[^\s'"]+`),
			regexp.MustCompile(`(?i)mysql:\/\/[^\s'"]+`),
			regexp.MustCompile(`(?i)postgres(ql)?:\/\/[^\s'"]+`),
			regexp.MustCompile(`(?i)redis:\/\/[^\s'"]+`),

			regexp.MustCompile(`(?i)\.ajax\(\s*\{\s*url:\s*["'][^"']+["']`),
			regexp.MustCompile(`(?i)\.(?:post|get|put|delete)\(\s*["'][^"']+["']`),
			regexp.MustCompile(`(?i)fetch\(\s*["'][^"']+["']`),

			regexp.MustCompile(`(?i)(user|username|login|account)\s*[=:]\s*['"][^'"]{3,}['"]`),
			regexp.MustCompile(`(?i)(pass|password|pwd|token)\s*[=:]\s*['"][^'"]{6,}['"]`),

			regexp.MustCompile(`(?i)client_secret\s*[=:]\s*['"][^'"]{10,}['"]`),
			regexp.MustCompile(`(?i)client_id\s*[=:]\s*['"][^'"]{10,}['"]`),

			regexp.MustCompile(`(?i)['"]s3\.amazonaws\.com\/[^'"]+['"]`),
			regexp.MustCompile(`(?i)['"][a-z0-9-]+\.s3\.amazonaws\.com['"]`),

			regexp.MustCompile(`(?i)document\.write\s*\(`),
			regexp.MustCompile(`(?i)\.innerHTML\s*=`),
			regexp.MustCompile(`(?i)eval\s*\(`),
			regexp.MustCompile(`(?i)setTimeout\s*\(\s*['"][^'"]*['"]`),
			regexp.MustCompile(`(?i)setInterval\s*\(\s*['"][^'"]*['"]`),
			regexp.MustCompile(`(?i)location\s*=|location\.href\s*=`),
			regexp.MustCompile(`(?i)\.outerHTML\s*=`),
			regexp.MustCompile(`(?i)Function\s*\(\s*['"][^'"]*['"]`),
			regexp.MustCompile(`(?i)document\.domain\s*=`),
			regexp.MustCompile(`(?i)\.insertAdjacentHTML\s*\(`),
			regexp.MustCompile(`(?i)\.setAttribute\s*\(\s*['"]on[^'"]*['"]`),

			regexp.MustCompile(`(?i)axios\.(get|post|put|delete|patch)\s*\(\s*['"][^'"]+['"]`),
			regexp.MustCompile(`(?i)(api|service|endpoint).*?['"][^'"]+['"]`),
			regexp.MustCompile(`(?i)(url|uri|endpoint)\s*[:=]\s*['"][^'"]+['"]`),
		}
		patterns = defaultPatterns
	}

	return &Analyzer{
		Config:		cfg,
		Target:		target,
		BaseURL:	baseURL,
		Timeout:	timeout,
		Results:	[]Finding{},
		mutex:		sync.Mutex{},
		patterns:	patterns,
		Silent:		silent,
		InSagaMode:	inSagaMode,
	}, nil
}

func (a *Analyzer) Run() ([]output.Finding, error) {
	var findings []output.Finding
	var jsURLs []string
	var processedURLs = make(map[string]bool)

	jsFiles, err := a.extractJSFromHTML(a.Target)
	if err != nil {
		a.logMessage(LogLevelError, "Failed to extract JS from HTML: %v", err)
		return nil, fmt.Errorf("failed to extract JS from HTML: %v", err)
	}

	if len(jsFiles) > 0 {
		fmt.Printf("%s Found %d JavaScript files to analyze\n", color.HiBlueString("INFO:"), len(jsFiles))
	}

	jsURLs = append(jsURLs, jsFiles...)

	if len(a.Config.IncludeURLs) > 0 && len(jsFiles) > 0 {
		hasValidPatterns := false
		for _, p := range a.Config.IncludeURLs {
			if p != "" {
				hasValidPatterns = true
				break
			}
		}

		if hasValidPatterns {
			if len(a.Config.IncludeURLs) == 1 {
				var filtered []string
				for _, jsURL := range jsURLs {
					for _, pattern := range a.Config.IncludeURLs {
						if pattern != "" && strings.Contains(jsURL, pattern) {
							filtered = append(filtered, jsURL)
							break
						}
					}
				}
				jsURLs = filtered
				if len(jsFiles) > 0 {
					fmt.Printf("%s After filtering, %d JavaScript files remain\n", color.HiBlueString("INFO:"), len(jsURLs))
				}
			}
		}
	}

	if len(a.Config.ExcludeURLs) > 0 {
		var filtered []string
		for _, jsURL := range jsURLs {
			exclude := false
			for _, pattern := range a.Config.ExcludeURLs {
				if strings.Contains(jsURL, pattern) {
					exclude = true
					break
				}
			}
			if !exclude {
				filtered = append(filtered, jsURL)
			}
		}
		jsURLs = filtered
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, a.Config.Concurrency)
	var resultsLock sync.Mutex

	for len(jsURLs) > 0 {
		currentBatch := jsURLs
		jsURLs = []string{}

		for _, jsURL := range currentBatch {
			if processedURLs[jsURL] {
				continue
			}
			processedURLs[jsURL] = true

			wg.Add(1)
			semaphore <- struct{}{}

			go func(jsURL string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				content, err := a.fetchURL(jsURL)
				if err != nil {
					if !a.Silent {
						fmt.Printf("ERROR: Failed to fetch JS from %s: %v\n", jsURL, err)
					}
					return
				}

				deobfuscated := a.deobfuscateJS(content)

				scriptURLRegex := regexp.MustCompile(`(?i)(loadScript|importScript|getScript)\s*\(\s*['"]([^'"]+\.js[^'"]*)['"]\s*\)`)
				scriptURLMatches := scriptURLRegex.FindAllStringSubmatch(deobfuscated, -1)

				for _, match := range scriptURLMatches {
					if len(match) > 2 {
						scriptURL := match[2]

						if !strings.HasPrefix(scriptURL, "http://") && !strings.HasPrefix(scriptURL, "https://") {
							scriptURL = a.resolveRelativeURL(jsURL, scriptURL)
						}

						resultsLock.Lock()
						jsURLs = append(jsURLs, scriptURL)
						resultsLock.Unlock()
					}
				}

				jsFindings := a.analyzeJS(jsURL, deobfuscated)

				resultsLock.Lock()
				a.Results = append(a.Results, jsFindings...)

				for _, f := range jsFindings {
					finding := output.NewFinding(
						"jsanalyzer",
						f.Target,
						f.Type,
						f.Description,
						f.Severity,
						map[string]interface{}{
							"source":	f.Source,
							"value":	f.Value,
							"context":	f.Context,
							"line_number":	f.LineNumber,
							"category":	f.Category,
							"metadata":	f.Metadata,
						},
					)
					findings = append(findings, finding)
				}
				resultsLock.Unlock()

			}(jsURL)
		}
	}

	wg.Wait()

	return findings, nil
}

func (a *Analyzer) extractJSFromHTML(targetURL string) ([]string, error) {
	var jsURLs []string

	if targetURL == "" {
		return nil, fmt.Errorf("empty target URL provided")
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	if parsedURL.Host == "" {
		return nil, fmt.Errorf("target URL has no host: %s", targetURL)
	}

	html, err := a.fetchURL(targetURL)
	if err != nil {
		return nil, err
	}

	scriptTagRe := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["'][^>]*>`)
	matches := scriptTagRe.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		jsURL := match[1]

		if strings.HasPrefix(jsURL, "//") {
			jsURL = "https:" + jsURL
		} else if !strings.HasPrefix(jsURL, "http") {
			if strings.HasPrefix(jsURL, "/") {
				jsURL = fmt.Sprintf("%s://%s%s", a.BaseURL.Scheme, a.BaseURL.Host, jsURL)
			} else {
				path := a.BaseURL.Path
				if !strings.HasSuffix(path, "/") {
					path = path[:strings.LastIndex(path, "/")+1]
				}
				jsURL = fmt.Sprintf("%s://%s%s%s", a.BaseURL.Scheme, a.BaseURL.Host, path, jsURL)
			}
		}

		jsURLs = append(jsURLs, jsURL)
	}

	return jsURLs, nil
}

func (a *Analyzer) fetchURL(targetURL string) (string, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:	true,
	}

	client := &http.Client{
		Transport:	transport,
		Timeout:	time.Duration(a.Timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		statusErr := fmt.Errorf("got status code %d", resp.StatusCode)
		a.logMessage(LogLevelError, "Failed to extract JS from HTML: got status code %d", resp.StatusCode)
		a.logMessage(LogLevelError, "During JavaScript analysis of %s: failed to extract JS from HTML: got status code %d",
			targetURL, resp.StatusCode)
		return "", statusErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (a *Analyzer) deobfuscateJS(content string) string {
	hexRegex := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	content = hexRegex.ReplaceAllStringFunc(content, func(match string) string {
		hexVal := match[2:]
		intVal, err := strconv.ParseInt(hexVal, 16, 64)
		if err != nil {
			return match
		}
		return string(rune(intVal))
	})

	unicodeRegex := regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	content = unicodeRegex.ReplaceAllStringFunc(content, func(match string) string {
		unicodeVal := match[2:]
		intVal, err := strconv.ParseInt(unicodeVal, 16, 64)
		if err != nil {
			return match
		}
		return string(rune(intVal))
	})

	base64Regex := regexp.MustCompile(`eval\s*\(\s*atob\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)\s*\)`)
	content = base64Regex.ReplaceAllStringFunc(content, func(match string) string {
		matches := base64Regex.FindStringSubmatch(match)
		if len(matches) > 1 {
			decoded, err := base64.StdEncoding.DecodeString(matches[1])
			if err != nil {
				return match
			}
			return string(decoded)
		}
		return match
	})

	return content
}

func (a *Analyzer) analyzeJS(jsURL, content string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	lines := strings.Split(content, "\n")

	for _, pattern := range a.patterns {
		matches := pattern.FindAllStringSubmatchIndex(content, -1)

		for _, match := range matches {
			start := match[0]
			end := match[1]

			if start >= 0 && end <= len(content) {
				value := content[start:end]

				key := fmt.Sprintf("%s:%s", jsURL, value)
				if seen[key] {
					continue
				}
				seen[key] = true

				lineNum, context := a.getContext(lines, start, 3)
				findingType, severity, category := a.classifyFinding(value, context)

				finding := Finding{
					Target:		a.Target,
					Source:		jsURL,
					Type:		findingType,
					Value:		value,
					Context:	context,
					LineNumber:	lineNum,
					Severity:	severity,
					Category:	category,
					Description:	fmt.Sprintf("Found %s in JavaScript: %s", findingType, truncateString(value, 50)),
					Metadata: map[string]interface{}{
						"script_url":	jsURL,
						"line":		lineNum,
					},
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (a *Analyzer) getContext(lines []string, position int, contextLines int) (int, string) {
	lineStart := 0
	lineNumber := 1

	for i, line := range lines {
		lineEnd := lineStart + len(line) + 1

		if position >= lineStart && position < lineEnd {
			lineNumber = i + 1
			break
		}

		lineStart = lineEnd
	}

	var contextBuilder bytes.Buffer

	startLine := max(0, lineNumber-contextLines-1)
	endLine := min(len(lines), lineNumber+contextLines)

	for i := startLine; i < endLine; i++ {
		linePrefix := fmt.Sprintf("%d: ", i+1)
		if i+1 == lineNumber {
			linePrefix = fmt.Sprintf("> %s", linePrefix)
		} else {
			linePrefix = fmt.Sprintf("  %s", linePrefix)
		}

		contextBuilder.WriteString(linePrefix)
		contextBuilder.WriteString(lines[i])
		contextBuilder.WriteString("\n")
	}

	functionInfo := a.extractFunctionContext(lines, lineNumber-1)
	if functionInfo != "" {
		contextBuilder.WriteString("\n")
		contextBuilder.WriteString(functionInfo)
	}

	return lineNumber, contextBuilder.String()
}

func (a *Analyzer) extractFunctionContext(lines []string, lineNum int) string {
	functionStart := -1
	bracketCount := 0
	inFunction := false
	functionName := ""

	funcNameRegex := regexp.MustCompile(`(?:function\s+([a-zA-Z0-9_$]+)|(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:function|\([^)]*\)\s*=>)|([a-zA-Z0-9_$]+)\s*:\s*function)`)

	for i := lineNum; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])

		for j := 0; j < len(line); j++ {
			if line[j] == '}' {
				bracketCount++
			} else if line[j] == '{' {
				bracketCount--
				if bracketCount < 0 && !inFunction {
					functionStart = i
					inFunction = true

					for k := i; k >= 0 && k > i-5; k-- {
						matches := funcNameRegex.FindStringSubmatch(lines[k])
						if len(matches) > 1 {
							for _, match := range matches[1:] {
								if match != "" {
									functionName = match
									break
								}
							}
							break
						}
					}
					break
				}
			}
		}

		if inFunction {
			break
		}
	}

	if functionStart >= 0 {
		var contextBuilder bytes.Buffer
		if functionName != "" {
			contextBuilder.WriteString(fmt.Sprintf("Function: %s\n", functionName))
		} else {
			contextBuilder.WriteString("Anonymous function\n")
		}
		return contextBuilder.String()
	}

	return ""
}

func (a *Analyzer) classifyFinding(value, context string) (string, string, string) {
	findingType := TypeURL
	severity := "info"
	category := "general"

	valueLower := strings.ToLower(value)
	contextLower := strings.ToLower(context)

	xssPatterns := []string{
		"document.write", "innerHTML", "outerHTML", "eval(",
		"setTimeout(", "setInterval(", "location=", "location.href",
		"document.domain", "insertAdjacentHTML", "setAttribute",
	}

	for _, pattern := range xssPatterns {
		if strings.Contains(valueLower, pattern) {
			userInputPatterns := []string{
				"location.hash", "location.search", "location.href",
				"document.referrer", "document.url", "document.cookie",
				"localStorage.getItem", "sessionStorage.getItem", "get(",
				"getElementById", "querySelector",
			}

			for _, inputPattern := range userInputPatterns {
				if strings.Contains(contextLower, inputPattern) {
					findingType = "xss_vulnerable"
					severity = "high"
					category = "dom_xss"
					return findingType, severity, category
				}
			}

			findingType = "xss_potential"
			severity = "medium"
			category = "dom_xss"
			return findingType, severity, category
		}
	}

	if strings.HasPrefix(value, "eyJ") && strings.Count(value, ".") == 2 {
		findingType = TypeSecret
		severity = "high"
		category = "auth_token"
		return findingType, severity, category
	}

	apiPrefixes := []string{"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/oauth", "/rest/", "/service/"}
	for _, prefix := range apiPrefixes {
		if strings.Contains(valueLower, prefix) {
			findingType = TypeAPI
			severity = "medium"
			category = "api_endpoint"

			sensitiveEndpoints := []string{
				"user", "admin", "auth", "token", "key", "secret", "cred",
				"password", "login", "signin", "account", "profile", "payment",
			}

			for _, sensitive := range sensitiveEndpoints {
				if strings.Contains(valueLower, sensitive) {
					severity = "high"
					if strings.Contains(valueLower, "user") || strings.Contains(valueLower, "admin") {
						category = "user_endpoint"
					} else if strings.Contains(valueLower, "auth") || strings.Contains(valueLower, "login") {
						category = "auth_endpoint"
					} else if strings.Contains(valueLower, "payment") || strings.Contains(valueLower, "card") {
						category = "payment_endpoint"
						severity = "critical"
					} else {
						category = "sensitive_endpoint"
					}
					return findingType, severity, category
				}
			}
		}
	}

	secretPatterns := map[string][]string{
		"api_key": {
			"api_key", "apikey", "api-key", "x-api-key", "key=", "key:", "appkey", "appid", "app_id", "app_key",
		},
		"auth_token": {
			"token", "authorization", "bearer", "auth-token", "auth_token", "jwt", "access_token", "refresh_token",
		},
		"credential": {
			"password", "passwd", "pwd", "credential", "secret", "client_secret", "client_id", "consumer_key", "consumer_secret",
		},
		"cloud_key": {
			"aws_", "akia", "azurewebsites", "cloudfront", "amazonaws", "firebase", "googleusercontent",
		},
		"encryption": {
			"private_key", "public_key", "pk_", "sk_", "cert", "certificate", "encryption",
		},
	}

	for foundCategory, patterns := range secretPatterns {
		for _, pattern := range patterns {
			if strings.Contains(valueLower, pattern) {
				findingType = TypeSecret
				severity = "high"
				category = foundCategory
				return findingType, severity, category
			}
		}
	}

	if strings.Contains(valueLower, "mongodb") ||
		strings.Contains(valueLower, "mysql") ||
		strings.Contains(valueLower, "postgres") ||
		strings.Contains(valueLower, "jdbc") ||
		strings.Contains(valueLower, "redis") ||
		strings.Contains(valueLower, "connection") {
		findingType = TypeSensitive
		severity = "high"
		category = "database"
	}

	if strings.Contains(valueLower, "akia") ||
		strings.Contains(valueLower, "amazonaws.com") ||
		strings.Contains(valueLower, ".s3.") {
		findingType = TypeSensitive
		severity = "high"
		category = "aws_resource"
	}

	ajaxPatterns := []string{
		".ajax", ".get(", ".post(", ".put(", ".delete(", "fetch(",
		"axios.get", "axios.post", "axios.put", "axios.delete",
		"$http", "XMLHttpRequest", "xhr",
	}

	for _, pattern := range ajaxPatterns {
		if strings.Contains(valueLower, pattern) {
			if findingType == TypeURL {
				findingType = TypeEndpoint
				severity = "medium"
				category = "ajax_endpoint"

				if strings.Contains(contextLower, "password") ||
					strings.Contains(contextLower, "token") ||
					strings.Contains(contextLower, "auth") ||
					strings.Contains(contextLower, "key") {
					severity = "high"
					category = "sensitive_ajax"
				}
			}
			break
		}
	}

	return findingType, severity, category
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (a *Analyzer) resolveRelativeURL(baseURL, relativeURL string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return relativeURL
	}

	rel, err := url.Parse(relativeURL)
	if err != nil {
		return relativeURL
	}

	resolved := base.ResolveReference(rel)
	return resolved.String()
}

func (j *Analyzer) logMessage(level int, format string, args ...interface{}) {
	if j.InSagaMode && level > LogLevelSilent && !j.Config.ShowErrorsInSaga {
		return
	}

	if j.Silent && level > LogLevelSilent {
		return
	}

	verbosityLevel := LogLevelError
	if j.Config.VerbosityLevel > 0 {
		verbosityLevel = j.Config.VerbosityLevel
	}

	if level <= verbosityLevel {
		switch level {
		case LogLevelError:
			fmt.Printf("ERROR: "+format+"\n", args...)
		case LogLevelWarning:
			fmt.Printf("WARNING: "+format+"\n", args...)
		case LogLevelInfo:
			fmt.Printf("INFO: "+format+"\n", args...)
		case LogLevelDebug:
			fmt.Printf("DEBUG: "+format+"\n", args...)
		}
	}
}
