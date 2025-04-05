package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"
	"gopkg.in/yaml.v3"
)

const (
	LogLevelSilent  = 0
	LogLevelError   = 1
	LogLevelWarning = 2
	LogLevelInfo    = 3
	LogLevelDebug   = 4
)

type WordlistConfig struct {
	SubdomainWordlist string            `json:"subdomain_wordlist" yaml:"subdomain_wordlist"`
	DirectoryWordlist string            `json:"directory_wordlist" yaml:"directory_wordlist"`
	CustomWordlists   map[string]string `json:"custom_wordlists" yaml:"custom_wordlists"`
}

type Config struct {
	Target           string           `json:"target" yaml:"target"`
	Threads          int              `json:"threads" yaml:"threads"`
	Timeout          int              `json:"timeout" yaml:"timeout"`
	OutputFile       string           `json:"output_file" yaml:"output_file"`
	WordlistConfig   WordlistConfig   `json:"wordlist_config" yaml:"wordlist_config"`
	SubdomainConfig  SubdomainConfig  `json:"subdomain_config" yaml:"subdomain_config"`
	HTTPProbeConfig  HTTPProbeConfig  `json:"httpprobe_config" yaml:"httpprobe_config"`
	DirBruteConfig   DirBruteConfig   `json:"dirbrute_config" yaml:"dirbrute_config"`
	JSAnalyzerConfig JSAnalyzerConfig `json:"jsanalyzer_config" yaml:"jsanalyzer_config"`
}

type SubdomainConfig struct {
	Enabled              bool              `json:"enabled" yaml:"enabled"`
	EnableBruteForce     bool              `json:"enable_bruteforce" yaml:"enable_bruteforce"`
	DisableAPISources    bool              `json:"disable_api_sources" yaml:"disable_api_sources"`
	WordlistPath         string            `json:"wordlist_path" yaml:"wordlist_path"`
	Resolvers            []string          `json:"resolvers" yaml:"resolvers"`
	Sources              []string          `json:"sources" yaml:"sources"`
	ExcludedSources      []string          `json:"excluded_sources" yaml:"excluded_sources"`
	Recursive            bool              `json:"recursive" yaml:"recursive"`
	UseAllSources        bool              `json:"use_all_sources" yaml:"use_all_sources"`
	MatchSubdomains      []string          `json:"match_subdomains" yaml:"match_subdomains"`
	FilterSubdomains     []string          `json:"filter_subdomains" yaml:"filter_subdomains"`
	ResolveIP            bool              `json:"resolve_ip" yaml:"resolve_ip"`
	CollectSources       bool              `json:"collect_sources" yaml:"collect_sources"`
	GlobalRateLimit      int               `json:"global_rate_limit" yaml:"global_rate_limit"`
	RateLimits           map[string]int    `json:"rate_limits" yaml:"rate_limits"`
	APIKeys              map[string]string `json:"api_keys" yaml:"api_keys"`
	SecurityTrailsAPIKey string            `json:"securitytrails_api_key" yaml:"securitytrails_api_key"`
	CensysAPIKey         string            `json:"censys_api_key" yaml:"censys_api_key"`
	CensysAPISecret      string            `json:"censys_api_secret"`
	ShodanAPIKey         string            `json:"shodan_api_key" yaml:"shodan_api_key"`
	Debug                bool              `json:"debug" yaml:"debug"`
	ShowStats            bool              `json:"show_stats" yaml:"show_stats"`
	VirusTotalAPIKey     string            `json:"virus_total_api_key" yaml:"virus_total_api_key"`
	SpyseAPIKey          string            `json:"spyse_api_key" yaml:"spyse_api_key"`
	FullHuntAPIKey       string            `json:"fullhunt_api_key" yaml:"fullhunt_api_key"`
	BinaryEdgeAPIKey     string            `json:"binaryedge_api_key" yaml:"binaryedge_api_key"`
	ThreatBookAPIKey     string            `json:"threatbook_api_key" yaml:"threatbook_api_key"`
	NetlasAPIKey         string            `json:"netlas_api_key" yaml:"netlas_api_key"`
	LeakixAPIKey         string            `json:"leakix_api_key" yaml:"leakix_api_key"`
}

type HTTPProbeConfig struct {
	Enabled             bool              `json:"enabled" yaml:"enabled"`
	Methods             []string          `json:"methods" yaml:"methods"`
	Headers             []string          `json:"headers" yaml:"headers"`
	UserAgent           string            `json:"user_agent" yaml:"user_agent"`
	FollowRedirect      bool              `json:"follow_redirect" yaml:"follow_redirect"`
	MaxRedirects        int               `json:"max_redirects" yaml:"max_redirects"`
	Concurrency         int               `json:"concurrency" yaml:"concurrency"`
	Timeout             int               `json:"timeout" yaml:"timeout"`
	StatusCodes         []int             `json:"status_codes" yaml:"status_codes"`
	ExtractTitle        bool              `json:"extract_title" yaml:"extract_title"`
	ExtractTechnologies bool              `json:"extract_technologies" yaml:"extract_technologies"`
	ExtractFavicon      bool              `json:"extract_favicon" yaml:"extract_favicon"`
	ScreenshotEnabled   bool              `json:"screenshot_enabled" yaml:"screenshot_enabled"`
	ScreenshotTimeout   int               `json:"screenshot_timeout" yaml:"screenshot_timeout"`
	ScreenshotQuality   int               `json:"screenshot_quality" yaml:"screenshot_quality"`
	ScreenshotPath      string            `json:"screenshot_path" yaml:"screenshot_path"`
	HTTPSOnly           bool              `json:"https_only" yaml:"https_only"`
	AvoidDuplicates     bool              `json:"avoid_duplicates" yaml:"avoid_duplicates"`
	HTTP2Enabled        bool              `json:"http2_enabled" yaml:"http2_enabled"`
	HTTP3Enabled        bool              `json:"http3_enabled" yaml:"http3_enabled"`
	AdditionalPorts     []int             `json:"additional_ports" yaml:"additional_ports"`
	ContentLengthFilter []int             `json:"content_length_filter" yaml:"content_length_filter"`
	OutputFormat        string            `json:"output_format" yaml:"output_format"`
	TechFingerprintPath string            `json:"tech_fingerprint_path" yaml:"tech_fingerprint_path"`
	CustomPatterns      map[string]string `json:"custom_patterns" yaml:"custom_patterns"`
	ExtractCertInfo     bool              `json:"extract_cert_info" yaml:"extract_cert_info"`
	Method              string            `yaml:"method"`
	Verbs               []string          `yaml:"verbs"`
	DetectTechnologies  bool              `yaml:"detect_technologies"`
}

type DirBruteConfig struct {
	Enabled        bool     `json:"enabled" yaml:"enabled"`
	WordlistPath   string   `json:"wordlist_path" yaml:"wordlist_path"`
	Extensions     []string `json:"extensions" yaml:"extensions"`
	StatusCodes    []int    `json:"status_codes" yaml:"status_codes"`
	Concurrency    int      `json:"concurrency" yaml:"concurrency"`
	FollowRedirect bool     `json:"follow_redirect" yaml:"follow_redirect"`
}

type JSAnalyzerConfig struct {
	Enabled          bool     `json:"enabled" yaml:"enabled"`
	IncludePatterns  []string `json:"include_patterns" yaml:"include_patterns"`
	ExcludePatterns  []string `json:"exclude_patterns" yaml:"exclude_patterns"`
	CustomPatterns   []string `json:"custom_patterns" yaml:"custom_patterns"`
	IncludeURLs      []string `json:"include_urls" yaml:"include_urls"`
	ExcludeURLs      []string `json:"exclude_urls" yaml:"exclude_urls"`
	Concurrency      int      `json:"concurrency" yaml:"concurrency"`
	Regex            []string `json:"regex" yaml:"regex"`
	Silent           bool     `json:"silent" yaml:"silent"`
	ShowErrorsInSaga bool     `json:"show_errors_in_saga" yaml:"show_errors_in_saga"`
	VerbosityLevel   int      `json:"verbosity_level" yaml:"verbosity_level"`
}

func DefaultConfig() Config {
	return Config{
		Threads: 10,
		Timeout: 30,
		WordlistConfig: WordlistConfig{
			CustomWordlists: make(map[string]string),
		},
		SubdomainConfig: SubdomainConfig{
			EnableBruteForce: false,
			Resolvers:        []string{"8.8.8.8", "8.8.4.4"},
			GlobalRateLimit:  10,
			RateLimits: map[string]int{
				"github":         10,
				"virustotal":     4,
				"securitytrails": 5,
				"shodan":         1,
				"censys":         5,
				"facebook":       5,
				"threatcrowd":    10,
				"rapiddns":       5,
				"dnsdumpster":    2,
				"chaos":          10,
				"commoncrawl":    5,
				"spyse":          10,
				"fullhunt":       10,
				"binaryedge":     10,
			},
			APIKeys: map[string]string{
				"virustotal":     "",
				"securitytrails": "",
				"censys":         "",
				"shodan":         "",
				"facebook":       "",
				"chaos":          "",
				"spyse":          "",
				"fullhunt":       "",
				"binaryedge":     "",
			},
		},
		HTTPProbeConfig: HTTPProbeConfig{
			Methods:             []string{"GET"},
			Headers:             []string{},
			UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			FollowRedirect:      true,
			MaxRedirects:        5,
			Concurrency:         200,
			Timeout:             10,
			StatusCodes:         []int{200, 201, 202, 203, 204, 301, 302, 303, 304, 307, 308, 401, 403, 404, 405, 500},
			ExtractTitle:        true,
			ExtractTechnologies: true,
			ExtractFavicon:      false,
			ScreenshotEnabled:   false,
			ScreenshotTimeout:   10,
			ScreenshotQuality:   75,
			ScreenshotPath:      "screenshots",
			HTTPSOnly:           false,
			AvoidDuplicates:     false,
			HTTP2Enabled:        false,
			HTTP3Enabled:        false,
			AdditionalPorts:     []int{},
			ContentLengthFilter: []int{},
			OutputFormat:        "json",
			TechFingerprintPath: "config/tech-fingerprints.json",
			CustomPatterns:      make(map[string]string),
			ExtractCertInfo:     true,
			Method:              "GET",
			Verbs:               []string{"GET"},
			DetectTechnologies:  true,
		},
		DirBruteConfig: DirBruteConfig{
			Extensions:     []string{".php", ".asp", ".aspx", ".jsp", ".html", ".js"},
			StatusCodes:    []int{200, 201, 202, 203, 204, 301, 302, 307, 401, 403},
			Concurrency:    100,
			FollowRedirect: true,
		},
		JSAnalyzerConfig: JSAnalyzerConfig{
			IncludePatterns: []string{".js$", ".jsx$", ".ts$", ".tsx$"},
			ExcludePatterns: []string{".min.js$", ".bundle.js$"},
			IncludeURLs:     []string{},
			ExcludeURLs:     []string{},
			Concurrency:     100,
			CustomPatterns: []string{
				`(?i)api[^a-zA-Z0-9]`,
				`(?i)token[^a-zA-Z0-9]`,
				`(?i)secret[^a-zA-Z0-9]`,
				`(?i)password[^a-zA-Z0-9]`,
				`(?i)key[^a-zA-Z0-9]`,
				`(?i)database[^a-zA-Z0-9]`,
				`(?i)endpoint[^a-zA-Z0-9]`,
			},
			Regex:            []string{},
			ShowErrorsInSaga: false,
			VerbosityLevel:   LogLevelError,
		},
	}
}

func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	cfg := DefaultConfig()
	ext := filepath.Ext(filePath)

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %v", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file format: %s", ext)
	}

	return &cfg, nil
}

func SaveConfig(cfg *Config, filePath string) error {
	var (
		data []byte
		err  error
	)

	ext := filepath.Ext(filePath)

	switch ext {
	case ".json":
		data, err = json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON config: %v", err)
		}
	case ".yaml", ".yml":
		data, err = yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML config: %v", err)
		}
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}

	return os.WriteFile(filePath, data, 0644)
}

func ValidateWordlist(path string) error {
	if path == "" {
		return fmt.Errorf("wordlist path cannot be empty")
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open wordlist %s: %v", path, err)
	}
	defer file.Close()

	return nil
}

func (c *Config) SetWordlist(module, path string) error {
	if err := ValidateWordlist(path); err != nil {
		return err
	}

	switch module {
	case "subdomain":
		c.SubdomainConfig.WordlistPath = path
		c.WordlistConfig.SubdomainWordlist = path
	case "directory":
		c.DirBruteConfig.WordlistPath = path
		c.WordlistConfig.DirectoryWordlist = path
	default:
		c.WordlistConfig.CustomWordlists[module] = path
	}

	return nil
}

func (c *Config) GetWordlist(module string) string {
	switch module {
	case "subdomain":
		return c.WordlistConfig.SubdomainWordlist
	case "directory":
		return c.WordlistConfig.DirectoryWordlist
	default:
		if path, ok := c.WordlistConfig.CustomWordlists[module]; ok {
			return path
		}
	}
	return ""
}

func LoadAPIKeys(apiKeysPath string, cfg *Config) error {
	data, err := os.ReadFile(apiKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read API keys file: %v", err)
	}

	fmt.Printf("%s %s\n",
		color.HiYellowString("Loading API keys from:"),
		color.HiWhiteString(apiKeysPath))

	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(data, &yamlData); err != nil {
		return fmt.Errorf("failed to parse API keys file: %v", err)
	}

	if cfg.SubdomainConfig.APIKeys == nil {
		cfg.SubdomainConfig.APIKeys = make(map[string]string)
	}

	validServices := make(map[string]bool)

	for key, value := range yamlData {
		if key == "" || strings.HasPrefix(key, "#") {
			continue
		}

		if nestedMap, ok := value.(map[string]interface{}); ok {
			for nestedKey, nestedValue := range nestedMap {
				if strValue, ok := nestedValue.(string); ok {
					combinedKey := fmt.Sprintf("%s_%s", key, nestedKey)

					if strings.TrimSpace(strValue) == "" ||
						strValue == "YOUR_API_KEY" ||
						strings.Contains(strings.ToUpper(strValue), "YOUR_") ||
						strings.Contains(strings.ToUpper(strValue), "XXXX") {
						continue
					}

					serviceName := key
					validServices[serviceName] = true

					addAPIKeyToConfig(cfg, combinedKey, strValue)
				}
			}
		} else if strValue, ok := value.(string); ok {
			strValue = strings.TrimSpace(strValue)
			if strValue == "" {
				continue
			}

			if strValue == "YOUR_API_KEY" ||
				strings.HasPrefix(strValue, "YOUR_") ||
				strings.Contains(strValue, "XXXX") {
				continue
			}

			serviceName := key
			if strings.HasSuffix(key, "_api_key") {
				serviceName = strings.TrimSuffix(key, "_api_key")
			} else if strings.HasSuffix(key, "_api") {
				serviceName = strings.TrimSuffix(key, "_api")
			} else if strings.Contains(key, "_") {
				parts := strings.Split(key, "_")
				if len(parts) > 0 {
					serviceName = parts[0]
				}
			}

			validServices[serviceName] = true

			addAPIKeyToConfig(cfg, key, strValue)
		}
	}

	if len(validServices) > 0 {
		serviceNames := make([]string, 0, len(validServices))
		for service := range validServices {
			serviceNames = append(serviceNames, service)
		}

		keyCount := color.HiGreenString("%d", len(serviceNames))
		fmt.Printf("%s Found %s keys (%s)\n",
			color.HiBlueString("API Keys:"),
			keyCount,
			strings.Join(serviceNames[:min(3, len(serviceNames))], ", "))
	} else {
		fmt.Printf("%s %s\n",
			color.HiBlueString("API Keys:"),
			color.HiRedString("No valid API keys configured"))
	}

	return nil
}

func getFirstFewServices(services []string, n int) []string {
	sort.Strings(services)

	if len(services) <= n {
		return services
	}
	return services[:n]
}

func addAPIKeyToConfig(cfg *Config, key, value string) {
	switch key {
	case "virustotal_api_key":
		cfg.SubdomainConfig.VirusTotalAPIKey = value
		cfg.SubdomainConfig.APIKeys["virustotal"] = value
	case "securitytrails_api_key":
		cfg.SubdomainConfig.SecurityTrailsAPIKey = value
		cfg.SubdomainConfig.APIKeys["securitytrails"] = value
	case "shodan_api_key":
		cfg.SubdomainConfig.ShodanAPIKey = value
		cfg.SubdomainConfig.APIKeys["shodan"] = value
	case "censys_api_id":
		cfg.SubdomainConfig.CensysAPIKey = value
		cfg.SubdomainConfig.APIKeys["censys"] = value
	case "censys_api_secret":
		cfg.SubdomainConfig.CensysAPISecret = value
	case "binaryedge_api_key":
		cfg.SubdomainConfig.BinaryEdgeAPIKey = value
		cfg.SubdomainConfig.APIKeys["binaryedge"] = value
	case "fullhunt_api_key":
		cfg.SubdomainConfig.FullHuntAPIKey = value
		cfg.SubdomainConfig.APIKeys["fullhunt"] = value
	case "spyse_api_key":
		cfg.SubdomainConfig.SpyseAPIKey = value
		cfg.SubdomainConfig.APIKeys["spyse"] = value
	case "netlas_api_key":
		cfg.SubdomainConfig.NetlasAPIKey = value
		cfg.SubdomainConfig.APIKeys["netlas"] = value
	case "leakix_api_key":
		cfg.SubdomainConfig.LeakixAPIKey = value
		cfg.SubdomainConfig.APIKeys["leakix"] = value
	case "threatbook_api_key":
		cfg.SubdomainConfig.ThreatBookAPIKey = value
		cfg.SubdomainConfig.APIKeys["threatbook"] = value
	default:
		if strings.HasSuffix(key, "_api_key") {
			sourceName := strings.TrimSuffix(key, "_api_key")
			cfg.SubdomainConfig.APIKeys[sourceName] = value
		} else if strings.HasSuffix(key, "_api") {
			sourceName := strings.TrimSuffix(key, "_api")
			cfg.SubdomainConfig.APIKeys[sourceName] = value
		} else if strings.Contains(key, "_api_") {
			parts := strings.Split(key, "_api_")
			if len(parts) >= 1 {
				cfg.SubdomainConfig.APIKeys[parts[0]] = value
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
