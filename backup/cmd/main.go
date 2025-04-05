package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/zarni99/bbrecon/pkg/config"
	"github.com/zarni99/bbrecon/pkg/dirbrute"
	"github.com/zarni99/bbrecon/pkg/dnsenum"
	"github.com/zarni99/bbrecon/pkg/errhandler"
	"github.com/zarni99/bbrecon/pkg/exposure"
	"github.com/zarni99/bbrecon/pkg/httpprobe"
	"github.com/zarni99/bbrecon/pkg/jsanalyzer"
	"github.com/zarni99/bbrecon/pkg/output"
	"github.com/zarni99/bbrecon/pkg/subdomain"
)

const (
	appName    = "BBRECON"
	appVersion = "1.0.0"
)

var banner = `
██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██████╔╝██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                           	Bug Bounty Recon Tool                                                 
`

var (
	success       = color.New(color.FgGreen).SprintFunc()
	info          = color.New(color.FgCyan).SprintFunc()
	warn          = color.New(color.FgYellow).SprintFunc()
	error_        = color.New(color.FgRed).SprintFunc()
	primary       = info
	accent        = color.New(color.FgMagenta).SprintFunc()
	statusSuccess = success
	statusWarning = color.New(color.FgHiYellow).SprintFunc()
)

var (
	configFile              string
	targetDomain            string
	outputFile              string
	threads                 int
	timeout                 int
	customTargetFile        string
	showHelp                bool
	bannerPrinted           bool
	enableSubdomain         bool
	enableHTTPProbe         bool
	enableDirBrute          bool
	enableJSAnalyzer        bool
	enableDNSEnum           bool
	allModules              bool
	sagaMode                bool
	wordlistPath            string
	sourcesFlag             string
	excludeSources          string
	recursive               bool
	all                     bool
	matchSubdomains         string
	filterSubdomains        string
	resolveIP               bool
	showStats               bool
	outputJSON              bool
	suppressResults         bool
	verbose                 bool
	debug                   bool
	silent                  bool
	suppressJSErrors        bool
	enableExposureDetection bool
)

func init() {
	flag.StringVar(&configFile, "c", "", "Configuration file path")
	flag.StringVar(&targetDomain, "t", "", "Target domain")
	flag.StringVar(&outputFile, "o", "", "Output file path")
	flag.IntVar(&threads, "th", 0, "Number of concurrent threads")
	flag.IntVar(&timeout, "to", 0, "Timeout in seconds")
	flag.StringVar(&wordlistPath, "w", "", "Wordlist path for brute forcing")
	flag.BoolVar(&allModules, "A", false, "Enable all modules")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.StringVar(&sourcesFlag, "s", "", "Comma-separated list of sources to use")
	flag.StringVar(&excludeSources, "es", "", "Comma-separated list of sources to exclude")
	flag.BoolVar(&recursive, "recursive", false, "Enable recursive directory brute forcing")
	flag.BoolVar(&all, "all", false, "Show all results, including 404s")
	flag.StringVar(&matchSubdomains, "m", "", "Only include subdomains matching these patterns (comma-separated)")
	flag.StringVar(&filterSubdomains, "f", "", "Exclude subdomains matching these patterns (comma-separated)")
	flag.BoolVar(&outputJSON, "json", false, "Output in JSON format")
	flag.BoolVar(&resolveIP, "ip", false, "Resolve IP addresses for subdomains")
	flag.BoolVar(&silent, "silent", false, "Suppress output")
	flag.StringVar(&customTargetFile, "C", "", "Custom target file containing URLs/domains to probe")
	flag.BoolVar(&suppressResults, "no-results", true, "Suppress individual result output, show only summary")
	flag.BoolVar(&enableSubdomain, "S", false, "Enable subdomain enumeration module")
	flag.BoolVar(&enableHTTPProbe, "H", false, "Enable HTTP probing of discovered subdomains")
	flag.BoolVar(&enableDirBrute, "D", false, "Enable directory bruteforcing on active hosts")
	flag.BoolVar(&enableJSAnalyzer, "J", false, "Enable JavaScript analysis for endpoints and secrets")
	flag.BoolVar(&enableDNSEnum, "N", false, "Enable DNS enumeration module (discovers DNS records)")
	flag.BoolVar(&showStats, "stats", false, "Show source statistics")
	flag.BoolVar(&suppressJSErrors, "no-js-errors", false, "Suppress JavaScript analysis error messages")
	flag.BoolVar(&enableExposureDetection, "X", false, "Enable exposure detection (secrets, API keys, sensitive data)")
}

func formatDuration(d time.Duration) string {
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}

func debugPrint(format string, args ...interface{}) {
	if debug {

		if strings.HasPrefix(format, "Error probing") {
			return
		}
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("%s %s\n", info("["+timestamp+"]"), fmt.Sprintf(format, args...))
	}
}

func loadTargetsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target != "" && !strings.HasPrefix(target, "#") {
			targets = append(targets, target)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

func stringContainsAny(s string, substrs []string) bool {
	s = strings.ToLower(s)
	for _, substr := range substrs {
		if strings.Contains(s, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

func handleTargetSelection(targets map[string][]string) []string {
	var allTargets []string
	for _, priority := range []string{"high", "medium", "low"} {
		allTargets = append(allTargets, targets[priority]...)
	}

	totalTargets := len(allTargets)
	fmt.Printf("\n%s %s %s %s Found %s live domains\n",
		color.HiCyanString("["),
		color.HiYellowString("LIVE DOMAINS FOUND"),
		color.HiCyanString("]"),
		color.HiMagentaString(":"),
		color.HiGreenString("%d", totalTargets))

	const pageSize = 20
	currentPage := 0

	var filteredTargets []string
	filterKeyword := ""
	sortOrder := "default"

	for {
		if filterKeyword != "" {
			filteredTargets = []string{}
			if filterKeyword == "__high_priority__" {
				filteredTargets = append(filteredTargets, targets["high"]...)
			} else {
				for _, target := range allTargets {
					if strings.Contains(strings.ToLower(target), strings.ToLower(filterKeyword)) {
						filteredTargets = append(filteredTargets, target)
					}
				}
			}
		} else {
			filteredTargets = allTargets
		}

		if sortOrder == "asc" {
			sort.Strings(filteredTargets)
		} else if sortOrder == "desc" {
			sort.Strings(filteredTargets)
			for i, j := 0, len(filteredTargets)-1; i < j; i, j = i+1, j-1 {
				filteredTargets[i], filteredTargets[j] = filteredTargets[j], filteredTargets[i]
			}
		}

		filteredTotal := len(filteredTargets)
		filteredPages := (filteredTotal + pageSize - 1) / pageSize

		if currentPage >= filteredPages && filteredPages > 0 {
			currentPage = filteredPages - 1
		}

		fmt.Printf("%s %s\n",
			color.HiCyanString("[ LIVE DOMAINS SELECTION ]"),
			color.HiYellowString("(Page %d of %d - Total: %d domains)",
				currentPage+1,
				filteredPages,
				filteredTotal))

		if filterKeyword != "" || sortOrder != "default" {
			statusParts := []string{}
			if filterKeyword != "" {
				if filterKeyword == "__high_priority__" {
					statusParts = append(statusParts, fmt.Sprintf("Filter: %s", color.HiRedString("High Priority")))
				} else {
					statusParts = append(statusParts, fmt.Sprintf("Filter: '%s'", color.HiYellowString(filterKeyword)))
				}
			}
			if sortOrder != "default" {
				statusParts = append(statusParts, fmt.Sprintf("Sort: %s", color.HiGreenString(sortOrder)))
			}
			fmt.Printf("\n%s %s\n", color.HiMagentaString("Active:"), strings.Join(statusParts, ", "))
		}

		displayStart := currentPage * pageSize
		displayEnd := min(displayStart+pageSize, filteredTotal)

		if filteredTotal > 0 {
			fmt.Printf("\n%s %s\n\n",
				color.HiYellowString("[ DOMAINS ]"),
				color.HiWhiteString("(Showing %d-%d of %d)",
					displayStart+1,
					displayEnd,
					filteredTotal))

			for i := displayStart; i < displayEnd; i++ {
				domainColor := "normal"
				domain := filteredTargets[i]

				for _, highPriorityDomain := range targets["high"] {
					if highPriorityDomain == domain {
						domainColor = "high"
						break
					}
				}

				if domainColor == "normal" {
					for _, mediumPriorityDomain := range targets["medium"] {
						if mediumPriorityDomain == domain {
							domainColor = "medium"
							break
						}
					}
				}

				switch domainColor {
				case "high":
					fmt.Printf("%3d. %s\n", i+1, color.HiRedString(domain))
				case "medium":
					fmt.Printf("%3d. %s\n", i+1, color.HiYellowString(domain))
				default:
					fmt.Printf("%3d. %s\n", i+1, color.HiWhiteString(domain))
				}
			}
		} else {
			fmt.Printf("\n%s No domains match your filter criteria.\n", color.HiRedString("NOTICE:"))
		}

		fmt.Printf("\n%s\n", color.HiCyanString("━━━━ COMMANDS ━━━━"))

		if filteredPages > 1 {
			navCmd := ""
			if currentPage > 0 {
				navCmd += color.HiGreenString("p") + color.HiWhiteString(" - prev")
			}
			if currentPage > 0 && currentPage < filteredPages-1 {
				navCmd += " | "
			}
			if currentPage < filteredPages-1 {
				navCmd += color.HiGreenString("n") + color.HiWhiteString(" - next")
			}
			if navCmd != "" {
				fmt.Printf("  %s\n", navCmd)
			}
		}

		fmt.Printf("  %s\n",
			color.HiGreenString("b")+color.HiWhiteString(" - back"))

		if !allModules {
			fmt.Printf("  %s\n",
				color.HiGreenString("help")+color.HiWhiteString(" - show available sources"))
		}

		fmt.Printf("\n%s ", color.HiWhiteString("Your selection:"))

		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "b" {
			return nil
		}

		if strings.HasPrefix(input, "f:") {
			filterKeyword = strings.TrimPrefix(input, "f:")
			currentPage = 0
			continue
		}

		if input == "clear" {
			filterKeyword = ""
			sortOrder = "default"
			currentPage = 0
			continue
		}

		if (input == "help" || input == "sources") && !allModules {
			showAvailableSources()
			continue
		}

		if input == "sort:asc" {
			sortOrder = "asc"
			continue
		}

		if input == "sort:desc" {
			sortOrder = "desc"
			continue
		}

		if input == "priority" {

			filterKeyword = "__high_priority__"
			currentPage = 0
			continue
		}

		if input == "a" && filteredTotal > 0 {

			scanType := chooseScanType(filteredTargets)
			if scanType == "" {

				continue
			}

			switch scanType {
			case "dir":
				enableDirBrute = true
				enableJSAnalyzer = false
				fmt.Printf("%s Your choice: Directory Bruteforcing\n", color.HiGreenString("INFO:"))
			case "js":
				enableDirBrute = false
				enableJSAnalyzer = true
				fmt.Printf("%s JavaScript analysis will extract endpoints, secrets, and sensitive data from JS files.\n", color.HiBlueString("JAVA:"))
			}

			return filteredTargets
		}

		if filteredPages > 1 {
			switch input {
			case "p", "prev", "previous":
				if currentPage > 0 {
					currentPage--

				}
				continue
			case "n", "next":
				if currentPage < filteredPages-1 {
					currentPage++

				}
				continue
			}
		}

		var selectedIndices []int
		ranges := strings.Split(input, ",")
		validSelection := true

		for _, r := range ranges {
			r = strings.TrimSpace(r)
			if strings.Contains(r, "-") {
				parts := strings.Split(r, "-")
				if len(parts) != 2 {
					validSelection = false
					break
				}

				start, err1 := strconv.Atoi(parts[0])
				end, err2 := strconv.Atoi(parts[1])
				if err1 != nil || err2 != nil {
					validSelection = false
					break
				}

				for i := start; i <= end; i++ {
					if i > 0 && i <= filteredTotal {
						selectedIndices = append(selectedIndices, i-1)
					}
				}
			} else {
				idx, err := strconv.Atoi(r)
				if err != nil || idx < 1 || idx > filteredTotal {
					validSelection = false
					break
				}
				selectedIndices = append(selectedIndices, idx-1)
			}
		}

		if !validSelection || len(selectedIndices) == 0 {
			fmt.Printf("%s Invalid selection. Please try again.\n", color.HiRedString("ERROR:"))
			continue
		}

		selectedMap := make(map[int]struct{})
		for _, idx := range selectedIndices {
			selectedMap[idx] = struct{}{}
		}

		selectedIndices = []int{}
		for idx := range selectedMap {
			selectedIndices = append(selectedIndices, idx)
		}
		sort.Ints(selectedIndices)

		var selectedTargets []string
		for _, idx := range selectedIndices {
			selectedTargets = append(selectedTargets, filteredTargets[idx])
		}

		scanType := chooseScanType(selectedTargets)
		if scanType == "" {

			continue
		}

		switch scanType {
		case "dir":
			enableDirBrute = true
			enableJSAnalyzer = false
			fmt.Printf("%s Your choice: Directory Bruteforcing\n", color.HiGreenString("INFO:"))
		case "js":
			enableDirBrute = false
			enableJSAnalyzer = true
			fmt.Printf("%s JavaScript analysis will extract endpoints, secrets, and sensitive data from JS files.\n", color.HiBlueString("JAVA:"))
		case "both":
			enableDirBrute = true
			enableJSAnalyzer = true
			fmt.Printf("%s Your choice: Both Directory Bruteforcing and JavaScript Analysis\n", color.HiGreenString("INFO:"))
		}

		return selectedTargets
	}
}

func chooseScanType(selectedTargets []string) string {
	fmt.Printf("\n%s %s %s %s\n",
		color.HiCyanString("["),
		color.HiYellowString("SCAN TYPE"),
		color.HiCyanString("]"),
		color.HiGreenString("(%d total)", len(selectedTargets)))

	maxToShow := min(5, len(selectedTargets))
	for i := 0; i < maxToShow; i++ {
		fmt.Printf("%d. %s\n", i+1, color.HiWhiteString(selectedTargets[i]))
	}
	if len(selectedTargets) > maxToShow {
		fmt.Printf("... and %d more\n", len(selectedTargets)-maxToShow)
	}

	fmt.Printf("\n%s\n", color.HiCyanString("Choose scan type:"))
	fmt.Printf("1. %s (slower but more thorough)\n", color.HiGreenString("Directory Bruteforcing"))
	fmt.Printf("2. %s (faster, analyzes JS files)\n", color.HiBlueString("JavaScript Analysis"))
	fmt.Printf("3. %s\n\n", color.HiYellowString("Go back to domain selection"))

	fmt.Printf("Your choice (1-3): ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))

	switch input {
	case "1", "dir", "directory":
		return "dir"
	case "2", "js", "javascript":
		return "js"
	case "3", "back":
		return ""
	default:
		fmt.Printf("%s Invalid choice. Please try again.\n", color.HiRedString("ERROR:"))
		return chooseScanType(selectedTargets)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isValidDomain(domain string) bool {

	if domain == "" {
		return false
	}

	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "http://"), "https://")

	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	if debug {
		fmt.Printf("%s Validating domain: %s\n", info("DEBUG:"), domain)
	}

	parts := strings.Split(domain, ".")

	if len(parts) < 2 {
		if debug {
			fmt.Printf("%s Domain must have at least one dot: %s\n", warn("DEBUG:"), domain)
		}
		return false
	}

	for _, part := range parts {
		if part == "" {
			if debug {
				fmt.Printf("%s Domain contains empty part: %s\n", warn("DEBUG:"), domain)
			}
			return false
		}
	}

	return true
}

func parseDomainList(domains string) []string {
	var result []string
	if domains == "" {
		return result
	}

	domainList := strings.Split(domains, ",")

	for _, domain := range domainList {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		if allModules && (strings.HasPrefix(strings.ToLower(domain), "help") ||
			strings.HasPrefix(strings.ToLower(domain), "-help")) {
			continue
		}

		if isValidDomain(domain) {
			result = append(result, domain)
		} else {
			fmt.Printf("%s Invalid domain format: %s (skipping)\n", warn("WARNING:"), domain)
		}
	}

	return result
}

func main() {

	for _, arg := range os.Args {
		if arg == "-h" || arg == "--help" {
			printHelp()
			os.Exit(0)
		}
	}

	errhandler.SetPrintBannerFunc(printBanner)
	errhandler.SetupFlagHandling()

	var bruteforceOnlyMode bool

	validateCommandLineArgs()

	flag.Parse()

	// Add restriction for using -S and -H together
	if enableSubdomain && enableHTTPProbe && !allModules {
		printBanner()
		fmt.Printf("%s Using -S and -H flags together is not allowed\n", error_("ERROR:"))
		fmt.Printf("%s For subdomain discovery with basic HTTP probing: %s\n", info("USAGE:"), color.HiGreenString("./bbrecon -t example.com"))
		fmt.Printf("%s For advanced HTTP probing on specific domains: %s\n", info("USAGE:"), color.HiGreenString("./bbrecon -t specific-domain.com -H"))
		os.Exit(1)
	}

	// Add validation for -X flag
	if enableExposureDetection {
		if enableSubdomain || enableHTTPProbe || enableDirBrute || enableJSAnalyzer || enableDNSEnum || allModules {
			printBanner()
			fmt.Printf("%s The -X flag (exposure detection) must be used standalone\n", error_("ERROR:"))
			fmt.Printf("%s Invalid usage: Cannot use -X with -S, -H, -D, -J, -N, or -A flags\n", error_("ERROR:"))
			fmt.Printf("%s Example usage: ./bbrecon -t example.com -X\n", info("INFO:"))
			os.Exit(1)
		}
	}

	if enableSubdomain && wordlistPath != "" {
		bruteforceOnlyMode = true
	}

	var startTime time.Time

	if len(os.Args) > 1 {
		for i, arg := range os.Args {
			if (arg == "-C" || arg == "-t") && (i+1 >= len(os.Args) || strings.HasPrefix(os.Args[i+1], "-")) {
				printBanner()

				usageText := color.HiCyanString("Usage:") + " " +
					color.HiWhiteString("./bbrecon") + " " +
					color.HiYellowString("-t") + " " +
					color.HiGreenString("example.com") + " " +
					color.HiWhiteString("or") + " " +
					color.HiWhiteString("./bbrecon") + " " +
					color.HiYellowString("-C") + " " +
					color.HiGreenString("targets.txt")

				helpText := color.HiCyanString("Use") + " " +
					color.HiYellowString("-h") + " " +
					color.HiCyanString("for detailed help information")

				fmt.Println(usageText)
				fmt.Println(helpText)
				os.Exit(1)
			}
		}
	}

	if targetDomain == "" && customTargetFile == "" {
		printBanner()

		usageText := color.HiCyanString("Usage:") + " " +
			color.HiWhiteString("./bbrecon") + " " +
			color.HiYellowString("-t") + " " +
			color.HiGreenString("example.com") + " " +
			color.HiWhiteString("or") + " " +
			color.HiWhiteString("./bbrecon") + " " +
			color.HiYellowString("-C") + " " +
			color.HiGreenString("targets.txt")

		helpText := color.HiCyanString("Use") + " " +
			color.HiYellowString("-h") + " " +
			color.HiCyanString("for detailed help information")

		fmt.Println(usageText)
		fmt.Println(helpText)
		os.Exit(1)
	}

	if !silent {

		printBanner()
	}

	if showHelp {
		printHelp()
		os.Exit(0)
	}

	if strings.HasPrefix(targetDomain, "-") {
		fmt.Printf("%s Usage: ./bbrecon -t example.com (target domain cannot start with '-')\n", error_("ERROR:"))
		os.Exit(1)
	}

	if customTargetFile != "" {

		if !enableSubdomain && !enableHTTPProbe {
			fmt.Printf("%s The -C flag (custom target file) must be used with -S and/or -H flags\n", error_("ERROR:"))
			fmt.Printf("%s Example usage: ./bbrecon -C targets.txt -S -H\n", info("INFO:"))
			os.Exit(1)
		}

		if enableDirBrute || enableJSAnalyzer || enableDNSEnum || allModules {
			fmt.Printf("%s The -C flag (custom target file) can only be used with -S and/or -H flags\n", error_("ERROR:"))
			fmt.Printf("%s Invalid usage: Directory bruteforcing (-D), JS analysis (-J), DNS enumeration (-N), or all modules (-A)\n", error_("ERROR:"))
			fmt.Printf("%s Example usage: ./bbrecon -C targets.txt -S -H\n", info("INFO:"))
			os.Exit(1)
		}
	}

	if allModules {
		if enableDirBrute || enableJSAnalyzer || enableDNSEnum || enableSubdomain || enableHTTPProbe || enableExposureDetection {
			fmt.Printf("%s The -A flag (all modules) must be used standalone\n", error_("ERROR:"))
			fmt.Printf("%s Invalid usage: Cannot use -A with -D, -J, -N, -S, -H, or -X flags\n", error_("ERROR:"))
			fmt.Printf("%s Example usage: ./bbrecon -t example.com -A\n", info("INFO:"))
			os.Exit(1)
		}
	}

	if !enableSubdomain && !allModules && (excludeSources != "" || recursive || matchSubdomains != "" || filterSubdomains != "" || resolveIP || showStats) {
		fmt.Printf("%s Subdomain enumeration options detected, but subdomain module is not enabled.\n", color.HiYellowString("WARNING:"))
		fmt.Printf("%s Add -S or -A to enable subdomain enumeration.\n", color.HiBlueString("INFO:"))

		if enableDirBrute {
			fmt.Printf("%s Usage: ./bbrecon -t example.com -S -D (subdomain options require -S flag)\n", error_("ERROR:"))
			os.Exit(1)
		}
	}

	var cfg config.Config
	if configFile != "" {
		loadedCfg, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Printf("%s Loading config file: %v\n", error_("ERROR:"), err)
			os.Exit(1)
		}
		cfg = *loadedCfg
		debugPrint("Loaded configuration from %s", configFile)
	} else {
		cfg = config.DefaultConfig()
		debugPrint("Using default configuration")
	}

	var targets []string

	if customTargetFile != "" {
		var err error
		targets, err = loadTargetsFromFile(customTargetFile)
		if err != nil {
			fmt.Printf("%s Failed to load targets from file: %v\n", error_("ERROR:"), err)
			os.Exit(1)
		}
		if len(targets) == 0 {
			fmt.Printf("%s No valid targets found in file\n", error_("ERROR:"))
			os.Exit(1)
		}

		if enableSubdomain || allModules {
			var validDomains []string

			if debug {
				fmt.Printf("%s Validating domains for subdomain enumeration\n", info("DEBUG:"))
			}

			for _, target := range targets {

				domain := target

				if debug {
					fmt.Printf("%s Original domain from file: %s\n", info("DEBUG:"), domain)
				}

				domain = strings.TrimPrefix(strings.TrimPrefix(domain, "http://"), "https://")

				if idx := strings.Index(domain, "/"); idx != -1 {
					domain = domain[:idx]
				}

				if debug {
					fmt.Printf("%s Cleaned domain: %s\n", info("DEBUG:"), domain)
				}

				valid := isValidDomain(domain)
				if valid {
					validDomains = append(validDomains, domain)

					if debug {
						fmt.Printf("%s Valid domain: %s\n", success("SUCCESS:"), domain)
					}
				} else {

					fmt.Printf("%s Invalid domain format in file: %s\n", warn("WARNING:"), domain)
				}
			}

			if len(validDomains) == 0 {
				fmt.Printf("%s No valid domains found in input: %s\n", error_("ERROR:"), strings.Join(targets, ", "))
				fmt.Printf("%s Please provide at least one valid domain\n", info("INFO:"))
				os.Exit(1)
			}

			targets = validDomains
		} else {

			for i, target := range targets {
				if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
					targets[i] = "http://" + target
				}
			}
		}

		fmt.Printf("%s Loaded %d targets from %s\n", info("INFO:"), len(targets), customTargetFile)
	}

	needsAPIKeys := enableSubdomain || allModules

	if needsAPIKeys && !bruteforceOnlyMode {

		homeDir, err := os.UserHomeDir()
		if err == nil {
			apiKeysPath := filepath.Join(homeDir, ".config", "bbrecon", "api_keys.yaml")
			err = config.LoadAPIKeys(apiKeysPath, &cfg)
			if err != nil {
				debugPrint("Failed to load API keys: %v", err)
			} else {
				debugPrint("Loaded API keys from %s", apiKeysPath)
			}

			currentDirAPIKeys := "api_keys.yaml"
			if _, err := os.Stat(currentDirAPIKeys); err == nil {
				err = config.LoadAPIKeys(currentDirAPIKeys, &cfg)
				if err != nil {
					debugPrint("Failed to load API keys from current directory: %v", err)
				} else {
					debugPrint("Loaded API keys from current directory")
				}
			}
		}
	}

	if targetDomain != "" && len(os.Args) <= 3 && !strings.Contains(strings.Join(os.Args, " "), "-S") && !bruteforceOnlyMode {

		currentDirAPIKeys := "api_keys.yaml"
		if _, err := os.Stat(currentDirAPIKeys); err == nil {
			fmt.Printf("%s %s\n", color.YellowString("Loading API keys from:"), color.WhiteString("api_keys.yaml"))

			apiKeysWithValues := make(map[string]string)

			apiKeysData, err := os.ReadFile(currentDirAPIKeys)
			if err == nil {

				lines := strings.Split(string(apiKeysData), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}

					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[0])
						value := strings.TrimSpace(parts[1])

						// Remove any comments that follow the value
						if commentIdx := strings.Index(value, "#"); commentIdx >= 0 {
							value = value[:commentIdx]
						}

						value = strings.TrimSpace(value)
						value = strings.Trim(value, "\"' ")

						// Only consider values that are not empty and not placeholders
						if value != "" &&
							!strings.Contains(value, "YOUR_") &&
							!strings.Contains(value, "XXXX") {
							serviceName := strings.TrimSuffix(key, "_api_key")
							serviceName = strings.TrimSuffix(serviceName, "_key")
							serviceName = strings.TrimSuffix(serviceName, "_api")

							// Store actual key/value pairs that have non-empty values
							apiKeysWithValues[serviceName] = value
							if debug {
								fmt.Printf("Adding key %s with value: %s\n", serviceName, value)
							}
						}
					}
				}
			}

			// Only display debug info if in debug mode
			if debug {
				fmt.Printf("--- DEBUG API KEYS INFO ---\n")
				fmt.Printf("API keys with values (%d): %v\n", len(apiKeysWithValues), keys(apiKeysWithValues))
			}

			// Get all defined sources
			allSources := subdomain.GetAllSourceNames()

			// Get actual premium sources from the defined sources
			premiumSources := []string{}
			for _, source := range allSources {
				if subdomain.IsSourcePremium(source) {
					premiumSources = append(premiumSources, source)
				}
			}

			// Count free and premium sources
			freeSources, totalPremiumSources := subdomain.CountSourceTypes(allSources)

			// Print all premium sources only in debug mode
			if debug {
				fmt.Printf("All premium sources (%d): %v\n", len(premiumSources), premiumSources)
			}

			// Filter to identify ACTUAL premium sources with valid keys
			validPremiumKeys := []string{}
			for keyName := range apiKeysWithValues {
				for _, source := range premiumSources {
					if strings.EqualFold(keyName, source) {
						validPremiumKeys = append(validPremiumKeys, source)
						if debug {
							fmt.Printf("Matched premium key with value: %s = %s\n", keyName, source)
						}
						break
					}
				}
			}

			// Print debug info for comparison only in debug mode
			if debug {
				fmt.Printf("Found keys with values (%d): %v\n", len(apiKeysWithValues), keys(apiKeysWithValues))
				fmt.Printf("Matched premium keys with values (%d): %v\n", len(validPremiumKeys), validPremiumKeys)
				fmt.Printf("--- END DEBUG INFO ---\n")
			}

			if len(validPremiumKeys) > 0 {
				// Show only first 3 keys with ellipsis if more
				activeKeysStr := strings.Join(validPremiumKeys[:min(len(validPremiumKeys), 3)], ", ")
				if len(validPremiumKeys) > 3 {
					activeKeysStr += "..."
				}

				// Improved API key messaging
				fmt.Printf("%s Found %d/%d premium sources (active: %s)\n",
					color.HiCyanString("API Keys:"),
					len(validPremiumKeys),
					totalPremiumSources,
					color.YellowString(activeKeysStr))

				// Different message based on flags
				if bruteforceOnlyMode {
					fmt.Printf("%s Subdomain enumeration mode: Bruteforce only (API sources disabled)\n",
						info("NOTE:"))
				} else if all {
					fmt.Printf("%s PREMIUM MODE: Using all available sources (%d free + %d premium)\n",
						info("NOTE:"),
						freeSources,
						len(validPremiumKeys))

					if totalPremiumSources-len(validPremiumKeys) > 0 {
						fmt.Printf("%s Missing keys for %d premium sources - results may be limited\n",
							info("TIP:"),
							totalPremiumSources-len(validPremiumKeys))
					}
				} else {
					fmt.Printf("%s Using: %d free sources + %d premium sources with valid keys\n",
						info("NOTE:"),
						freeSources,
						len(validPremiumKeys))
				}

				if debug {
					fmt.Printf("%s Active premium keys: %s\n", info("DEBUG:"), strings.Join(validPremiumKeys, ", "))

					// Calculate missing premium sources
					missingKeys := []string{}
					for _, source := range premiumSources {
						if !contains(validPremiumKeys, source) {
							missingKeys = append(missingKeys, source)
						}
					}

					if len(missingKeys) > 0 {
						missingStr := strings.Join(missingKeys[:min(len(missingKeys), 5)], ", ")
						if len(missingKeys) > 5 {
							missingStr += fmt.Sprintf("... (and %d more)", len(missingKeys)-5)
						}
						fmt.Printf("%s Missing premium sources: %s\n", info("DEBUG:"), missingStr)
					}
				}
			} else {
				fmt.Printf("%s No valid keys found\n",
					color.HiCyanString("API Keys:"))
				fmt.Printf("%s Using: %d free sources only (premium sources skipped)\n",
					info("NOTE:"),
					freeSources)
				fmt.Printf("%s Add API keys to api_keys.yaml for better results\n",
					info("TIP:"))
			}
		} else {
			fmt.Printf("%s %s\n", color.YellowString("Loading API keys from:"), color.WhiteString("api_keys.yaml"))

			// Get count of free sources for the message
			allSources := subdomain.GetAllSourceNames()
			freeSources, _ := subdomain.CountSourceTypes(allSources)

			fmt.Printf("%s No valid keys found\n",
				color.HiCyanString("API Keys:"))
			fmt.Printf("%s Using: %d free sources only (premium sources skipped)\n",
				info("NOTE:"),
				freeSources)
			fmt.Printf("%s Add API keys to api_keys.yaml for better results\n",
				info("TIP:"))
		}
	}

	domainList := parseDomainList(targetDomain)

	if customTargetFile != "" && len(targets) > 0 {
		domainList = targets
	}

	if allModules && customTargetFile != "" {
		printBanner()
		fmt.Printf("%s SAGA Mode (-A) cannot be used with custom target file (-C)\n", error_("ERROR:"))
		os.Exit(1)
	}

	if enableDirBrute && len(domainList) > 1 && !allModules {
		printBanner()
		fmt.Printf("%s Directory bruteforcing (-D) is not allowed with multiple domains\n", error_("ERROR:"))
		fmt.Printf("%s Please specify a single domain when using -D flag\n", info("INFO:"))
		fmt.Printf("%s Example: ./bbrecon -t example.com -D\n", info("USAGE:"))
		os.Exit(1)
	}

	if enableDNSEnum && len(domainList) > 1 && !allModules {
		printBanner()
		fmt.Printf("%s DNS enumeration (-N) is not allowed with multiple domains\n", error_("ERROR:"))
		fmt.Printf("%s Please specify a single domain when using -N flag\n", info("INFO:"))
		fmt.Printf("%s Example: ./bbrecon -t example.com -N\n", info("USAGE:"))
		os.Exit(1)
	}

	for _, domain := range domainList {
		debugPrint("Processing domain: %s", domain)

		cfg.Target = domain

		if threads > 0 {
			cfg.Threads = threads
		}
		if timeout > 0 {
			cfg.Timeout = timeout
		}

		resultsDir := "results"

		if outputFile != "" {

			outDir := filepath.Dir(outputFile)

			if !filepath.IsAbs(outDir) {
				workDir, err := os.Getwd()
				if err == nil {
					outDir = filepath.Join(workDir, outDir)
					outputFile = filepath.Join(workDir, outputFile)
				}
			}

			resultsDir = outDir
			if err := os.MkdirAll(resultsDir, 0755); err != nil {
				fmt.Printf("%s Creating output directory: %v\n", error_("ERROR:"), err)
				os.Exit(1)
			}
			cfg.OutputFile = outputFile
		} else {

			if !filepath.IsAbs(resultsDir) {
				workDir, err := os.Getwd()
				if err == nil {
					resultsDir = filepath.Join(workDir, resultsDir)
				}
			}

			if err := os.MkdirAll(resultsDir, 0755); err != nil {
				fmt.Printf("%s Creating results directory: %v\n", error_("ERROR:"), err)
				os.Exit(1)
			}

			if domain != "" {
				cfg.OutputFile = filepath.Join(resultsDir, fmt.Sprintf("%s.txt", domain))
			} else {

				baseFileName := filepath.Base(customTargetFile)
				baseFileName = strings.TrimSuffix(baseFileName, filepath.Ext(baseFileName))
				cfg.OutputFile = filepath.Join(resultsDir, fmt.Sprintf("%s_results.txt", baseFileName))
			}
		}

		if sourcesFlag != "" {

			if !enableSubdomain && !allModules {
				enableSubdomain = true

				sources := strings.Split(sourcesFlag, ",")
				validSources, invalidSources := subdomain.ValidateSources(sources)

				if len(validSources) > 0 {
					freeCount, premiumCount := subdomain.CountSourceTypes(validSources)
					fmt.Printf("%s Auto-enabling subdomain enumeration with %d free and %d premium sources\n",
						info("NOTE:"), freeCount, premiumCount)

					cfg.SubdomainConfig.Sources = validSources

					if debug {
						fmt.Printf("[DEBUG] Using sources: %v\n", validSources)
					}

					if len(invalidSources) > 0 {
						fmt.Printf("WARNING: The following sources are invalid: %s\n",
							strings.Join(invalidSources, ", "))
					}
				} else {
					fmt.Printf("ERROR: No valid sources specified. Cannot run subdomain enumeration.\n")

					enableSubdomain = false
					cfg.SubdomainConfig.Enabled = false

					if !enableHTTPProbe && !enableDirBrute && !enableJSAnalyzer && !enableDNSEnum && !allModules {
						fmt.Printf("Available sources: %v\n", strings.Join(subdomain.GetAllSourceNames(), ", "))
						os.Exit(1)
					}
				}
			} else {

				sources := strings.Split(sourcesFlag, ",")

				validSources, invalidSources := subdomain.ValidateSources(sources)

				if len(invalidSources) > 0 {
					fmt.Printf("WARNING: The following sources are invalid: %s\n",
						strings.Join(invalidSources, ", "))
				}

				if len(validSources) == 0 {
					fmt.Printf("ERROR: No valid sources specified. Cannot run subdomain enumeration.\n")
					fmt.Printf("Available sources: %v\n", strings.Join(subdomain.GetAllSourceNames(), ", "))

					enableSubdomain = false
					cfg.SubdomainConfig.Enabled = false

					if !enableHTTPProbe && !enableDirBrute && !enableJSAnalyzer && !enableDNSEnum && !allModules {
						os.Exit(1)
					}
				} else {

					cfg.SubdomainConfig.Sources = validSources

					if debug {
						fmt.Printf("[DEBUG] Using sources: %v\n", validSources)
					}

					freeCount, premiumCount := subdomain.CountSourceTypes(validSources)
					fmt.Printf("%s Auto-enabled subdomain enumeration with %d free source(s) and %d premium source(s)\n",
						info("NOTE:"), freeCount, premiumCount)

					if premiumCount > 0 {
						fmt.Printf("%s To use premium sources, add API keys in api_keys.yaml\n",
							info("NOTE:"))
					}
				}
			}
		} else if enableSubdomain || allModules {

			if !bruteforceOnlyMode {
				availableSources := subdomain.GetAvailableSources(cfg.SubdomainConfig)
				freeCount, premiumCount := subdomain.CountSourceTypes(availableSources)

				// Only show this in debug mode as it's redundant with our new messaging
				if debug {
					fmt.Printf("%s Using available sources (%d free and %d premium)\n",
						info("DEBUG:"), freeCount, premiumCount)
				}
			}
		}

		if excludeSources != "" {
			excluded := strings.Split(excludeSources, ",")
			cfg.SubdomainConfig.ExcludedSources = excluded
			debugPrint("Excluding sources: %v", excluded)
		}

		if recursive {
			cfg.SubdomainConfig.Recursive = true
			debugPrint("Using recursive sources only")
		}

		if all {

			if !enableSubdomain && !allModules {
				enableSubdomain = true

				allSources := subdomain.GetAllSourceNames()
				freeCount, premiumCount := subdomain.CountSourceTypes(allSources)
				fmt.Printf("%s Auto-enabling subdomain enumeration with all available sources (%d free and %d premium)\n",
					info("NOTE:"), freeCount, premiumCount)

				if premiumCount > 0 {
					fmt.Printf("%s To use premium sources, configure API keys in ~/.config/bbrecon/config.yaml\n",
						info("NOTE:"))
				}
			}

			cfg.SubdomainConfig.UseAllSources = true

			if debug {
				debugPrint("Using all available sources")
			}
		}

		if matchSubdomains != "" {
			if _, err := os.Stat(matchSubdomains); err == nil {
				data, err := os.ReadFile(matchSubdomains)
				if err == nil {
					matches := strings.Split(string(data), "\n")
					cfg.SubdomainConfig.MatchSubdomains = matches
					debugPrint("Loaded %d subdomain patterns to match from file", len(matches))
				}
			} else {
				matches := strings.Split(matchSubdomains, ",")
				cfg.SubdomainConfig.MatchSubdomains = matches
				debugPrint("Using subdomain patterns to match: %v", matches)
			}
		}

		if filterSubdomains != "" {
			if _, err := os.Stat(filterSubdomains); err == nil {
				data, err := os.ReadFile(filterSubdomains)
				if err == nil {
					filters := strings.Split(string(data), "\n")
					cfg.SubdomainConfig.FilterSubdomains = filters
					debugPrint("Loaded %d subdomain patterns to filter from file", len(filters))
				}
			} else {
				filters := strings.Split(filterSubdomains, ",")
				cfg.SubdomainConfig.FilterSubdomains = filters
				debugPrint("Using subdomain patterns to filter: %v", filters)
			}
		}

		if resolveIP {
			cfg.SubdomainConfig.ResolveIP = true
			debugPrint("Will resolve IPs for discovered subdomains")
		}

		if !silent {
			debugPrint("Target: %s", cfg.Target)
			debugPrint("Threads: %d", cfg.Threads)
			debugPrint("Timeout: %ds", cfg.Timeout)
			debugPrint("Output: %s", cfg.OutputFile)

			if cfg.SubdomainConfig.Enabled {
				fmt.Printf("%s Some sources may be skipped due to missing API keys\n", warn("WARNING:"))
			}
		}

		onlyTargetSpecified := !enableSubdomain && !enableHTTPProbe &&
			!enableDirBrute && !enableJSAnalyzer && !enableDNSEnum && !allModules

		if enableHTTPProbe && !enableSubdomain && !enableDirBrute && !enableJSAnalyzer && !allModules {

			startTime := time.Now()

			fmt.Printf("\n%s Enhanced HTTP probe for target: %s\n", info("INFO:"), cfg.Target)

			prober := httpprobe.NewProber([]string{cfg.Target}, cfg.HTTPProbeConfig, cfg.Timeout)
			result, err := prober.EnhancedSingleProbe(cfg.Target)
			if err != nil {
				fmt.Printf("%s Error probing target: %v\n", error_("ERROR:"), err)
				os.Exit(1)
			}

			fmt.Printf("\n%s Basic Information:\n", success("[+]"))
			fmt.Printf("    Host: %s\n", result.Host)
			fmt.Printf("    IP: %s\n", result.IP)
			fmt.Printf("    Status: %d %s\n", result.StatusCode, http.StatusText(result.StatusCode))
			fmt.Printf("    Response Time: %v\n", result.ResponseTime)

			if result.WebServer != "" {
				fmt.Printf("\n%s Server Information:\n", success("[+]"))
				fmt.Printf("    Server: %s\n", result.WebServer)
				if len(result.Technologies) > 0 {
					fmt.Printf("    Technologies:\n")
					for _, tech := range result.Technologies {
						fmt.Printf("        - %s", tech.Name)
						if tech.Version != "" {
							fmt.Printf(" (%s)", tech.Version)
						}
						fmt.Printf("\n")
					}
				}
			}

			if result.TLS != nil {
				fmt.Printf("\n%s SSL/TLS Information:\n", success("[+]"))
				fmt.Printf("    Certificate Valid: Yes\n")
				fmt.Printf("    Issuer: %s\n", result.TLS.Issuer)
				fmt.Printf("    Expires: %s\n", result.TLS.NotAfter)
				fmt.Printf("    SSL Version: %s\n", result.TLS.Version)
			}

			if len(result.SecurityHeaders) > 0 {
				fmt.Printf("\n%s Security Headers:\n", success("[+]"))
				for header, present := range result.SecurityHeaders {
					if present {
						fmt.Printf("    [%s] %s: %s\n", success("✓"), header, result.Headers[header])
					} else {
						fmt.Printf("    [%s] %s: Not Set\n", warn("✗"), header)
					}
				}
			}

			if result.Title != "" || result.ContentType != "" {
				fmt.Printf("\n%s Page Information:\n", success("[+]"))
				if result.Title != "" {
					fmt.Printf("    Title: %s\n", result.Title)
				}
				if result.ContentType != "" {
					fmt.Printf("    Content Type: %s\n", result.ContentType)
				}
				fmt.Printf("    Response Size: %d bytes\n", result.ResponseSize)
			}

			// Generate output filename
			var httpOutputFile string
			if outputFile != "" {
				// Use the exact file path provided by the user
				httpOutputFile = outputFile
			} else {
				httpOutputFile = filepath.Join(resultsDir, fmt.Sprintf("%s_enhanced_http_%s.txt",
					sanitizeFilename(cfg.Target),
					time.Now().Format("0102_1504")))
			}

			f, err := os.Create(httpOutputFile)
			if err == nil {
				defer f.Close()
				fmt.Fprintf(f, "BBRECON - Bug Bounty Recon Tool\n")
				fmt.Fprintf(f, "Version: v1.0.0\n")
				fmt.Fprintf(f, "Created by: Zarni(Neo)\n")
				fmt.Fprintf(f, "Scan Time: %s\n", time.Now().Format(time.RFC3339))
				fmt.Fprintf(f, "Target: %s\n\n", cfg.Target)

				fmt.Fprintf(f, "[+] Basic Information:\n")
				fmt.Fprintf(f, "    Host: %s\n", result.Host)
				fmt.Fprintf(f, "    IP: %s\n", result.IP)
				fmt.Fprintf(f, "    Status: %d %s\n", result.StatusCode, http.StatusText(result.StatusCode))
				fmt.Fprintf(f, "    Response Time: %v\n\n", result.ResponseTime)

				fmt.Fprintf(f, "[+] Server Information:\n")
				fmt.Fprintf(f, "    Server: %s\n", result.WebServer)
				fmt.Fprintf(f, "    Technologies:\n")
				for _, tech := range result.Technologies {
					fmt.Fprintf(f, "        - %s\n", tech.Name)
					if tech.Category != "" {
						fmt.Fprintf(f, "          Category: %s\n", tech.Category)
					}
					if tech.Version != "" {
						fmt.Fprintf(f, "          Version: %s\n", tech.Version)
					}
				}
				fmt.Fprintf(f, "\n")

				if result.TLS != nil {
					fmt.Fprintf(f, "[+] SSL/TLS Information:\n")
					fmt.Fprintf(f, "    Certificate Valid: Yes\n")
					fmt.Fprintf(f, "    Issuer: %s\n", result.TLS.Issuer)
					fmt.Fprintf(f, "    Expires: %s\n", result.TLS.NotAfter)
					fmt.Fprintf(f, "    SSL Version: %s\n\n", result.TLS.Version)
				}

				fmt.Fprintf(f, "[+] Security Headers:\n")
				for header, present := range result.SecurityHeaders {
					status := "Not Set"
					icon := "[FAIL]"
					if present {
						status = result.Headers[header]
						icon = "[PASS]"
					}
					fmt.Fprintf(f, "    %s %s: %s\n", icon, header, status)
				}
				fmt.Fprintf(f, "\n")

				fmt.Fprintf(f, "[+] Page Information:\n")
				if result.Title != "" {
					fmt.Fprintf(f, "    Title: %s\n", result.Title)
				}
				fmt.Fprintf(f, "    Content Type: %s\n", result.ContentType)
				fmt.Fprintf(f, "    Response Size: %d bytes\n\n", result.ResponseSize)

				fmt.Fprintf(f, "[+] All Response Headers:\n")
				for header, value := range result.Headers {
					fmt.Fprintf(f, "    %s: %s\n", header, value)
				}
				fmt.Fprintf(f, "\n")

				fmt.Fprintf(f, "[+] CURL Command for Reproducing:\n")
				fmt.Fprintf(f, "    curl -I -H \"User-Agent: BBRECON/1.0\" %s\n\n", cfg.Target)

				fmt.Fprintf(f, "[+] Security Assessment Summary:\n")
				totalHeaders := len(result.SecurityHeaders)
				headersSet := 0
				for _, present := range result.SecurityHeaders {
					if present {
						headersSet++
					}
				}
				securityScore := float64(headersSet) / float64(totalHeaders) * 100
				fmt.Fprintf(f, "    Total Headers Checked: %d\n", totalHeaders)
				fmt.Fprintf(f, "    Headers Properly Set: %d\n", headersSet)
				fmt.Fprintf(f, "    Headers Missing: %d\n", totalHeaders-headersSet)
				fmt.Fprintf(f, "    Overall Security Score: %.1f%%\n", securityScore)
			}

			fmt.Printf("\n%s Scan Complete!\n", success("[✓]"))
			fmt.Printf("    Duration: %v\n", time.Since(startTime))
			if err == nil {
				fmt.Printf("    Output saved to: %s\n", httpOutputFile)
			}

			continue
		}

		if onlyTargetSpecified {
			if enableExposureDetection {
				// Skip subdomain enumeration if only -X flag is used
				cfg.SubdomainConfig.Enabled = false
				cfg.HTTPProbeConfig.Enabled = false
				cfg.DirBruteConfig.Enabled = false
				cfg.JSAnalyzerConfig.Enabled = false

				startTime = time.Now()
				fmt.Printf("\n%s %s %s %s\n",
					primary("["),
					statusWarning("*"),
					primary("]"),
					accent("Starting Exposure Detection..."))

				fmt.Printf("%s Target: %s\n", info("INFO:"), targetDomain)

				detector := exposure.NewDetector()
				err := detector.Detect(targetDomain)
				if err != nil {
					fmt.Printf("%s Exposure detection error: %v\n", error_("ERROR:"), err)
					os.Exit(1)
				}

				// Process findings
				if len(detector.Findings) > 0 {
					// Generate output filename
					var expOutputFile string
					if outputFile != "" {
						// Use the exact file path provided by the user
						expOutputFile = outputFile
					} else {
						expOutputFile = generateUniqueFilename(resultsDir, cfg.Target, "EXP")
					}

					// Save findings to file
					f, err := os.Create(expOutputFile)
					if err != nil {
						fmt.Printf("%s Creating exposure results file: %v\n", error_("ERROR:"), err)
						os.Exit(1)
					}
					defer f.Close()

					// Write header
					fmt.Fprintf(f, "EXPOSURE DETECTION RESULTS\n\n")
					fmt.Fprintf(f, "Target: %s\n", cfg.Target)
					fmt.Fprintf(f, "Scan Date: %s\n", time.Now().Format("2006-01-02 15:04:05"))
					fmt.Fprintf(f, "Total Findings: %d\n\n", len(detector.Findings))

					// Group findings by severity
					highSev := make([]exposure.Finding, 0)
					medSev := make([]exposure.Finding, 0)

					for _, finding := range detector.Findings {
						if finding.Severity == "HIGH" {
							highSev = append(highSev, finding)
						} else {
							medSev = append(medSev, finding)
						}
					}

					// Write summary
					fmt.Fprintf(f, "SUMMARY\n")
					fmt.Fprintf(f, "• HIGH Severity:   %d findings\n", len(highSev))
					fmt.Fprintf(f, "• MEDIUM Severity: %d findings\n\n", len(medSev))

					// Write findings by severity
					if len(highSev) > 0 {
						fmt.Fprintf(f, "HIGH SEVERITY FINDINGS\n\n")
						for i, finding := range highSev {
							fmt.Fprintf(f, "[%d] %s\n", i+1, finding.Type)
							fmt.Fprintf(f, "URL: %s\n", finding.URL)
							if finding.StatusCode > 0 {
								fmt.Fprintf(f, "Status: %d\n", finding.StatusCode)
							}
							if finding.ContentType != "" {
								fmt.Fprintf(f, "Content-Type: %s\n", finding.ContentType)
							}
							if finding.Value != "" {
								fmt.Fprintf(f, "Value: %s\n", finding.Value)
							}
							if finding.LineNumber > 0 {
								fmt.Fprintf(f, "Line: %d\n", finding.LineNumber)
							}
							if finding.POC != "" {
								fmt.Fprintf(f, "POC: %s\n", finding.POC)
							}
							if finding.Confidence != "" {
								fmt.Fprintf(f, "Confidence: %s\n", finding.Confidence)
							}
							if len(finding.Evidence) > 0 {
								fmt.Fprintf(f, "Evidence:\n")
								for _, ev := range finding.Evidence {
									fmt.Fprintf(f, "  %s\n", ev)
								}
							}
							fmt.Fprintf(f, "\n")
						}
					}

					if len(medSev) > 0 {
						fmt.Fprintf(f, "MEDIUM SEVERITY FINDINGS\n\n")
						for i, finding := range medSev {
							fmt.Fprintf(f, "[%d] %s\n", i+1, finding.Type)
							fmt.Fprintf(f, "URL: %s\n", finding.URL)
							if finding.StatusCode > 0 {
								fmt.Fprintf(f, "Status: %d\n", finding.StatusCode)
							}
							if finding.ContentType != "" {
								fmt.Fprintf(f, "Content-Type: %s\n", finding.ContentType)
							}
							if finding.Value != "" {
								fmt.Fprintf(f, "Value: %s\n", finding.Value)
							}
							if finding.LineNumber > 0 {
								fmt.Fprintf(f, "Line: %d\n", finding.LineNumber)
							}
							if finding.POC != "" {
								fmt.Fprintf(f, "POC: %s\n", finding.POC)
							}
							if finding.Confidence != "" {
								fmt.Fprintf(f, "Confidence: %s\n", finding.Confidence)
							}
							if len(finding.Evidence) > 0 {
								fmt.Fprintf(f, "Evidence:\n")
								for _, ev := range finding.Evidence {
									fmt.Fprintf(f, "  %s\n", ev)
								}
							}
							fmt.Fprintf(f, "\n")
						}
					}

					fmt.Printf("%s Found %d potential exposures:\n", success("SUCCESS:"), len(detector.Findings))
					fmt.Printf("    • HIGH Severity: %d\n", len(highSev))
					fmt.Printf("    • MEDIUM Severity: %d\n", len(medSev))
					fmt.Printf("\n%s Exposure results saved to: %s\n", success("SUCCESS:"), expOutputFile)
				} else {
					fmt.Printf("%s No potential exposures found\n", info("INFO:"))
				}

				scanDuration := time.Since(startTime)
				fmt.Printf("\n%s %s %s %s\n",
					primary("["),
					statusSuccess("✓"),
					primary("]"),
					accent("Scan Complete!"))
				fmt.Printf("%s Scan duration: %s\n", info("INFO:"), formatDuration(scanDuration))
				os.Exit(0)
			} else {
				cfg.SubdomainConfig.Enabled = true
				cfg.HTTPProbeConfig.Enabled = true
				cfg.DirBruteConfig.Enabled = false
				cfg.JSAnalyzerConfig.Enabled = false
			}

			cfg.SubdomainConfig.EnableBruteForce = false

			if !silent && !bruteforceOnlyMode && !enableExposureDetection {

				// Use all available sources (free + premium with API keys) instead of just default sources
				availableSources := subdomain.GetAvailableSources(cfg.SubdomainConfig)
				freeCount, premiumCount := subdomain.CountSourceTypes(availableSources)

				fmt.Printf("%s Auto-enabling subdomain enumeration with available sources (%d free and %d premium)\n",
					info("NOTE:"), freeCount, premiumCount)

				if premiumCount > 0 {
					fmt.Printf("%s To use premium sources, add API keys in ~/api_keys.yaml\n",
						info("NOTE:"))
				}

				// Set the available sources to be used
				cfg.SubdomainConfig.Sources = availableSources

				debugPrint("No modules specified, enabling subdomain enumeration by default (sources only)")
			}
		} else {
			cfg.SubdomainConfig.Enabled = enableSubdomain || allModules
			cfg.HTTPProbeConfig.Enabled = enableHTTPProbe || allModules
			cfg.DirBruteConfig.Enabled = enableDirBrute || allModules
			cfg.JSAnalyzerConfig.Enabled = enableJSAnalyzer || allModules

			if allModules {
				sagaMode = true
				if !silent {
					debugPrint("Full saga mode enabled with -A: subdomain → DNS → HTTP → directories → JavaScript")
					fmt.Printf("%s Saga mode enabled: modules will run sequentially with dependencies\n", info("INFO:"))
				}
			}
		}

		if !silent {
			debugPrint("Enabled modules: %s", getEnabledModules(cfg))
		}

		if wordlistPath != "" {
			if err := cfg.SetWordlist("subdomain", wordlistPath); err != nil {
				fmt.Printf("%s Loading wordlist: %v\n", error_("ERROR:"), err)
				os.Exit(1)
			}
			cfg.SetWordlist("directory", wordlistPath)
			if !silent {
				debugPrint("Loaded wordlist: %s", wordlistPath)
			}

			if cfg.SubdomainConfig.Enabled {
				cfg.SubdomainConfig.EnableBruteForce = true
				cfg.SubdomainConfig.DisableAPISources = true

				bruteforceOnlyMode = true

				fmt.Printf("%s Subdomain enumeration mode: Bruteforce only (API sources disabled)\n",
					info("INFO:"))

			}
		} else if cfg.SubdomainConfig.Enabled || cfg.DirBruteConfig.Enabled {
			if cfg.SubdomainConfig.Enabled && cfg.SubdomainConfig.EnableBruteForce {

				defaultSubdomainWordlist := "wordlists/subdomains.txt"
				if _, err := os.Stat(defaultSubdomainWordlist); err == nil {
					if err := cfg.SetWordlist("subdomain", defaultSubdomainWordlist); err != nil {
						fmt.Printf("%s Loading default subdomain wordlist: %v\n", error_("ERROR:"), err)
						os.Exit(1)
					}
					if !silent {
						debugPrint("Using default wordlist for subdomain enumeration: %s", defaultSubdomainWordlist)
					}
				} else if onlyTargetSpecified {

					defaultWordlist := []string{"www", "mail", "admin", "blog", "dev", "test", "api", "docs", "shop", "app"}
					tempFile, err := os.CreateTemp("", "default-subdomains-*.txt")
					if err != nil {
						fmt.Printf("%s Creating default wordlist: %v\n", error_("ERROR:"), err)
						os.Exit(1)
					}
					defer os.Remove(tempFile.Name())

					for _, subdomain := range defaultWordlist {
						tempFile.WriteString(subdomain + "\n")
					}
					tempFile.Close()

					if err := cfg.SetWordlist("subdomain", tempFile.Name()); err != nil {
						fmt.Printf("%s Loading default wordlist: %v\n", error_("ERROR:"), err)
						os.Exit(1)
					}
					if !silent {
						debugPrint("Using built-in default wordlist for subdomain enumeration")
					}
				}
			}

			if cfg.DirBruteConfig.Enabled {

				defaultDirWordlist := "wordlists/directories.txt"
				if _, err := os.Stat(defaultDirWordlist); err == nil {
					if err := cfg.SetWordlist("directory", defaultDirWordlist); err != nil {
						fmt.Printf("%s Loading default directory wordlist: %v\n", error_("ERROR:"), err)
						os.Exit(1)
					}
					if !silent {
						debugPrint("Using default wordlist for directory brute-forcing: %s", defaultDirWordlist)
					}
				} else if !allModules {

					fmt.Printf("%s Wordlist path (-w) is required for directory brute-forcing\n", error_("ERROR:"))
					os.Exit(1)
				}
			}
		}

		cfg.SubdomainConfig.ShowStats = showStats
		cfg.SubdomainConfig.Debug = debug

		var subdomainFindings []output.Finding
		var httpFindings []output.Finding
		var dirFindings []output.Finding
		var jsFindings []output.Finding
		var dnsFindings []output.Finding

		startTime = time.Now()

		var categorizedTargets map[string][]string
		var selectedTargets []string
		var targets []string

		if customTargetFile != "" {

			var err error
			targets, err = loadTargetsFromFile(customTargetFile)
			if err != nil {
				fmt.Printf("%s Failed to load targets from file: %v\n", error_("ERROR:"), err)
			} else {
				fmt.Printf("%s Using targets loaded from %s\n", info("INFO:"), customTargetFile)
			}
		}

		if len(targets) > 0 && enableJSAnalyzer && !enableHTTPProbe && !enableDirBrute && !enableSubdomain {
			cfg.JSAnalyzerConfig.IncludeURLs = targets
			cfg.Target = targets[0]
		}

		if cfg.SubdomainConfig.Enabled {
			fmt.Printf("\n%s %s %s\n",
				info("[ * ]"),
				color.MagentaString("Starting Subdomain Enumeration for"),
				color.HiCyanString(cfg.Target+"..."))

			sourcesToUse := subdomain.GetAvailableSources(cfg.SubdomainConfig)

			if cfg.SubdomainConfig.UseAllSources {
				sourcesToUse = subdomain.GetAllSourceNames()
			}

			if !silent && !bruteforceOnlyMode {

				if customTargetFile == "" {
					displaySourcesWithAPIInfo(sourcesToUse, true)

					missingKeys := checkAPIKeysConfiguration(cfg, sourcesToUse)
					if len(missingKeys) > 0 {

						fmt.Println()
					}
				} else {

					displaySourcesWithAPIInfo(sourcesToUse, false)
				}
			}

			subdomainEnum := subdomain.NewEnum(cfg.Target, cfg.SubdomainConfig, cfg.Threads, cfg.Timeout)

			findings, err := subdomainEnum.Run()
			if err != nil {

				if debug || verbose {
					fmt.Printf("\n%s During subdomain enumeration: %v\n", error_("ERROR:"), err)
				} else {

					debugPrint("Error during subdomain enumeration: %v", err)
				}
			} else {
				subdomainFindings = findings

				sourceResults := make(map[string]int)
				for _, finding := range findings {
					if source, ok := finding.Data["source"].(string); ok {
						sourceResults[source]++
					}
				}

				// Display source statistics if -stats flag is used
				if showStats && len(sourceResults) > 0 {
					fmt.Printf("\n%s Source Statistics:\n", success("SUMMARY:"))

					// Convert map to slice for sorting
					type SourceCount struct {
						Name  string
						Count int
					}

					var sourceCounts []SourceCount
					for source, count := range sourceResults {
						sourceCounts = append(sourceCounts, SourceCount{
							Name:  source,
							Count: count,
						})
					}

					// Sort sources by count in descending order
					sort.Slice(sourceCounts, func(i, j int) bool {
						return sourceCounts[i].Count > sourceCounts[j].Count
					})

					// Calculate percentage contribution
					totalCount := len(findings)
					for _, sc := range sourceCounts {
						percentage := float64(sc.Count) / float64(totalCount) * 100
						fmt.Printf("  %s: %s (%s of total)\n",
							info(fmt.Sprintf("%-15s", sc.Name)),
							color.HiGreenString("%d subdomains", sc.Count),
							color.HiYellowString("%.1f%%", percentage))
					}
					fmt.Println()
				}

				var sdOutputFile string

				if outputFile != "" {
					// Use the exact file path provided by the user
					sdOutputFile = outputFile
				} else {
					// Only generate a unique filename if no custom file was specified
					sdOutputFile = generateUniqueFilename(resultsDir, cfg.Target, "SD")
				}

				f, err := os.Create(sdOutputFile)
				if err != nil {
					fmt.Printf("%s Creating subdomain results file: %v\n", error_("ERROR:"), err)
				} else {
					defer f.Close()

					// Write statistics to file if stats flag is enabled
					if showStats && len(sourceResults) > 0 {
						fmt.Fprintf(f, "# Subdomain Enumeration Statistics\n")
						fmt.Fprintf(f, "# Domain: %s\n", cfg.Target)
						fmt.Fprintf(f, "# Date: %s\n", time.Now().Format(time.RFC3339))
						fmt.Fprintf(f, "# Total Subdomains: %d\n\n", len(findings))
						fmt.Fprintf(f, "# Source Statistics\n")

						// Convert map to slice for sorting
						type SourceCount struct {
							Name  string
							Count int
						}

						var sourceCounts []SourceCount
						for source, count := range sourceResults {
							sourceCounts = append(sourceCounts, SourceCount{
								Name:  source,
								Count: count,
							})
						}

						// Sort sources by count in descending order
						sort.Slice(sourceCounts, func(i, j int) bool {
							return sourceCounts[i].Count > sourceCounts[j].Count
						})

						// Calculate percentage contribution
						totalCount := len(findings)
						for _, sc := range sourceCounts {
							percentage := float64(sc.Count) / float64(totalCount) * 100
							fmt.Fprintf(f, "# %s: %d subdomains (%.1f%%)\n",
								sc.Name, sc.Count, percentage)
						}

						fmt.Fprintf(f, "\n# Subdomains List\n")
					}

					// Write subdomains to file
					for _, finding := range findings {
						if subdomain, ok := finding.Data["subdomain"].(string); ok {
							fmt.Fprintf(f, "%s\n", subdomain)

							if !suppressResults {
								fmt.Printf("[%s] Subdomain: %s\n", info("info"), subdomain)
							}
						}
					}
					fmt.Printf("\n%s Total subdomains found: %s\n",
						success("SUMMARY:"),
						color.HiGreenString("%d", len(findings)))
					sdFilePathAbs, _ := filepath.Abs(sdOutputFile)
					fmt.Printf("%s Subdomain results saved to: %s\n", success("SUCCESS:"), sdFilePathAbs)
				}
			}
		}

		if enableDNSEnum || allModules {
			fmt.Printf("\n%s %s %s %s\n",
				primary("["),
				statusWarning("*"),
				primary("]"),
				accent("Starting DNS Enumeration..."))

			fmt.Println()

			recordCounts := make(map[string]int)
			startTime := time.Now()

			dnsTargets := []string{cfg.Target}
			if sagaMode && len(subdomainFindings) > 0 {
				dnsTargets = nil
				for _, finding := range subdomainFindings {
					if subdomain, ok := finding.Data["subdomain"].(string); ok {
						dnsTargets = append(dnsTargets, subdomain)
					}
				}
			}

			if customTargetFile != "" {
				var err error
				customDomains, err := loadTargetsFromFile(customTargetFile)
				if err != nil {
					fmt.Printf("%s Failed to load targets from file: %v\n", error_("ERROR:"), err)
				} else {
					var cleanDomains []string
					for _, target := range customDomains {
						domain := target

						if strings.Contains(domain, "://") {
							parts := strings.Split(domain, "://")
							if len(parts) > 1 {
								domain = parts[1]
							}
						}

						if strings.Contains(domain, "/") {
							domain = strings.Split(domain, "/")[0]
						}
						cleanDomains = append(cleanDomains, domain)
					}
					dnsTargets = cleanDomains
				}
			}

			dnsConfig := dnsenum.Config{
				RecordTypes:      []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA"},
				Timeout:          cfg.Timeout,
				Debug:            debug || verbose,
				CheckTakeover:    true,
				IncludeWildcards: false,
				AllRecords:       all,
			}

			if sagaMode && len(dnsTargets) > 100 {
				estimatedSeconds := len(dnsTargets) * 2
				estimatedTime := formatDuration(time.Duration(estimatedSeconds) * time.Second)

				fmt.Printf("\n%s Found %s subdomains. DNS enumeration may take approximately %s.\n",
					color.YellowString("WARNING:"),
					color.HiWhiteString("%d", len(dnsTargets)),
					color.HiWhiteString("%s", estimatedTime))

				fmt.Printf("%s Options:\n", color.CyanString("INFO:"))
				fmt.Printf("  1. Process all %d subdomains (estimated time: %s)\n", len(dnsTargets), estimatedTime)
				fmt.Printf("  2. Process a random sample of 100 subdomains (faster)\n")
				fmt.Printf("  3. Skip DNS enumeration\n")

				fmt.Printf("%s Enter your choice (1-3): ", color.CyanString("?"))
				var choice int
				fmt.Scanf("%d", &choice)

				switch choice {
				case 2:
					rand.Seed(time.Now().UnixNano())
					if len(dnsTargets) > 100 {
						rand.Shuffle(len(dnsTargets), func(i, j int) {
							dnsTargets[i], dnsTargets[j] = dnsTargets[j], dnsTargets[i]
						})
						dnsTargets = dnsTargets[:100]
					}
					fmt.Printf("%s Using a sample of 100 random subdomains\n",
						color.CyanString("INFO:"))
				case 3:
					fmt.Printf("%s Skipping DNS enumeration\n",
						color.CyanString("INFO:"))
					goto SkipDNSEnum
				}
			}

			dnsFindings, err := processDNSEnumerationWithBatching(dnsTargets, dnsConfig, cfg.Timeout, 200)

			if err != nil {
				fmt.Printf("%s Error during DNS enumeration: %v\n",
					error_("ERROR:"), err)
			}

			totalTime := time.Since(startTime)

			fmt.Printf("\n%s DNS enumeration completed in %s\n",
				success("SUMMARY:"),
				formatDuration(totalTime))

			fmt.Printf("\n%s Record types found:\n", primary("SUMMARY:"))

			recordTypes := make([]string, 0, len(recordCounts))
			for rt := range recordCounts {
				recordTypes = append(recordTypes, rt)
			}
			sort.Slice(recordTypes, func(i, j int) bool {
				return recordCounts[recordTypes[i]] > recordCounts[recordTypes[j]]
			})

			for _, rt := range recordTypes {
				count := recordCounts[rt]

				recordLabel := "records"
				if count == 1 {
					recordLabel = "record"
				}
				fmt.Printf("  %s : %d %s\n",
					info(fmt.Sprintf("%-5s", rt)),
					count,
					recordLabel)
			}

			var dnsOutputFile string

			if outputFile != "" {
				// Use the exact file path provided by the user
				dnsOutputFile = outputFile
			} else {
				dnsOutputFile = generateUniqueFilename(resultsDir, cfg.Target, "DNS")
			}

			if len(dnsFindings) > 0 {
				f, err := os.Create(dnsOutputFile)
				if err != nil {
					fmt.Printf("%s Creating DNS enumeration results file: %v\n", error_("ERROR:"), err)
				} else {
					defer f.Close()

					fmt.Fprintf(f, "# DNS Enumeration Results\n")
					fmt.Fprintf(f, "# Target: %s\n", cfg.Target)
					fmt.Fprintf(f, "# Date: %s\n", time.Now().Format(time.RFC3339))
					fmt.Fprintf(f, "# Total Findings: %d\n\n", len(dnsFindings))

					domainRecords := make(map[string]map[string][]string)
					securityIssues := make(map[string][]output.Finding)

					for _, finding := range dnsFindings {
						domain := finding.Target

						if finding.Type == "dns_record" {
							recordType, _ := finding.Data["record_type"].(string)
							value, _ := finding.Data["value"].(string)

							if _, ok := domainRecords[domain]; !ok {
								domainRecords[domain] = make(map[string][]string)
							}
							if _, ok := domainRecords[domain][recordType]; !ok {
								domainRecords[domain][recordType] = []string{}
							}

							exists := false
							for _, existingValue := range domainRecords[domain][recordType] {
								if existingValue == value {
									exists = true
									break
								}
							}
							if !exists {
								domainRecords[domain][recordType] = append(domainRecords[domain][recordType], value)
							}
						} else if finding.Type == "dns_security_issue" {
							if _, ok := securityIssues[domain]; !ok {
								securityIssues[domain] = []output.Finding{}
							}

							description := finding.Description
							exists := false
							for _, existingIssue := range securityIssues[domain] {
								if existingIssue.Description == description {
									exists = true
									break
								}
							}
							if !exists {
								securityIssues[domain] = append(securityIssues[domain], finding)
							}
						}
					}

					for domain, records := range domainRecords {
						fmt.Fprintf(f, "\n=== Domain: %s ===\n", domain)

						recordTypes := make([]string, 0, len(records))
						for recordType := range records {
							recordTypes = append(recordTypes, recordType)
						}
						sort.Strings(recordTypes)

						for _, recordType := range recordTypes {
							values := records[recordType]
							fmt.Fprintf(f, "\n%s Records:\n", recordType)
							fmt.Fprintf(f, "%s\n", strings.Repeat("-", 50))
							for _, value := range values {
								fmt.Fprintf(f, "%s\n", value)
							}
						}

						if issues, ok := securityIssues[domain]; ok && len(issues) > 0 {
							fmt.Fprintf(f, "\nSecurity Issues:\n")
							fmt.Fprintf(f, "%s\n", strings.Repeat("-", 50))

							for _, severity := range []string{"high", "medium", "low"} {
								hasSeverity := false
								for _, issue := range issues {
									if issue.Severity == severity {
										if !hasSeverity {
											fmt.Fprintf(f, "\n[%s]:\n", strings.ToUpper(severity))
											hasSeverity = true
										}
										fmt.Fprintf(f, "- %s\n", issue.Description)
									}
								}
							}
						}

						fmt.Fprintf(f, "\n%s\n", strings.Repeat("=", 50))
					}

					var recordCount, securityIssueCount int
					for _, records := range domainRecords {
						for _, values := range records {
							recordCount += len(values)
						}
					}
					for _, issues := range securityIssues {
						securityIssueCount += len(issues)
					}

					fmt.Printf("\n%s Total DNS records found: %d\n",
						success("SUMMARY:"),
						recordCount)

					if securityIssueCount > 0 {
						fmt.Printf("%s DNS security issues found: %d\n",
							warn("WARNING:"),
							securityIssueCount)
					}

					dnsFilePathAbs, _ := filepath.Abs(dnsOutputFile)
					fmt.Printf("%s DNS enumeration results saved to: %s\n",
						success("SUCCESS:"),
						dnsFilePathAbs)
				}
			} else {
				fmt.Printf("%s No DNS records found.\n", warn("WARNING:"))
			}
		}
	SkipDNSEnum:

		if cfg.HTTPProbeConfig.Enabled {

			skipHTTPProbing := false
			if len(subdomainFindings) == 0 && customTargetFile == "" && !enableSubdomain && cfg.Target != "" {

				if enableHTTPProbe && !enableSubdomain && !enableDirBrute && !enableJSAnalyzer && !allModules {
					fmt.Printf("%s Using HTTP probing on single target: %s\n", info("INFO:"), cfg.Target)
				}
			}

			if !skipHTTPProbing {

				if sagaMode && len(subdomainFindings) == 0 && customTargetFile == "" {
					fmt.Printf("\n%s No subdomains found, skipping HTTP probing\n", warn("WARNING:"))

					cfg.DirBruteConfig.Enabled = false
					cfg.JSAnalyzerConfig.Enabled = false
				} else {
					fmt.Printf("\n%s %s %s %s\n",
						primary("["),
						statusWarning("*"),
						primary("]"),
						accent("Starting HTTP Probing..."))

					var (
						err error
					)

					if customTargetFile != "" {
						targets, err = loadTargetsFromFile(customTargetFile)
						if err != nil {
							fmt.Printf("%s Failed to load targets from file: %v\n", error_("ERROR:"), err)
							os.Exit(1)
						}
						if len(targets) == 0 {
							fmt.Printf("%s No valid targets found in file\n", error_("ERROR:"))
							os.Exit(1)
						}
						fmt.Printf("%s Loaded %d targets from %s\n", info("INFO:"), len(targets), customTargetFile)
					} else {

						for _, finding := range subdomainFindings {
							if subdomain, ok := finding.Data["subdomain"].(string); ok {

								if allModules && (strings.HasPrefix(subdomain, "help") || strings.HasPrefix(subdomain, "-help")) {
									continue
								}
								targets = append(targets, subdomain)
							}
						}

						if len(targets) == 0 && cfg.Target != "" {

							targets = append(targets, cfg.Target)
							fmt.Printf("%s Using single target: %s for HTTP probing\n", info("INFO:"), cfg.Target)
						}
					}

					httpProber := httpprobe.NewProber(targets, cfg.HTTPProbeConfig, cfg.Timeout)

					progressTracker := httpprobe.NewProbeProgress(len(targets))

					fmt.Printf("\n%s Starting HTTP probing for %d targets...\n", info("INFO:"), len(targets))

					done := make(chan struct{})

					go func() {
						lastUpdate := time.Now()
						lastProcessed := 0
						spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
						spinnerIdx := 0

						ticker := time.NewTicker(100 * time.Millisecond)
						defer ticker.Stop()

						for {
							select {
							case <-ticker.C:

								if progressTracker.Current != lastProcessed || time.Since(lastUpdate) > 500*time.Millisecond {
									current, total, found, _, _ := progressTracker.GetStats()
									progress := float64(current) / float64(total) * 100
									elapsedTime := time.Since(progressTracker.StartTime).Round(time.Second)

									fmt.Print("\r\033[K")

									progressMsg := fmt.Sprintf("%s %s %d/%d (%.1f%%) | Live: %d | %s",
										info("HTTP:"),
										spinner[spinnerIdx],
										current,
										total,
										progress,
										found,
										formatDuration(elapsedTime))

									fmt.Print(progressMsg)

									lastProcessed = progressTracker.Current
									lastUpdate = time.Now()
									spinnerIdx = (spinnerIdx + 1) % len(spinner)
								}
							case <-done:

								_, total, found, _, _ := progressTracker.GetStats()
								elapsedTime := time.Since(progressTracker.StartTime).Round(time.Second)

								fmt.Print("\r\033[K")

								fmt.Printf("%s %s %d/%d (100%%) | Live: %d | %s\n",
									info("HTTP:"),
									spinner[spinnerIdx],
									total,
									total,
									found,
									formatDuration(elapsedTime))

								return
							}
						}
					}()

					findings, err := httpProber.Run(progressTracker)

					close(done)
					time.Sleep(100 * time.Millisecond)

					if err != nil {
						fmt.Printf("%s During HTTP probing: %v\n", error_("ERROR:"), err)
					} else {
						httpFindings = findings

						var waOutputFile string

						if outputFile != "" {
							// Use the exact file path provided by the user
							waOutputFile = outputFile
						} else {
							waOutputFile = generateUniqueFilename(filepath.Dir(cfg.OutputFile), cfg.Target, "WA")
						}

						f, err := os.Create(waOutputFile)
						if err != nil {
							fmt.Printf("%s Creating live domains results file: %v\n", error_("ERROR:"), err)
						} else {
							defer f.Close()

							uniqueURLs := make(map[string]output.Finding)
							for _, finding := range findings {
								if url, ok := finding.Data["url"].(string); ok {
									uniqueURLs[url] = finding
								}
							}

							liveSubdomains := make(map[string]bool)
							for _, finding := range uniqueURLs {
								url, _ := finding.Data["url"].(string)

								domain := url
								domain = strings.TrimPrefix(domain, "http://")
								domain = strings.TrimPrefix(domain, "https://")
								if idx := strings.Index(domain, "/"); idx != -1 {
									domain = domain[:idx]
								}
								liveSubdomains[domain] = true
							}

							domains := make([]string, 0, len(liveSubdomains))
							for domain := range liveSubdomains {
								domains = append(domains, domain)
							}
							sort.Strings(domains)

							for _, domain := range domains {
								fmt.Fprintf(f, "%s\n", domain)
							}

							fmt.Printf("\n%s Total unique live subdomains found: %d\n",
								success("SUMMARY:"),
								len(liveSubdomains))
							waFilePathAbs, _ := filepath.Abs(waOutputFile)
							fmt.Printf("%s Live subdomains list saved to: %s\n", success("SUCCESS:"), waFilePathAbs)
						}
					}
				}
			}
		}

		if enableDirBrute || allModules {

			for {

				targets = []string{}

				if len(httpFindings) > 0 {
					for _, finding := range httpFindings {
						if url, ok := finding.Data["url"].(string); ok {

							if allModules && (strings.HasPrefix(strings.ToLower(url), "help") ||
								strings.HasPrefix(strings.ToLower(url), "-help")) {
								continue
							}

							targets = append(targets, url)
						}
					}
				} else if customTargetFile != "" {
					var err error
					targets, err = loadTargetsFromFile(customTargetFile)
					if err != nil {
						fmt.Printf("%s Loading targets from file: %v\n", error_("ERROR:"), err)
						break
					}
					fmt.Printf("%s Loaded %d targets from %s for directory bruteforcing\n",
						info("INFO:"), len(targets), customTargetFile)
				} else if cfg.Target != "" {

					target := cfg.Target

					if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
						target = "https://" + target
					}
					targets = append(targets, target)
					fmt.Printf("\n%s Using target: %s for directory bruteforcing\n", info("INFO:"), target)
				}

				if len(targets) == 0 {
					fmt.Printf("%s No targets found for directory bruteforcing\n", warn("WARNING:"))
					break
				}

				if enableDirBrute && !allModules && !enableJSAnalyzer {

					selectedTargets = targets

					fmt.Printf("%s Starting directory brute forcing...\n", info("INFO:"))
				} else {

					categorizedTargets = categorizeDomains(targets)

					selectedTargets = handleTargetSelection(categorizedTargets)
					if selectedTargets == nil {

						fmt.Printf("\n%s %s %s %s\n",
							color.HiCyanString("["),
							color.HiYellowString("MAIN MENU"),
							color.HiCyanString("]"),
							color.HiMagentaString("Choose an option:"))

						fmt.Printf("\nOptions:\n")
						fmt.Printf("1. %s - Return to target selection\n", color.HiGreenString("Target Selection"))
						fmt.Printf("2. %s - Continue to JavaScript Analysis\n", color.HiYellowString("Next Module"))
						fmt.Printf("3. %s - Exit directory bruteforcing\n", color.HiRedString("Exit"))

						fmt.Printf("\nEnter your choice (1-3): ")
						reader := bufio.NewReader(os.Stdin)
						input, _ := reader.ReadString('\n')
						input = strings.TrimSpace(strings.ToLower(input))

						switch input {
						case "1":

							continue
						case "2":

							fmt.Println("Continuing to next module...")
						case "3", "exit", "quit":

							fmt.Printf("%s Exiting directory bruteforcing module.\n", info("INFO:"))
							return
						default:
							fmt.Printf("%s Invalid selection, returning to target selection.\n", warn("WARNING:"))
							continue
						}
						break
					}

					if len(selectedTargets) == 0 {
						fmt.Printf("%s No targets selected. Please select at least one target.\n", warn("WARNING:"))
						continue
					}

					if (!enableDirBrute && !enableJSAnalyzer) && (allModules || sagaMode) {
						scanType := chooseScanType(selectedTargets)
						if scanType == "" {

							continue
						} else if scanType == "js" {
							enableJSAnalyzer = true
							enableDirBrute = false

							break
						} else if scanType == "dir" {
							enableDirBrute = true
							enableJSAnalyzer = false
						} else if scanType == "both" {
							enableDirBrute = true
							enableJSAnalyzer = true
						}
					}
				}

				if !enableDirBrute {

					break
				}

				if len(selectedTargets) > 1 && !sagaMode && (enableDirBrute && !enableJSAnalyzer && !enableHTTPProbe && !enableSubdomain) {

					fmt.Printf("\n%s Directory bruteforcing works best with a single target.\n", warn("WARNING:"))
					fmt.Printf("%s Please select ONE target for directory bruteforcing:\n", info("INFO:"))

					perPage := 10
					totalTargets := len(selectedTargets)
					totalPages := (totalTargets + perPage - 1) / perPage
					currentPage := 1

					for {
						fmt.Printf("\n%s Page %d of %d (showing %d targets per page)\n\n",
							info("TARGETS:"),
							currentPage,
							totalPages,
							perPage)

						startIndex := (currentPage - 1) * perPage
						endIndex := startIndex + perPage
						if endIndex > totalTargets {
							endIndex = totalTargets
						}

						for i := startIndex; i < endIndex; i++ {
							fmt.Printf("  %d. %s\n", i+1, selectedTargets[i])
						}

						fmt.Printf("\n%s ", info("OPTIONS:"))
						if totalPages > 1 {
							if currentPage > 1 {
								fmt.Printf("p=previous page, ")
							}
							if currentPage < totalPages {
								fmt.Printf("n=next page, ")
							}
						}
						fmt.Printf("1-%d=select target, q=quit\n", totalTargets)

						fmt.Printf("\n%s Enter selection: ", info("SELECT:"))
						reader := bufio.NewReader(os.Stdin)
						input, _ := reader.ReadString('\n')
						input = strings.TrimSpace(strings.ToLower(input))

						if input == "n" && currentPage < totalPages {

							currentPage++
						} else if input == "p" && currentPage > 1 {

							currentPage--
						} else if input == "q" {

							fmt.Printf("%s Exiting directory bruteforcing.\n", info("INFO:"))
							return
						} else if selection, err := strconv.Atoi(input); err == nil {

							if selection >= 1 && selection <= totalTargets {

								target := selectedTargets[selection-1]
								selectedTargets = []string{target}
								fmt.Printf("%s Using target: %s for directory bruteforcing\n", info("INFO:"), target)
								break
							} else {
								fmt.Printf("%s Invalid selection. Please select a number between 1 and %d.\n",
									warn("WARNING:"),
									totalTargets)
							}
						} else {
							fmt.Printf("%s Invalid input. Please try again.\n", warn("WARNING:"))
						}
					}
				}

				for _, target := range selectedTargets {
					dirBruter := dirbrute.NewScanner(target, cfg.DirBruteConfig, cfg.Timeout)
					findings, err := dirBruter.Run()
					if err != nil {
						fmt.Printf("%s During directory brute-forcing of %s: %v\n", error_("ERROR:"), target, err)
						continue
					}
					dirFindings = append(dirFindings, findings...)
				}

				if len(dirFindings) > 0 {
					var dbfOutputFile string

					if outputFile != "" {
						// Use the exact file path provided by the user
						dbfOutputFile = outputFile
					} else {
						dbfOutputFile = generateUniqueFilename(resultsDir, cfg.Target, "DBF")
					}

					f, err := os.Create(dbfOutputFile)
					if err != nil {
						fmt.Printf("%s Creating directory brute-forcing results file: %v\n", error_("ERROR:"), err)
					} else {
						defer f.Close()
						for _, finding := range dirFindings {
							if url, ok := finding.Data["url"].(string); ok {
								fmt.Fprintf(f, "%s\n", url)
							}
						}
						fmt.Printf("%s Found %d directories/files across %d targets\n",
							success("SUCCESS:"),
							len(dirFindings),
							len(selectedTargets))
						dbfFilePathAbs, _ := filepath.Abs(dbfOutputFile)
						fmt.Printf("%s Directory brute-forcing results saved to: %s\n",
							success("SUCCESS:"),
							dbfFilePathAbs)
					}
				}

				if enableDirBrute && !allModules && !enableJSAnalyzer {

					break
				} else {

					fmt.Println()

					fmt.Printf("%s %s %s %s",
						color.HiCyanString("["),
						color.HiMagentaString("?"),
						color.HiCyanString("]"),
						color.HiYellowString(" Do you want to perform another directory bruteforcing scan? (y/n): "))

					reader := bufio.NewReader(os.Stdin)
					input, _ := reader.ReadString('\n')
					input = strings.TrimSpace(strings.ToLower(input))

					if input != "y" && input != "yes" {

						break
					}
				}
			}
		}

		if cfg.JSAnalyzerConfig.Enabled || enableJSAnalyzer {

			if sagaMode && len(httpFindings) == 0 {
				fmt.Printf("\n%s No live domains found, skipping JavaScript analysis\n", warn("WARNING:"))
			} else {

				fmt.Printf("\n%s %s %s %s\n",
					primary("["),
					statusWarning("*"),
					primary("]"),
					accent("Starting JavaScript Analysis..."))

				fmt.Printf("%s Analyzing JavaScript files for endpoints, API keys, and sensitive patterns\n", primary("SCAN:"))

				moduleStart := time.Now()

				targetsForJSAnalysis := []string{}

				if len(selectedTargets) > 0 && enableJSAnalyzer {

					targetsForJSAnalysis = selectedTargets
					fmt.Printf("%s Using %d user-selected targets for JavaScript analysis\n", info("INFO:"), len(targetsForJSAnalysis))
				} else {

					if enableJSAnalyzer && customTargetFile != "" {

						if len(targets) > 0 {

							targetsForJSAnalysis = []string{}

							for _, target := range targets {

								if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
									target = "http://" + target
								}
								targetsForJSAnalysis = append(targetsForJSAnalysis, target)
							}

							if len(targetsForJSAnalysis) > 0 {
								cfg.Target = targetsForJSAnalysis[0]
							}
						}

						fmt.Printf("%s Using %d targets from %s for JavaScript analysis\n",
							info("INFO:"), len(targetsForJSAnalysis), customTargetFile)
					}

					if cfg.Target != "" {

						if !strings.HasPrefix(cfg.Target, "http://") && !strings.HasPrefix(cfg.Target, "https://") {
							cfg.Target = "http://" + cfg.Target
						}
						targetsForJSAnalysis = append(targetsForJSAnalysis, cfg.Target)
					}

					if sagaMode && len(httpFindings) > 0 {
						targetsForJSAnalysis = []string{}
						for _, finding := range httpFindings {
							if url, ok := finding.Data["url"].(string); ok {

								if allModules && (strings.HasPrefix(strings.ToLower(url), "help") ||
									strings.HasPrefix(strings.ToLower(url), "-help")) {
									continue
								}

								if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
									url = "http://" + url
								}
								targetsForJSAnalysis = append(targetsForJSAnalysis, url)
							}
						}
						if !silent {
							debugPrint("Using %d live domains for JavaScript analysis", len(targetsForJSAnalysis))
						}
					}

					if len(cfg.JSAnalyzerConfig.IncludeURLs) > 0 {
						for i, url := range cfg.JSAnalyzerConfig.IncludeURLs {

							if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
								cfg.JSAnalyzerConfig.IncludeURLs[i] = "http://" + url
							}
						}
						targetsForJSAnalysis = cfg.JSAnalyzerConfig.IncludeURLs
					}
				}

				if len(targetsForJSAnalysis) > 10 && !silent && !sagaMode {
					fmt.Printf("\n%s %s %s %s\n",
						color.HiCyanString("["),
						color.HiYellowString("TARGET SELECTION"),
						color.HiCyanString("]"),
						color.HiMagentaString("JavaScript Analysis"))

					fmt.Printf("%s Found %d potential targets for JavaScript analysis\n",
						info("INFO:"),
						len(targetsForJSAnalysis))
					fmt.Printf("%s Would you like to select specific targets or analyze all? (y=select/n=all): ",
						color.HiCyanString("QUESTION:"))

					reader := bufio.NewReader(os.Stdin)
					input, _ := reader.ReadString('\n')
					input = strings.TrimSpace(strings.ToLower(input))

					if input == "y" || input == "yes" {

						categorizedJSTargets := make(map[string][]string)
						categorizedJSTargets["high"] = []string{}
						categorizedJSTargets["medium"] = []string{}
						categorizedJSTargets["low"] = []string{}

						for _, target := range targetsForJSAnalysis {
							switch {
							case stringContainsAny(target, []string{"admin", "portal", "login", "auth", "manage", "dashboard", "account"}):
								categorizedJSTargets["high"] = append(categorizedJSTargets["high"], target)
							case stringContainsAny(target, []string{"api", "dev", "test", "stage", "beta", "uat", "sandbox", "internal"}):
								categorizedJSTargets["medium"] = append(categorizedJSTargets["medium"], target)
							default:
								categorizedJSTargets["low"] = append(categorizedJSTargets["low"], target)
							}
						}

						selectedJSTargets := handleTargetSelection(categorizedJSTargets)
						if len(selectedJSTargets) > 0 {
							targetsForJSAnalysis = selectedJSTargets
							fmt.Printf("%s Selected %d targets for JavaScript analysis\n",
								success("SUCCESS:"),
								len(targetsForJSAnalysis))
						} else {
							fmt.Printf("%s No targets selected, using all targets\n",
								warn("WARNING:"))
						}
					}
				}

				if len(targetsForJSAnalysis) > 0 {
					fmt.Printf("%s Target", color.HiBlueString("TARGET:"))
					if len(targetsForJSAnalysis) > 1 {
						fmt.Printf("s")
					}
					fmt.Printf(" (%d): ", len(targetsForJSAnalysis))

					displayLimit := min(3, len(targetsForJSAnalysis))
					for i := 0; i < displayLimit; i++ {
						if i > 0 {
							fmt.Print(", ")
						}
						fmt.Print(truncateString(targetsForJSAnalysis[i], 30))
					}
					if len(targetsForJSAnalysis) > displayLimit {
						fmt.Printf(", ... and %d more", len(targetsForJSAnalysis)-displayLimit)
					}
					fmt.Println()
					fmt.Println()
				}

				if len(targetsForJSAnalysis) > 0 {

					cfg.JSAnalyzerConfig.IncludeURLs = targetsForJSAnalysis

					fmt.Printf("%s Analyzing JavaScript for %d targets\n", color.HiBlueString("INFO:"), len(targetsForJSAnalysis))
				} else {
					fmt.Printf("%s No targets found for JavaScript analysis. Skipping module.\n", warn("WARNING:"))
					goto jsanalyzerComplete
				}

				cfg.JSAnalyzerConfig.Silent = silent || suppressJSErrors
				cfg.JSAnalyzerConfig.ShowErrorsInSaga = !suppressJSErrors

				jsAnalyzer, err := jsanalyzer.NewAnalyzer(cfg.Target, cfg.JSAnalyzerConfig, cfg.Timeout, silent, allModules)
				if err != nil {
					fmt.Printf("%s Failed to initialize JavaScript analyzer: %v\n", error_("ERROR:"), err)
					goto jsanalyzerComplete
				}

				findings, err := jsAnalyzer.Run()
				if err != nil {
					fmt.Printf("%s During JavaScript analysis: %v\n", error_("ERROR:"), err)
				} else {
					jsFindings = findings

					scanDuration := time.Since(moduleStart)
					fmt.Printf("%s Found %d JavaScript endpoints/secrets in %s\n",
						success("SUCCESS:"),
						len(findings),
						formatDuration(scanDuration))

					if len(findings) > 0 {

						var jsOutputFile string

						if outputFile != "" {
							// Use the exact file path provided by the user
							jsOutputFile = outputFile
						} else {
							jsOutputFile = generateUniqueFilename(resultsDir, cfg.Target, "JS")
						}

						f, err := os.Create(jsOutputFile)
						if err != nil {
							fmt.Printf("%s Creating JavaScript analysis results file: %v\n", error_("ERROR:"), err)
						} else {
							defer f.Close()

							var highFindings, mediumFindings, lowFindings []output.Finding
							for _, finding := range findings {
								switch finding.Severity {
								case "high":
									highFindings = append(highFindings, finding)
								case "medium":
									mediumFindings = append(mediumFindings, finding)
								default:
									lowFindings = append(lowFindings, finding)
								}
							}

							categoryCounts := make(map[string]int)
							fileFindings := make(map[string]int)

							for _, finding := range findings {
								category := "general"
								if val, ok := finding.Data["category"].(string); ok && val != "" {
									category = val
								}
								categoryCounts[category]++

								source := "unknown"
								if val, ok := finding.Data["source"].(string); ok && val != "" {
									source = val
								}
								fileFindings[source]++
							}

							type categoryCount struct {
								Name  string
								Count int
							}

							var sortedCategories []categoryCount
							for cat, count := range categoryCounts {
								sortedCategories = append(sortedCategories, categoryCount{
									Name:  cat,
									Count: count,
								})
							}

							sort.Slice(sortedCategories, func(i, j int) bool {
								return sortedCategories[i].Count > sortedCategories[j].Count
							})

							type fileCount struct {
								Name  string
								Count int
							}

							var sortedFiles []fileCount
							for file, count := range fileFindings {
								sortedFiles = append(sortedFiles, fileCount{
									Name:  file,
									Count: count,
								})
							}

							sort.Slice(sortedFiles, func(i, j int) bool {
								return sortedFiles[i].Count > sortedFiles[j].Count
							})

							fmt.Fprintf(f, "#########################################################\n")
							fmt.Fprintf(f, "#           JAVASCRIPT ANALYSIS RESULTS                 #\n")
							fmt.Fprintf(f, "#########################################################\n\n")

							fmt.Fprintf(f, "Target: %s\n", cfg.Target)
							fmt.Fprintf(f, "Scan Date: %s\n", time.Now().Format("2006-01-02 15:04:05"))
							fmt.Fprintf(f, "Total Findings: %d\n\n", len(findings))

							fmt.Fprintf(f, "---------------------- SUMMARY --------------------------\n\n")

							fmt.Fprintf(f, "Severity Breakdown:\n")

							highPct := 0
							mediumPct := 0
							lowPct := 0

							if len(findings) > 0 {
								highPct = len(highFindings) * 100 / len(findings)
								mediumPct = len(mediumFindings) * 100 / len(findings)
								lowPct = len(lowFindings) * 100 / len(findings)
							}

							fmt.Fprintf(f, "- HIGH: %d findings (%d%%)\n", len(highFindings), highPct)
							fmt.Fprintf(f, "- MEDIUM: %d findings (%d%%)\n", len(mediumFindings), mediumPct)
							fmt.Fprintf(f, "- LOW: %d findings (%d%%)\n\n", len(lowFindings), lowPct)

							fmt.Fprintf(f, "Top Categories:\n")

							categoryLimit := min(5, len(sortedCategories))
							for i := 0; i < categoryLimit; i++ {
								cat := sortedCategories[i]
								fmt.Fprintf(f, "- %s: %d\n", strings.Title(cat.Name), cat.Count)
							}
							fmt.Fprintf(f, "\n")

							fmt.Fprintf(f, "Most Vulnerable Files:\n")

							fileLimit := min(3, len(sortedFiles))
							for i := 0; i < fileLimit; i++ {
								file := sortedFiles[i]
								fmt.Fprintf(f, "%d. %s (%d findings)\n", i+1, file.Name, file.Count)
							}
							fmt.Fprintf(f, "\n")

							fmt.Fprintf(f, "---------------------- CONTENTS ------------------------\n\n")

							if len(highFindings) > 0 {
								fmt.Fprintf(f, "HIGH SEVERITY FINDINGS (%d)\n", len(highFindings))
							}

							if len(mediumFindings) > 0 {
								fmt.Fprintf(f, "MEDIUM SEVERITY FINDINGS (%d)\n", len(mediumFindings))
							}

							if len(lowFindings) > 0 {
								fmt.Fprintf(f, "LOW SEVERITY FINDINGS (%d)\n", len(lowFindings))
							}

							fmt.Fprintf(f, "\n")

							findingIndex := 1

							writeFinding := func(finding output.Finding, severityTag string, writer io.Writer) {

								url := finding.Target
								findingType := finding.Type
								value := ""
								source := ""
								context := ""
								category := ""

								if val, ok := finding.Data["value"].(string); ok {
									value = val
								}
								if val, ok := finding.Data["source"].(string); ok {
									source = val
								}
								if val, ok := finding.Data["context"].(string); ok {
									context = val
								}
								if val, ok := finding.Data["category"].(string); ok {
									category = val
								}

								if url == "" {
									url = "N/A"
								}
								if findingType == "" {
									findingType = "unknown"
								}
								if value == "" {
									value = "N/A"
								}
								if source == "" {
									source = "N/A"
								}
								if category == "" {
									category = "general"
								}

								fmt.Fprintf(writer, "=== FINDING #%d (%s SEVERITY) ===\n", findingIndex, strings.TrimSpace(strings.Trim(severityTag, "[]")))
								fmt.Fprintf(writer, "URL: %s\n", url)
								fmt.Fprintf(writer, "Type: %s\n", strings.Title(findingType))
								fmt.Fprintf(writer, "Category: %s\n", strings.Title(category))
								fmt.Fprintf(writer, "Value: %s\n", value)
								fmt.Fprintf(writer, "Source File: %s\n", source)

								if context != "" && context != "N/A" {
									fmt.Fprintf(writer, "\nContext:\n```javascript\n%s\n```\n", context)
								}

								fmt.Fprintf(writer, "\n%s\n\n", strings.Repeat("-", 60))
								findingIndex++
							}

							if len(highFindings) > 0 {
								fmt.Fprintf(f, "############### HIGH SEVERITY FINDINGS ###############\n\n")
								for _, finding := range highFindings {
									writeFinding(finding, "HIGH", f)
								}
							}

							if len(mediumFindings) > 0 {
								fmt.Fprintf(f, "############## MEDIUM SEVERITY FINDINGS ##############\n\n")
								for _, finding := range mediumFindings {
									writeFinding(finding, "MEDIUM", f)
								}
							}

							if len(lowFindings) > 0 {
								fmt.Fprintf(f, "############### LOW SEVERITY FINDINGS ################\n\n")
								for _, finding := range lowFindings {
									writeFinding(finding, "LOW", f)
								}
							}

							if err := f.Sync(); err != nil {
								fmt.Printf("%s Error flushing JavaScript results file: %v\n", error_("ERROR:"), err)
							}

							jsFilePathAbs, _ := filepath.Abs(jsOutputFile)
							fmt.Printf("%s JavaScript analysis results saved to: %s\n",
								success("SUCCESS:"),
								jsFilePathAbs)
						}
					} else {
						fmt.Printf("%s No sensitive information or endpoints found in JavaScript files\n",
							info("INFO:"))
					}
				}
			}
		}

	jsanalyzerComplete:

		if outputJSON {
			jsonFileName := generateUniqueFilename(filepath.Dir(cfg.OutputFile), cfg.Target, "JSON")

			jsonFileName = strings.TrimSuffix(jsonFileName, ".txt") + ".json"

			if err := output.SaveFindingsJSON(httpFindings, jsonFileName); err != nil {
				fmt.Printf("%s Saving JSON findings: %v\n", error_("ERROR:"), err)
				os.Exit(1)
			}
			if !silent {
				jsonFilePathAbs, _ := filepath.Abs(jsonFileName)
				fmt.Printf("%s Results saved to: %s\n", success("SUCCESS:"), jsonFilePathAbs)
			}
		}

		scanDuration := time.Since(startTime)

		if !silent {
			fmt.Printf("\n%s %s %s %s\n",
				primary("["),
				statusSuccess("✓"),
				primary("]"),
				accent("Scan Complete!"))
			fmt.Printf("FINAL SUMMARY:\n")
			if cfg.SubdomainConfig.Enabled {
				fmt.Printf("  %s: %d\n",
					primary("Subdomains found"),
					len(subdomainFindings))
			}
			if enableDNSEnum || allModules {
				fmt.Printf("  %s: %d\n",
					primary("DNS records found"),
					len(dnsFindings))
			}
			if cfg.HTTPProbeConfig.Enabled {
				fmt.Printf("  %s: %d\n",
					primary("Live domains"),
					len(httpFindings))
			}
			if cfg.DirBruteConfig.Enabled {
				fmt.Printf("  %s: %d\n",
					primary("Directories/files found"),
					len(dirFindings))
			}
			if cfg.JSAnalyzerConfig.Enabled {
				fmt.Printf("  %s: %d\n",
					primary("JavaScript findings"),
					len(jsFindings))
			}

			fmt.Printf("\n%s Scan duration: %s\n",
				primary("INFO:"),
				formatDuration(scanDuration))
		}

		if enableExposureDetection {
			startTime = time.Now()
			fmt.Printf("\n%s %s %s %s\n",
				primary("["),
				statusWarning("*"),
				primary("]"),
				accent("Starting Exposure Detection..."))

			fmt.Printf("%s Target: %s\n", info("INFO:"), targetDomain)

			detector := exposure.NewDetector()
			err := detector.Detect(targetDomain)
			if err != nil {
				fmt.Printf("%s Exposure detection error: %v\n", error_("ERROR:"), err)
			}

			// Process findings
			if len(detector.Findings) > 0 {
				// Generate output filename
				var expOutputFile string
				if outputFile != "" {
					// Use the exact file path provided by the user
					expOutputFile = outputFile
				} else {
					expOutputFile = generateUniqueFilename(resultsDir, cfg.Target, "EXP")
				}

				// Save findings to file
				f, err := os.Create(expOutputFile)
				if err != nil {
					fmt.Printf("%s Creating exposure results file: %v\n", error_("ERROR:"), err)
				} else {
					defer f.Close()

					// Write header
					fmt.Fprintf(f, "EXPOSURE DETECTION RESULTS\n\n")
					fmt.Fprintf(f, "Target: %s\n", cfg.Target)
					fmt.Fprintf(f, "Scan Date: %s\n", time.Now().Format("2006-01-02 15:04:05"))
					fmt.Fprintf(f, "Total Findings: %d\n\n", len(detector.Findings))

					// Group findings by severity
					highSev := make([]exposure.Finding, 0)
					medSev := make([]exposure.Finding, 0)

					for _, finding := range detector.Findings {
						if finding.Severity == "HIGH" {
							highSev = append(highSev, finding)
						} else {
							medSev = append(medSev, finding)
						}
					}

					// Write summary
					fmt.Fprintf(f, "SUMMARY\n")
					fmt.Fprintf(f, "• HIGH Severity:   %d findings\n", len(highSev))
					fmt.Fprintf(f, "• MEDIUM Severity: %d findings\n\n", len(medSev))

					// Write findings by severity
					if len(highSev) > 0 {
						fmt.Fprintf(f, "HIGH SEVERITY FINDINGS\n\n")
						for i, finding := range highSev {
							fmt.Fprintf(f, "[%d] %s\n", i+1, finding.Type)
							fmt.Fprintf(f, "URL: %s\n", finding.URL)
							if finding.StatusCode > 0 {
								fmt.Fprintf(f, "Status: %d\n", finding.StatusCode)
							}
							if finding.ContentType != "" {
								fmt.Fprintf(f, "Content-Type: %s\n", finding.ContentType)
							}
							if finding.Value != "" {
								fmt.Fprintf(f, "Value: %s\n", finding.Value)
							}
							if finding.LineNumber > 0 {
								fmt.Fprintf(f, "Line: %d\n", finding.LineNumber)
							}
							if finding.POC != "" {
								fmt.Fprintf(f, "POC: %s\n", finding.POC)
							}
							if finding.Confidence != "" {
								fmt.Fprintf(f, "Confidence: %s\n", finding.Confidence)
							}
							if len(finding.Evidence) > 0 {
								fmt.Fprintf(f, "Evidence:\n")
								for _, ev := range finding.Evidence {
									fmt.Fprintf(f, "  %s\n", ev)
								}
							}
							fmt.Fprintf(f, "\n")
						}
					}

					if len(medSev) > 0 {
						fmt.Fprintf(f, "MEDIUM SEVERITY FINDINGS\n\n")
						for i, finding := range medSev {
							fmt.Fprintf(f, "[%d] %s\n", i+1, finding.Type)
							fmt.Fprintf(f, "URL: %s\n", finding.URL)
							if finding.StatusCode > 0 {
								fmt.Fprintf(f, "Status: %d\n", finding.StatusCode)
							}
							if finding.ContentType != "" {
								fmt.Fprintf(f, "Content-Type: %s\n", finding.ContentType)
							}
							if finding.Value != "" {
								fmt.Fprintf(f, "Value: %s\n", finding.Value)
							}
							if finding.LineNumber > 0 {
								fmt.Fprintf(f, "Line: %d\n", finding.LineNumber)
							}
							if finding.POC != "" {
								fmt.Fprintf(f, "POC: %s\n", finding.POC)
							}
							if finding.Confidence != "" {
								fmt.Fprintf(f, "Confidence: %s\n", finding.Confidence)
							}
							if len(finding.Evidence) > 0 {
								fmt.Fprintf(f, "Evidence:\n")
								for _, ev := range finding.Evidence {
									fmt.Fprintf(f, "  %s\n", ev)
								}
							}
							fmt.Fprintf(f, "\n")
						}
					}

					fmt.Printf("%s Found %d potential exposures:\n", success("SUCCESS:"), len(detector.Findings))
					fmt.Printf("    • HIGH Severity: %d\n", len(highSev))
					fmt.Printf("    • MEDIUM Severity: %d\n", len(medSev))
					fmt.Printf("\n%s Exposure results saved to: %s\n", success("SUCCESS:"), expOutputFile)
				}
			} else {
				fmt.Printf("%s No potential exposures found\n", info("INFO:"))
			}

			scanDuration := time.Since(startTime)
			fmt.Printf("\n%s Scan duration: %s\n", info("INFO:"), formatDuration(scanDuration))
			os.Exit(0)
		}
	}
}

func getEnabledModules(cfg config.Config) string {
	var modules []string
	if cfg.SubdomainConfig.Enabled {
		modules = append(modules, "Subdomain")
	}
	if cfg.HTTPProbeConfig.Enabled {
		modules = append(modules, "HTTPProbe")
	}
	if cfg.DirBruteConfig.Enabled {
		modules = append(modules, "DirBrute")
	}
	if cfg.JSAnalyzerConfig.Enabled {
		modules = append(modules, "JSAnalyzer")
	}
	return fmt.Sprintf("%v", modules)
}

func printHelp() {

	printBanner()

	sourceInfo := subdomain.GetSourcesInfo()

	freeSources := []string{}
	premiumSources := []string{}

	totalFreeSources := 0
	totalPremiumSources := 0

	for source, info := range sourceInfo {
		if info.RequiresKey {
			premiumSources = append(premiumSources, source)
			totalPremiumSources++
		} else {
			freeSources = append(freeSources, source)
			totalFreeSources++
		}
	}

	sort.Strings(freeSources)
	sort.Strings(premiumSources)

	fmt.Println(color.HiMagentaString("BBRECON - BUG BOUNTY RECONNAISSANCE TOOL"))
	fmt.Println()

	fmt.Println(color.HiWhiteString("USAGE"))
	fmt.Println(color.HiWhiteString(strings.Repeat("_", 50)))
	fmt.Println()
	fmt.Printf("  bbrecon -t example.com [OPTIONS]                 # Single domain\n")
	fmt.Printf("  bbrecon -t domain1.com,domain2.com [OPTIONS]     # Multiple domains (comma-separated, NO spaces)\n")
	fmt.Printf("  bbrecon -C targets.txt [OPTIONS]                 # Load domains from file\n")
	fmt.Printf("  bbrecon -t example.com -A                        # Run all modules on a domain\n")
	fmt.Println()

	fmt.Println(color.HiWhiteString("DESCRIPTION"))
	fmt.Println(color.HiWhiteString(strings.Repeat("_", 50)))
	fmt.Println()
	fmt.Println("  A comprehensive reconnaissance tool for bug bounty hunting and penetration testing.")
	fmt.Println("  Combines multiple modules:")
	fmt.Println()
	fmt.Println("  • Subdomain enumeration    • HTTP probing         • Directory bruteforcing")
	fmt.Println("  • DNS analysis             • JS analysis          • API endpoint discovery")
	fmt.Println()

	fmt.Println(color.HiWhiteString("ESSENTIAL FLAGS"))
	fmt.Println(color.HiWhiteString(strings.Repeat("_", 50)))
	fmt.Println()
	fmt.Printf("  -t %s\n", color.HiGreenString("string"))
	fmt.Printf("    Target domain to scan (e.g., example.com)\n")
	fmt.Printf("    %s For multiple domains: use commas WITHOUT spaces (domain1.com,domain2.com)\n", color.HiYellowString("FORMAT:"))
	fmt.Printf("    %s Avoid trailing commas and spaces (incorrect: \"domain.com, \")\n", color.HiYellowString("WARNING:"))
	fmt.Println()
	fmt.Printf("  -C %s\n", color.HiGreenString("string"))
	fmt.Printf("    Custom targets file (domains or URLs, one per line)\n")
	fmt.Printf("    %s Each domain should be in valid format without http:// for subdomain enumeration\n", color.HiYellowString("FORMAT:"))
	fmt.Printf("    %s MUST be used with -S and/or -H flags only\n", color.HiRedString("RESTRICTION:"))
	fmt.Printf("    %s Example usage: ./bbrecon -C targets.txt -S -H\n", color.HiCyanString("USAGE:"))
	fmt.Println()
	fmt.Printf("  -A\n")
	fmt.Printf("    Enable all modules in the correct sequence\n")
	fmt.Printf("    %s Runs subdomain enum → DNS → HTTP probe → directory brute → JS analysis\n", color.HiYellowString("SEQUENCE:"))
	fmt.Printf("    %s Cannot be used with -C flag (custom target file)\n", color.HiRedString("RESTRICTION:"))
	fmt.Println()
	fmt.Printf("  -h\n")
	fmt.Printf("    Display this help message\n")
	fmt.Println()

	fmt.Println(color.HiWhiteString("MODULE FLAGS"))
	fmt.Println(color.HiWhiteString(strings.Repeat("_", 50)))
	fmt.Println()
	fmt.Printf("  -S\n")
	fmt.Printf("    Enable subdomain enumeration\n")
	fmt.Printf("    %s Only works with a SINGLE domain when used directly\n", color.HiRedString("RESTRICTION:"))
	fmt.Printf("    %s Multiple domains can be used with -C (file) or in SAGA mode (-A)\n", color.HiCyanString("TIP:"))
	fmt.Printf("    %s Cannot be used with -H flag (use -A instead for combined functionality)\n", color.HiRedString("RESTRICTION:"))
	fmt.Println()
	fmt.Printf("  -H\n")
	fmt.Printf("    Enable HTTP probing\n")
	fmt.Printf("    %s Works with single domains, multiple domains, or domains from file\n", color.HiCyanString("USAGE:"))
	fmt.Printf("    %s Verifies which domains are accessible via HTTP/HTTPS\n", color.HiCyanString("FUNCTION:"))
	fmt.Printf("    %s Cannot be used with -S flag (use -A instead for combined functionality)\n", color.HiRedString("RESTRICTION:"))
	fmt.Println()
	fmt.Printf("  -D\n")
	fmt.Printf("    Enable directory bruteforcing\n")
	fmt.Printf("    %s Only works with a SINGLE domain when used directly\n", color.HiRedString("RESTRICTION:"))
	fmt.Printf("    %s Multiple domains can be used with -C (file) or in SAGA mode (-A)\n", color.HiCyanString("TIP:"))
	fmt.Printf("    %s Requires -w flag to specify wordlist\n", color.HiCyanString("NOTE:"))
	fmt.Println()
	fmt.Printf("  -J\n")
	fmt.Printf("    Enable JavaScript analyzer\n")
	fmt.Printf("    %s Works with single domains, multiple domains, or domains from file\n", color.HiCyanString("USAGE:"))
	fmt.Printf("    %s Finds sensitive information, endpoints, and secrets in JS files\n", color.HiCyanString("FUNCTION:"))
	fmt.Println()
	fmt.Printf("  -N\n")
	fmt.Printf("    Enable DNS enumeration\n")
	fmt.Printf("    %s Only works with a SINGLE domain\n", color.HiRedString("RESTRICTION:"))
	fmt.Printf("    %s Cannot be used with multiple domains or in SAGA mode (-A)\n", color.HiCyanString("NOTE:"))
	fmt.Printf("    %s Identifies security misconfigurations in DNS records\n", color.HiCyanString("FUNCTION:"))
	fmt.Printf("    %s Provides intelligent domain sampling for large targets (>100 subdomains)\n", color.HiCyanString("FEATURE:"))
	fmt.Println()

	fmt.Println(color.HiWhiteString("FLAG RESTRICTIONS"))
	fmt.Println(color.HiWhiteString(strings.Repeat("_", 50)))
	fmt.Println()
	fmt.Printf("  • -S and -H cannot be used together\n")
	fmt.Printf("    %s Use -A for combined functionality, or run separately\n", color.HiCyanString("SOLUTION:"))
	fmt.Printf("  • -C can only be used with -S and/or -H\n")
	fmt.Printf("    %s Cannot be used with -D, -J, -N, or -A\n", color.HiCyanString("LIMITATION:"))
	fmt.Printf("  • -A cannot be used with any other module flags\n")
	fmt.Printf("    %s Run as standalone: ./bbrecon -t example.com -A\n", color.HiCyanString("USAGE:"))
	fmt.Println()

	fmt.Println(color.HiWhiteString("SUBDOMAIN ENUMERATION"))
	fmt.Println(color.HiWhiteString(strings.Repeat("_", 50)))
	fmt.Println()
	fmt.Printf("  -s %s\n", color.HiGreenString("string"))
	fmt.Printf("    Comma-separated list of sources to use\n")
	fmt.Printf("    %s Example: -s crtsh,securitytrails,shodan\n", color.HiCyanString("USAGE:"))
	fmt.Printf("    %s Will auto-enable subdomain enumeration even without -S flag\n", color.HiCyanString("NOTE:"))
	fmt.Printf("    %s Invalid source names will be ignored with a warning\n", color.HiCyanString("NOTE:"))
	fmt.Println()
	fmt.Printf("  -es %s\n", color.HiGreenString("string"))
	fmt.Printf("    Comma-separated list of sources to exclude\n")
	fmt.Printf("    %s Example: -es wayback,urlscan\n", color.HiCyanString("USAGE:"))
	fmt.Println()
	fmt.Printf("  -all\n")
	fmt.Printf("    Use all available sources (including premium ones)\n")
	fmt.Printf("    %s Currently supports %d free sources and %d premium sources\n",
		color.HiCyanString("INFO:"), totalFreeSources, totalPremiumSources)
	fmt.Println()
	fmt.Printf("  -stats\n")
	fmt.Printf("    Show statistics about found subdomains\n")
	fmt.Printf("    %s Displays number of subdomains found by each source\n", color.HiCyanString("FUNCTION:"))
	fmt.Printf("    %s Shows percentage contribution of each source\n", color.HiCyanString("FUNCTION:"))
	fmt.Printf("    %s Includes statistics in output file as metadata\n", color.HiCyanString("FEATURE:"))
	fmt.Println()
	fmt.Printf("  -r\n")
	fmt.Printf("    Enable recursive subdomain enumeration\n")
	fmt.Printf("    %s Uses found subdomains as input for further discovery\n", color.HiCyanString("FUNCTION:"))
	fmt.Println()

	fmt.Println(color.HiYellowString("AVAILABLE SOURCES:"))
	fmt.Println()
	fmt.Println(color.HiYellowString("FREE SOURCES (No API key required):"))
	helpFreeSources := []string{
		"crtsh", "hackertarget", "alienvault", "urlscan", "threatminer",
		"riddler", "wayback", "rapiddns", "commoncrawl", "certspotter",
		"anubis", "threatcrowd", "sitedossier", "hudsonrock", "digitorus",
	}
	printSourcesGrid(helpFreeSources, 3)

	fmt.Printf("\n%s\n", color.HiYellowString("Premium Sources (API key required):"))
	helpPremiumSources := []string{
		"bufferover", "leakix", "netlas", "securitytrails", "shodan",
		"censys", "virustotal", "facebookct", "dnsdumpster", "chaos",
		"spyse", "fullhunt", "binaryedge", "threatbook", "intelx",
		"c99", "bevigil", "chinaz", "digitalyama", "dnsdb",
		"dnsrepo", "fofa", "github", "hunter", "quake",
		"redhuntlabs", "robtex", "whoisxmlapi", "zoomeye", "facebook",
		"builtwith",
	}
	printSourcesGrid(helpPremiumSources, 5)

	fmt.Printf("\n%s\n", color.HiWhiteString("Usage:"))
	fmt.Printf("  • To use specific sources: %s\n", color.HiGreenString("./bbrecon -t example.com -s crtsh,hackertarget,alienvault"))
	fmt.Printf("  • To auto-enable with specific sources: %s\n", color.HiGreenString("./bbrecon -t example.com -s crtsh"))
	fmt.Printf("  • To exclude sources: %s\n", color.HiGreenString("./bbrecon -t example.com -es securitytrails,shodan"))
	fmt.Printf("  • To use all sources: %s\n", color.HiGreenString("./bbrecon -t example.com -all"))
	fmt.Printf("  • To show source statistics: %s\n", color.HiGreenString("./bbrecon -t example.com -stats"))
}

func printSourcesGrid(sources []string, columns int) {
	for i, source := range sources {
		if i%columns == 0 {
			fmt.Print("  ")
		}
		fmt.Printf("%-15s", source)
		if (i+1)%columns == 0 {
			fmt.Println()
		}
	}

	if len(sources)%columns != 0 {
		fmt.Println()
	}
}

func categorizeDomains(urls []string) map[string][]string {
	targets := make(map[string][]string)
	targets["high"] = []string{}
	targets["medium"] = []string{}
	targets["low"] = []string{}

	for _, url := range urls {
		switch {
		case stringContainsAny(url, []string{"admin", "portal", "login", "auth", "manage", "dashboard", "account"}):
			targets["high"] = append(targets["high"], url)
		case stringContainsAny(url, []string{"api", "dev", "test", "stage", "beta", "uat", "sandbox", "internal"}):
			targets["medium"] = append(targets["medium"], url)
		default:
			targets["low"] = append(targets["low"], url)
		}
	}
	return targets
}

func generateUniqueFilename(baseDir, target, moduleCode string) string {

	dateStamp := time.Now().Format("0601")

	sanitizedTarget := sanitizeFilename(target)

	baseFilename := fmt.Sprintf("%s_%s_%s", sanitizedTarget, moduleCode, dateStamp)

	fileExt := ".txt"
	if moduleCode == "JS" {
		fileExt = ".js"
	}

	pattern := filepath.Join(baseDir, baseFilename+"*"+fileExt)
	matches, err := filepath.Glob(pattern)

	if err != nil || len(matches) == 0 {

		return filepath.Join(baseDir, baseFilename+"_1"+fileExt)
	}

	maxSeq := 0
	seqRegex := regexp.MustCompile(`_(\d+)` + regexp.QuoteMeta(fileExt) + `$`)

	for _, match := range matches {
		submatch := seqRegex.FindStringSubmatch(match)
		if len(submatch) > 1 {
			if seq, err := strconv.Atoi(submatch[1]); err == nil && seq > maxSeq {
				maxSeq = seq
			}
		}
	}

	return filepath.Join(baseDir, fmt.Sprintf("%s_%d%s", baseFilename, maxSeq+1, fileExt))
}

func sanitizeFilename(input string) string {

	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")

	invalidChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", " "}
	result := input

	for _, char := range invalidChars {
		result = strings.ReplaceAll(result, char, "_")
	}

	result = strings.TrimRight(result, ". ")

	maxLength := 200
	if len(result) > maxLength {
		result = result[:maxLength]
	}

	return result
}

func truncateString(s string, maxLen int) string {
	if s == "" {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func showAvailableSources() {
	fmt.Printf("\n%s\n", color.HiCyanString("━━━━ AVAILABLE SOURCES ━━━━"))

	fmt.Printf("\n%s\n", color.HiGreenString("Free Sources (No API key required):"))
	freeSources := []string{
		"crtsh", "hackertarget", "alienvault", "urlscan", "threatminer",
		"riddler", "wayback", "rapiddns", "commoncrawl", "certspotter",
		"anubis", "threatcrowd", "sitedossier", "hudsonrock", "digitorus",
	}
	printSourcesGrid(freeSources, 3)

	fmt.Printf("\n%s\n", color.HiYellowString("Premium Sources (API key required):"))
	premiumSources := []string{
		"bufferover", "leakix", "netlas", "securitytrails", "shodan",
		"censys", "virustotal", "facebookct", "dnsdumpster", "chaos",
		"spyse", "fullhunt", "binaryedge", "threatbook", "intelx",
		"c99", "bevigil", "chinaz", "digitalyama", "dnsdb",
		"dnsrepo", "fofa", "github", "hunter", "quake",
		"redhuntlabs", "robtex", "whoisxmlapi", "zoomeye", "facebook",
		"builtwith",
	}
	printSourcesGrid(premiumSources, 5)

	fmt.Printf("\n%s\n", color.HiWhiteString("Usage:"))
	fmt.Printf("  • To use specific sources: %s\n", color.HiGreenString("./bbrecon -t example.com -s crtsh,hackertarget,alienvault"))
	fmt.Printf("  • To exclude sources: %s\n", color.HiGreenString("./bbrecon -t example.com -es securitytrails,shodan"))
	fmt.Printf("  • To use all sources: %s\n", color.HiGreenString("./bbrecon -t example.com -all"))
	fmt.Printf("  • To show source statistics: %s\n", color.HiGreenString("./bbrecon -t example.com -stats"))
}

func displaySourcesWithAPIInfo(sources []string, showAPIInfo bool) {
	if len(sources) == 0 {
		return
	}

	sourceInfo := subdomain.GetSourcesInfo()

	var freeSources []string
	var premiumSources []string

	// Get list of premium sources with configured API keys
	homeDir, _ := os.UserHomeDir()
	configPath := filepath.Join(homeDir, ".config", "bbrecon", "config.yaml")
	cfg, err := config.LoadConfig(configPath)
	var activeKeys []string

	if err == nil {
		for source := range cfg.SubdomainConfig.APIKeys {
			activeKeys = append(activeKeys, source)
		}
	}

	for _, source := range sources {
		info, exists := sourceInfo[source]
		if !exists {
			freeSources = append(freeSources, source)
			continue
		}

		if info.RequiresKey {
			premiumSources = append(premiumSources, source)
		} else {
			freeSources = append(freeSources, source)
		}
	}

	// This ensures we're using the slices (placates staticcheck)
	_ = freeSources[:0]
	_ = premiumSources[:0]

	// Enhanced API key messaging
	// Message removed as requested by user

	// Show active premium sources count
	activePremiumCount := 0
	for _, key := range activeKeys {
		for _, source := range premiumSources {
			if strings.EqualFold(key, source) {
				activePremiumCount++
				break
			}
		}
	}

	if activePremiumCount > 0 && len(premiumSources) > 0 {
		fmt.Printf("%s %d/%d premium sources have API keys configured\n",
			info("INFO:"), activePremiumCount, len(premiumSources))
	}

	if showAPIInfo {
		if err == nil && len(premiumSources) > 0 {
			missingKeys := checkAPIKeysConfiguration(*cfg, premiumSources)

			if debug {
				fmt.Printf("%s Premium sources: %v\n", info("DEBUG:"), premiumSources)
				fmt.Printf("%s Active keys: %s\n", info("DEBUG:"), strings.Join(activeKeys, ", "))
				fmt.Printf("%s Missing keys: %v\n", info("DEBUG:"), missingKeys)
			}

			// Show more detailed information about missing keys
			if len(missingKeys) > 0 {
				fmt.Printf("%s Missing API keys for %d premium sources\n",
					warn("WARNING:"), len(missingKeys))

				fmt.Printf("%s Add keys to api_keys.yaml for better results\n",
					info("TIP:"))
			}
		}
	}
}

func checkAPIKeysConfiguration(cfg config.Config, sources []string) []string {
	sourceInfo := subdomain.GetSourcesInfo()
	missingKeys := []string{}

	for _, source := range sources {
		info, exists := sourceInfo[source]
		if !exists || !info.RequiresKey {
			continue
		}

		hasKey := false

		switch source {
		case "securitytrails":
			hasKey = cfg.SubdomainConfig.SecurityTrailsAPIKey != ""
		case "shodan":
			hasKey = cfg.SubdomainConfig.ShodanAPIKey != ""
		case "censys":
			hasKey = cfg.SubdomainConfig.CensysAPIKey != "" && cfg.SubdomainConfig.CensysAPISecret != ""
		case "virustotal":
			hasKey = cfg.SubdomainConfig.VirusTotalAPIKey != ""
		case "binaryedge":
			hasKey = cfg.SubdomainConfig.BinaryEdgeAPIKey != ""
		case "fullhunt":
			hasKey = cfg.SubdomainConfig.FullHuntAPIKey != ""
		case "spyse":
			hasKey = cfg.SubdomainConfig.SpyseAPIKey != ""
		case "netlas":
			hasKey = cfg.SubdomainConfig.NetlasAPIKey != ""
		case "leakix":
			hasKey = cfg.SubdomainConfig.LeakixAPIKey != ""
		case "threatbook":
			hasKey = cfg.SubdomainConfig.ThreatBookAPIKey != ""

		default:
			if value, exists := cfg.SubdomainConfig.APIKeys[source]; exists && value != "" {
				hasKey = true
			}
		}

		if !hasKey {
			missingKeys = append(missingKeys, source)
		}
	}

	return missingKeys
}

func contains(slice []string, str string) bool {
	for _, s := range slice {
		if strings.TrimSpace(s) == str {
			return true
		}
	}
	return false
}

func printBanner() {

	if bannerPrinted {
		return
	}

	bannerLines := strings.Split(banner, "\n")
	for _, line := range bannerLines {
		if line != "" {
			fmt.Println(color.HiCyanString(line))
		}
	}
	fmt.Println(color.HiGreenString("Created by: ") + color.HiWhiteString("Zarni(Neo)"))
	fmt.Printf("%s %s\n\n", color.HiMagentaString(appName), color.HiYellowString("v"+appVersion))

	bannerPrinted = true
}

func validateCommandLineArgs() {
	args := os.Args[1:]
	if len(args) == 0 {
		return
	}

	for i := 0; i < len(args); i++ {
		if args[i] == "-t" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {

			tValueIndex := i + 1

			if tValueIndex+1 < len(args) && !strings.HasPrefix(args[tValueIndex+1], "-") {
				printBanner()
				fmt.Printf("%s Invalid use of -t flag: '%s %s %s'\n",
					error_("ERROR:"),
					args[i],
					args[tValueIndex],
					args[tValueIndex+1])
				fmt.Printf("%s Use comma-separated domains with -t flag: -t domain1.com,domain2.com\n",
					info("INFO:"))
				fmt.Printf("%s Or specify module flags like: -t domain.com -S -H\n",
					info("INFO:"))
				os.Exit(1)
			}
		}
	}

	knownFlags := map[string]bool{
		"-c": true, "-t": true, "-o": true, "-th": true, "-to": true,
		"-w": true, "-A": true, "-debug": true, "-v": true, "-h": true,
		"-s": true, "-es": true, "-recursive": true, "-all": true,
		"-m": true, "-f": true, "-json": true, "-ip": true, "-silent": true,
		"-C": true, "-no-results": true, "-S": true, "-H": true, "-D": true,
		"-J": true, "-N": true, "-stats": true, "-no-js-errors": true,
		"-X": true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {

			if _, ok := knownFlags[arg]; !ok {

				printBanner()
				fmt.Printf("%s Unknown flag: %s\n", error_("ERROR:"), arg)
				fmt.Printf("%s Use -h for help on available flags\n", info("INFO:"))
				os.Exit(1)
			}

			if arg == "-c" || arg == "-t" || arg == "-o" || arg == "-th" || arg == "-to" ||
				arg == "-w" || arg == "-s" || arg == "-es" || arg == "-m" || arg == "-f" || arg == "-C" {
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
				}
			}
		} else {

			if i > 0 && (args[i-1] == "-c" || args[i-1] == "-t" || args[i-1] == "-o" ||
				args[i-1] == "-th" || args[i-1] == "-to" || args[i-1] == "-w" ||
				args[i-1] == "-s" || args[i-1] == "-es" || args[i-1] == "-m" ||
				args[i-1] == "-f" || args[i-1] == "-C") {

				continue
			}

			printBanner()
			fmt.Printf("%s Unrecognized argument: %s\n", error_("ERROR:"), arg)
			fmt.Printf("%s Use -h for help on correct command usage\n", info("INFO:"))
			os.Exit(1)
		}
	}
}

func calculateOptimalBatchSize(totalDomains, maxBatchSize int) int {
	if maxBatchSize <= 0 {
		maxBatchSize = 100
	}

	if totalDomains <= 50 {
		return totalDomains
	}

	if totalDomains <= 500 {
		return min(50, maxBatchSize)
	}

	if totalDomains <= 2000 {
		return min(100, maxBatchSize)
	}

	return min(200, maxBatchSize)
}

func processDNSEnumerationWithBatching(dnsTargets []string, config dnsenum.Config, timeout int, maxBatchSize int) ([]output.Finding, error) {
	allFindings := []output.Finding{}
	totalDomains := len(dnsTargets)

	batchSize := calculateOptimalBatchSize(totalDomains, maxBatchSize)
	batchCount := (totalDomains + batchSize - 1) / batchSize

	fmt.Printf("%s Processing %d subdomains in %d batches\n",
		color.CyanString("INFO:"),
		totalDomains,
		batchCount)

	startTime := time.Now()
	recordCounts := make(map[string]int)
	securityIssueCount := 0
	totalRecords := 0

	for i := 0; i < totalDomains; i += batchSize {
		end := min(i+batchSize, totalDomains)
		currentBatch := dnsTargets[i:end]

		batchProgress := float64(i+1) / float64(totalDomains) * 100
		elapsed := time.Since(startTime).Round(time.Second)
		fmt.Printf("\r%s Batch %d/%d | Progress: %.1f%% | Records: %d | Issues: %d | Elapsed: %s",
			color.CyanString("DNS:"),
			(i/batchSize)+1,
			batchCount,
			batchProgress,
			totalRecords,
			securityIssueCount,
			formatDuration(elapsed))

		var batchFindings []output.Finding
		var wg sync.WaitGroup
		var mu sync.Mutex
		semaphore := make(chan struct{}, 20)

		for _, domain := range currentBatch {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(domain string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				dnsEnumerator := dnsenum.NewEnumerator(domain, config, timeout)
				results, err := dnsEnumerator.Run()

				if err != nil {
					return
				}

				mu.Lock()
				for _, finding := range results {
					if finding.Type == "dns_record" {
						if recordType, ok := finding.Data["record_type"].(string); ok {
							recordCounts[recordType]++
							totalRecords++
						}
					} else if finding.Type == "dns_security_issue" {
						securityIssueCount++
					}
				}
				batchFindings = append(batchFindings, results...)
				mu.Unlock()
			}(domain)
		}

		wg.Wait()
		allFindings = append(allFindings, batchFindings...)

		time.Sleep(100 * time.Millisecond)
	}

	// Ensure we display 100% progress at the end
	elapsed := time.Since(startTime).Round(time.Second)
	fmt.Printf("\r%s Batch %d/%d | Progress: 100.0%% | Records: %d | Issues: %d | Elapsed: %s",
		color.CyanString("DNS:"),
		batchCount,
		batchCount,
		totalRecords,
		securityIssueCount,
		formatDuration(elapsed))

	fmt.Println()
	return allFindings, nil
}

// Helper function to write findings to file
func writeFinding(finding exposure.Finding, severity string, f *os.File) {
	fmt.Fprintf(f, "[%s] %s\n", severity, finding.Type)
	fmt.Fprintf(f, "URL: %s\n", finding.URL)
	if finding.StatusCode > 0 {
		fmt.Fprintf(f, "Status: %d\n", finding.StatusCode)
	}
	if finding.ContentType != "" {
		fmt.Fprintf(f, "Content-Type: %s\n", finding.ContentType)
	}
	if finding.Value != "" {
		fmt.Fprintf(f, "Value: %s\n", finding.Value)
	}
	if finding.LineNumber > 0 {
		fmt.Fprintf(f, "Line: %d\n", finding.LineNumber)
	}
	if finding.POC != "" {
		fmt.Fprintf(f, "POC: %s\n", finding.POC)
	}
	fmt.Fprintf(f, "\n")
}

// Add this helper function at the bottom of the file
func keys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
