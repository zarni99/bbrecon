package cloudassets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/zarni99/bbrecon/pkg/cloudassets/aws"
	"github.com/zarni99/bbrecon/pkg/cloudassets/azure"
	"github.com/zarni99/bbrecon/pkg/cloudassets/common"
)

// Discovery methods
const (
	DiscoveryAPIEnum     = "api_enumeration"
	DiscoveryPermutation = "permutation"
	DiscoveryDomainBased = "domain_based"
)

// CloudAssetDiscovery is the main interface for cloud asset discovery
type CloudAssetDiscovery struct {
	Domain       string
	OutputDir    string
	AWSEnabled   bool
	AzureEnabled bool
	GCPEnabled   bool
	AWSRegion    string
	Concurrency  int
	Timeout      int
	Debug        bool
	SummaryOnly  bool // Option to only display summary and not detailed findings
	AWSScanner   *aws.AWSScanner
	AzureScanner *azure.AzureScanner
	Findings     []common.AssetFinding
}

// NewCloudAssetDiscovery creates a new cloud asset discovery scanner
func NewCloudAssetDiscovery(domain, outputDir, awsRegion string, awsEnabled, azureEnabled, gcpEnabled bool, concurrency, timeout int, debug, summaryOnly bool) (*CloudAssetDiscovery, error) {
	if concurrency <= 0 {
		concurrency = 10
	}

	if timeout <= 0 {
		timeout = 30
	}

	if awsRegion == "" {
		awsRegion = "us-east-1"
	}

	cd := &CloudAssetDiscovery{
		Domain:       domain,
		OutputDir:    outputDir,
		AWSEnabled:   awsEnabled,
		AzureEnabled: azureEnabled,
		GCPEnabled:   gcpEnabled,
		AWSRegion:    awsRegion,
		Concurrency:  concurrency,
		Timeout:      timeout,
		Debug:        debug,
		SummaryOnly:  summaryOnly,
		Findings:     []common.AssetFinding{},
	}

	// Generate permutations for each provider
	awsPermutations := GenerateProviderSpecificPermutations(domain, "aws")
	azurePermutations := GenerateProviderSpecificPermutations(domain, "azure")

	// Initialize scanners
	if awsEnabled {
		cd.AWSScanner = aws.NewAWSScanner(domain, awsRegion, awsPermutations, concurrency, timeout, debug)
	}

	if azureEnabled {
		cd.AzureScanner = azure.NewAzureScanner(domain, azurePermutations, concurrency, timeout, debug)
	}

	// GCP scanner initialization would go here

	return cd, nil
}

// ScanAll runs all enabled cloud scanners
func (cd *CloudAssetDiscovery) ScanAll(ctx context.Context) ([]common.AssetFinding, error) {
	fmt.Printf("\n%s %s %s\n",
		color.HiYellowString("[ * ]"),
		color.HiMagentaString("Starting Cloud Asset Discovery for"),
		color.HiWhiteString(cd.Domain))

	startTime := time.Now()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var findings []common.AssetFinding

	// Run AWS scanner if enabled
	if cd.AWSEnabled && cd.AWSScanner != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			awsFindings, err := cd.AWSScanner.ScanAll(ctx)
			if err != nil {
				fmt.Printf("%s Error in AWS scanning: %v\n", color.HiRedString("ERROR:"), err)
				return
			}

			if len(awsFindings) > 0 {
				mu.Lock()
				findings = append(findings, awsFindings...)
				mu.Unlock()

				fmt.Printf("Found %s AWS assets\n", color.HiGreenString("%d", len(awsFindings)))

				// Print detailed findings if not in summary-only mode
				if !cd.SummaryOnly {
					cd.AWSScanner.PrintFindings(awsFindings)
				}
			} else {
				fmt.Printf("No AWS assets found\n")
			}
		}()
	}

	// Run Azure scanner if enabled
	if cd.AzureEnabled && cd.AzureScanner != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			azureFindings, err := cd.AzureScanner.ScanAll(ctx)
			if err != nil {
				fmt.Printf("%s Error in Azure scanning: %v\n", color.HiRedString("ERROR:"), err)
				return
			}

			if len(azureFindings) > 0 {
				mu.Lock()
				findings = append(findings, azureFindings...)
				mu.Unlock()

				fmt.Printf("Found %s Azure assets\n", color.HiGreenString("%d", len(azureFindings)))

				// Print detailed findings if not in summary-only mode
				if !cd.SummaryOnly {
					cd.AzureScanner.PrintFindings(azureFindings)
				}
			} else {
				fmt.Printf("No Azure assets found\n")
			}
		}()
	}

	// Run GCP scanner if enabled (would go here)

	// Wait for all scans to complete
	wg.Wait()

	// Save findings
	cd.Findings = findings

	if len(findings) > 0 {
		// Always show the summary
		cd.ShowSummary()

		// Save results to file
		err := cd.SaveResults()
		if err != nil {
			fmt.Printf("%s Error saving results: %v\n", color.HiRedString("ERROR:"), err)
		}
	} else {
		fmt.Printf("\nNo cloud assets found for %s\n",
			color.HiWhiteString(cd.Domain))
	}

	duration := time.Since(startTime)

	fmt.Printf("\n%s %s %s %s\n",
		color.HiGreenString("[ SCAN COMPLETE ]"),
		color.HiMagentaString("Duration:"),
		color.HiWhiteString(duration.Round(time.Second).String()),
		color.HiGreenString("Total assets: %d", len(findings)))

	return findings, nil
}

// SaveResults saves all findings to a file
func (cd *CloudAssetDiscovery) SaveResults() error {
	if len(cd.Findings) == 0 {
		return nil
	}

	// Create results directory if it doesn't exist
	resultsDir := cd.OutputDir
	if resultsDir == "" {
		resultsDir = "results"
	}

	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	// Generate a unique filename
	baseFilename := cd.Domain
	if baseFilename == "" {
		baseFilename = "cloud_assets"
	}

	outputFile := generateUniqueFilename(resultsDir, baseFilename, "CLOUD")

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	// Write header
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	f.WriteString(fmt.Sprintf("# Cloud Asset Discovery Results for '%s'\n", cd.Domain))
	f.WriteString(fmt.Sprintf("# Scan Date: %s\n", currentTime))
	f.WriteString(fmt.Sprintf("# Total Assets Found: %d\n\n", len(cd.Findings)))

	// Group findings by provider
	awsFindings := []common.AssetFinding{}
	azureFindings := []common.AssetFinding{}
	gcpFindings := []common.AssetFinding{}
	otherFindings := []common.AssetFinding{}

	for _, finding := range cd.Findings {
		switch finding.Provider {
		case common.ProviderAWS:
			awsFindings = append(awsFindings, finding)
		case common.ProviderAzure:
			azureFindings = append(azureFindings, finding)
		case common.ProviderGCP:
			gcpFindings = append(gcpFindings, finding)
		default:
			otherFindings = append(otherFindings, finding)
		}
	}

	// Write findings for each provider
	writeProviderFindings(f, "AWS", awsFindings)
	writeProviderFindings(f, "AZURE", azureFindings)
	writeProviderFindings(f, "GCP", gcpFindings)
	writeProviderFindings(f, "OTHER", otherFindings)

	fmt.Printf("%s Results saved to %s\n",
		color.HiGreenString("[✓]"),
		color.HiYellowString(outputFile))

	return nil
}

// Helper function to write findings for a specific provider
func writeProviderFindings(f *os.File, providerName string, findings []common.AssetFinding) {
	if len(findings) == 0 {
		return
	}

	f.WriteString(fmt.Sprintf("\n===== %s ASSETS (%d) =====\n\n", providerName, len(findings)))
	for i, finding := range findings {
		f.WriteString(fmt.Sprintf("%d. %s (%s)\n", i+1, finding.Name, finding.Type))
		f.WriteString(fmt.Sprintf("   URL: %s\n", finding.URL))

		if finding.Region != "" {
			f.WriteString(fmt.Sprintf("   Region: %s\n", finding.Region))
		}

		f.WriteString(fmt.Sprintf("   Access Level: %s\n", finding.AccessLevel))
		f.WriteString(fmt.Sprintf("   Discovery Method: %s\n", finding.DiscoveryMethod))

		if finding.IsVulnerable {
			f.WriteString(fmt.Sprintf("   Vulnerability: %s\n", finding.VulnDescription))
		}

		if len(finding.Metadata) > 0 {
			f.WriteString("   Additional Info:\n")
			for k, v := range finding.Metadata {
				f.WriteString(fmt.Sprintf("     %s: %s\n", k, v))
			}
		}

		f.WriteString("\n")
	}
}

// generateUniqueFilename creates a unique filename with the given parameters
// It checks for existing files and adds a sequence number if needed
func generateUniqueFilename(baseDir, target, moduleCode string) string {
	// Create date stamp
	dateStamp := time.Now().Format("0102") // MMDD format

	// Sanitize the target name for use in a filename
	safeName := sanitizeFilename(target)

	// Create base filename
	baseFilename := fmt.Sprintf("%s_%s_%s", safeName, moduleCode, dateStamp)

	// Check if file already exists with the base name
	basePattern := fmt.Sprintf(`%s_%s_%s(_\d+)?\.txt$`,
		regexp.QuoteMeta(safeName),
		regexp.QuoteMeta(moduleCode),
		regexp.QuoteMeta(dateStamp))

	baseRegex := regexp.MustCompile(basePattern)

	// Find existing files that match our pattern
	files, err := filepath.Glob(filepath.Join(baseDir, "*.txt"))
	if err != nil {
		// If there's an error, just use the base filename
		return filepath.Join(baseDir, baseFilename+".txt")
	}

	// Find the highest sequence number
	maxSeq := 0
	for _, file := range files {
		filename := filepath.Base(file)
		if baseRegex.MatchString(filename) {
			// If it's an exact match with no sequence number
			if filename == baseFilename+".txt" {
				maxSeq = 1
				continue
			}

			// Try to extract sequence number
			seqMatch := regexp.MustCompile(`_([0-9]+)\.txt$`).FindStringSubmatch(filename)
			if len(seqMatch) > 1 {
				seq, err := strconv.Atoi(seqMatch[1])
				if err == nil && seq >= maxSeq {
					maxSeq = seq + 1
				}
			}
		}
	}

	// Add sequence number if needed
	finalFilename := baseFilename
	if maxSeq > 0 {
		finalFilename = fmt.Sprintf("%s_%d", baseFilename, maxSeq)
	}

	return filepath.Join(baseDir, finalFilename+".txt")
}

// sanitizeFilename removes invalid characters from a filename and ensures it's not too long
func sanitizeFilename(name string) string {
	// Replace invalid characters with underscores
	re := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)
	name = re.ReplaceAllString(name, "_")

	// Limit length to 200 chars to avoid path length issues
	if len(name) > 200 {
		name = name[:200]
	}

	return name
}

// PrintFindings prints all findings from all scanners to the console
func (cd *CloudAssetDiscovery) PrintFindings() {
	if len(cd.Findings) == 0 {
		fmt.Printf("%s %s\n",
			color.HiBlueString("[CLOUD ASSET DISCOVERY]"),
			color.HiYellowString("No cloud assets found"))
		return
	}

	fmt.Printf("%s %s %s\n",
		color.HiBlueString("[CLOUD ASSET DISCOVERY]"),
		color.HiYellowString("SUMMARY"),
		color.HiGreenString("(%d total assets found)", len(cd.Findings)))

	// Group findings by provider
	findingsByProvider := make(map[common.CloudProvider][]common.AssetFinding)

	// Count vulnerable resources
	vulnerableCount := 0
	for _, finding := range cd.Findings {
		provider := finding.Provider
		if provider == "" {
			provider = "Unknown"
		}
		findingsByProvider[provider] = append(findingsByProvider[provider], finding)

		if finding.IsVulnerable {
			vulnerableCount++
		}
	}

	// Show security highlights if any vulnerable resources found
	if vulnerableCount > 0 {
		fmt.Printf("%s %s public/vulnerable resources detected!\n",
			color.HiRedString("SECURITY ALERT:"),
			color.HiRedString("%d", vulnerableCount))
	}

	// Print summary counts by provider
	for provider, findings := range findingsByProvider {
		var displayName string
		switch provider {
		case common.ProviderAWS:
			displayName = color.HiYellowString("AWS")
		case common.ProviderAzure:
			displayName = color.HiBlueString("Azure")
		case common.ProviderGCP:
			displayName = color.HiRedString("GCP")
		default:
			displayName = color.HiWhiteString(string(provider))
		}

		fmt.Printf("%s: %s assets\n",
			displayName,
			color.HiGreenString("%d", len(findings)))
	}

	// Pagination constants
	const maxItemsPerPage = 10
	const totalToShow = 30 // Show only the first N items in detail by default

	// If there are many findings, only show details for the first few
	totalItems := len(cd.Findings)
	itemsToShow := totalItems
	if totalItems > totalToShow {
		fmt.Printf("%s Showing first %d of %d assets (see output file for full list)\n",
			color.HiYellowString("NOTE:"),
			totalToShow,
			totalItems)
		itemsToShow = totalToShow
	}

	// Display findings by provider with pagination
	var itemCounter int = 0
	for provider, findings := range findingsByProvider {
		var displayName string
		switch provider {
		case common.ProviderAWS:
			displayName = color.HiYellowString("AWS ASSETS")
		case common.ProviderAzure:
			displayName = color.HiBlueString("AZURE ASSETS")
		case common.ProviderGCP:
			displayName = color.HiRedString("GCP ASSETS")
		default:
			displayName = color.HiWhiteString(string(provider) + " ASSETS")
		}

		fmt.Printf("\n%s %s\n",
			displayName,
			color.HiGreenString("(%d)", len(findings)))

		// Print up to itemsToShow findings with pagination
		for i, finding := range findings {
			// Stop if we've hit our total limit across all providers
			if itemCounter >= itemsToShow {
				break
			}

			// Pagination break
			if itemCounter > 0 && itemCounter%maxItemsPerPage == 0 {
				fmt.Printf("%s Press Enter to see more results (%d-%d of %d)...",
					color.HiYellowString("PAGE:"),
					itemCounter+1,
					min(itemCounter+maxItemsPerPage, itemsToShow),
					totalItems)
				fmt.Scanln() // Wait for user to press Enter
			}

			fmt.Printf("%d. %s (%s)\n",
				i+1,
				color.HiWhiteString(finding.Name),
				color.HiCyanString(string(finding.Type)))

			fmt.Printf("   %s %s\n",
				color.HiBlueString("URL:"),
				finding.URL)

			if finding.Region != "" {
				fmt.Printf("   %s %s\n",
					color.HiBlueString("Region:"),
					finding.Region)
			}

			// Color the access level based on sensitivity
			accessColor := color.HiGreenString
			accessLevelStr := string(finding.AccessLevel)
			if accessLevelStr == "PUBLIC" || accessLevelStr == "OPEN" {
				accessColor = color.HiRedString
			} else if accessLevelStr == "PARTIAL" || accessLevelStr == "LIMITED" {
				accessColor = color.HiYellowString
			}

			fmt.Printf("   %s %s\n",
				color.HiBlueString("Access Level:"),
				accessColor(accessLevelStr))

			fmt.Printf("   %s %s\n",
				color.HiBlueString("Discovery Method:"),
				color.HiMagentaString(finding.DiscoveryMethod))

			if finding.IsVulnerable {
				fmt.Printf("   %s %s\n",
					color.HiRedString("Vulnerability:"),
					finding.VulnDescription)
			}

			if len(finding.Metadata) > 0 {
				fmt.Printf("   %s\n", color.HiBlueString("Additional Info:"))
				for k, v := range finding.Metadata {
					fmt.Printf("     %s %s\n",
						color.HiYellowString(k+":"),
						v)
				}
			}

			if i < len(findings)-1 && itemCounter < itemsToShow-1 {
				fmt.Printf("%s\n", color.HiWhiteString(strings.Repeat("·", 40)))
			}

			itemCounter++
		}

		// If we've hit our total limit, break out of the provider loop
		if itemCounter >= itemsToShow {
			break
		}
	}

	// If there are more findings beyond what we've shown
	if totalItems > totalToShow {
		fmt.Printf("Additional %d assets not shown here (see output file for complete results)\n",
			totalItems-totalToShow)
	}
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ShowSummary prints only a concise summary of the findings without detailed listings
func (cd *CloudAssetDiscovery) ShowSummary() {
	if len(cd.Findings) == 0 {
		fmt.Printf("%s %s\n",
			color.HiBlueString("[CLOUD ASSET DISCOVERY]"),
			color.HiYellowString("No cloud assets found"))
		return
	}

	fmt.Printf("%s %s %s\n",
		color.HiBlueString("[CLOUD ASSET DISCOVERY]"),
		color.HiYellowString("SUMMARY"),
		color.HiGreenString("(%d total assets found)", len(cd.Findings)))

	// Group findings by provider and count by type and access level
	findingsByProvider := make(map[common.CloudProvider][]common.AssetFinding)
	typeCountsByProvider := make(map[common.CloudProvider]map[common.AssetType]int)
	accessLevelCounts := make(map[common.AccessLevel]int)

	// Count vulnerable resources
	vulnerableCount := 0
	for _, finding := range cd.Findings {
		provider := finding.Provider
		if provider == "" {
			provider = "Unknown"
		}

		// Add to provider findings
		findingsByProvider[provider] = append(findingsByProvider[provider], finding)

		// Count by type
		if typeCountsByProvider[provider] == nil {
			typeCountsByProvider[provider] = make(map[common.AssetType]int)
		}
		typeCountsByProvider[provider][finding.Type]++

		// Count by access level
		accessLevelCounts[finding.AccessLevel]++

		// Count vulnerable
		if finding.IsVulnerable {
			vulnerableCount++
		}
	}

	// Show security highlights if any vulnerable resources found
	if vulnerableCount > 0 {
		fmt.Printf("%s %s public/vulnerable resources detected!\n\n",
			color.HiRedString("SECURITY ALERT:"),
			color.HiRedString("%d", vulnerableCount))
	} else {
		fmt.Println()
	}

	// Print summary counts by provider
	for provider, findings := range findingsByProvider {
		var displayName string
		switch provider {
		case common.ProviderAWS:
			displayName = color.HiYellowString("AWS")
		case common.ProviderAzure:
			displayName = color.HiBlueString("Azure")
		case common.ProviderGCP:
			displayName = color.HiRedString("GCP")
		default:
			displayName = color.HiWhiteString(string(provider))
		}

		fmt.Printf("%s: %s assets\n",
			displayName,
			color.HiGreenString("%d", len(findings)))

		// Print type breakdown for this provider
		if len(typeCountsByProvider[provider]) > 0 {
			fmt.Printf("  Types: ")
			var typeNames []string
			for typeName := range typeCountsByProvider[provider] {
				typeNames = append(typeNames, string(typeName))
			}
			sort.Strings(typeNames)

			for i, typeName := range typeNames {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Printf("%s (%d)", typeName, typeCountsByProvider[provider][common.AssetType(typeName)])
			}
			fmt.Println()
		}
	}

	// Print access level counts
	fmt.Printf("\nAccess Level Distribution:\n")
	fmt.Printf("  %s %d\n", color.HiRedString("PUBLIC:"), accessLevelCounts["PUBLIC"])
	fmt.Printf("  %s %d\n", color.HiYellowString("PARTIAL:"), accessLevelCounts["PARTIAL"])
	fmt.Printf("  %s %d\n", color.HiGreenString("PRIVATE:"), accessLevelCounts["PRIVATE"])

	// Show complete file output message
	resultsDir := cd.OutputDir
	if resultsDir == "" {
		resultsDir = "results"
	}

	fmt.Printf("\n%s Complete scan results saved to file (see output directory: %s)\n",
		color.HiGreenString("[✓]"),
		resultsDir)
}
