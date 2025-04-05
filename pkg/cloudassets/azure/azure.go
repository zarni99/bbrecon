package azure

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/zarni99/bbrecon/pkg/cloudassets/common"
)

// AzureScanner handles Azure asset discovery
type AzureScanner struct {
	Domain       string
	Permutations []string
	Concurrency  int
	Timeout      int
	Debug        bool
}

// NewAzureScanner creates a new Azure scanner
func NewAzureScanner(domain string, permutations []string, concurrency int, timeout int, debug bool) *AzureScanner {
	if concurrency <= 0 {
		concurrency = 10
	}

	if timeout <= 0 {
		timeout = 10
	}

	return &AzureScanner{
		Domain:       domain,
		Permutations: permutations,
		Concurrency:  concurrency,
		Timeout:      timeout,
		Debug:        debug,
	}
}

// ScanAll runs all Azure scanners
func (a *AzureScanner) ScanAll(ctx context.Context) ([]common.AssetFinding, error) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.Timeout)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var findings []common.AssetFinding
	var errs []error

	// Scan Azure Blob Storage
	wg.Add(1)
	go func() {
		defer wg.Done()

		blobFindings, err := DiscoverAzureBlobsByPermutation(ctx, a.Permutations, a.Concurrency)
		if err != nil && a.Debug {
			fmt.Printf("[DEBUG] Error scanning Azure Blob storage: %v\n", err)
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
			return
		}

		if len(blobFindings) > 0 {
			mu.Lock()
			findings = append(findings, blobFindings...)
			mu.Unlock()
		}
	}()

	// Add more Azure service scanners here
	// ...

	// Wait for all scans to complete
	wg.Wait()

	if len(errs) > 0 && a.Debug {
		fmt.Printf("[DEBUG] Completed Azure scanning with %d errors\n", len(errs))
	}

	return findings, nil
}

// PrintFindings prints the Azure findings to the console
func (s *AzureScanner) PrintFindings(findings []common.AssetFinding) {
	if len(findings) == 0 {
		fmt.Printf("%s No Azure assets found\n", color.HiBlueString("AZURE:"))
		return
	}

	fmt.Printf("\n%s %s %s %s %s\n",
		color.HiCyanString("["),
		color.HiYellowString("AZURE ASSETS FOUND"),
		color.HiCyanString("]"),
		color.HiMagentaString(":"),
		color.HiGreenString("%d", len(findings)))

	fmt.Println(color.HiWhiteString(strings.Repeat("─", 80)))

	// If there are a lot of findings, show a summary first and paginate
	const maxItemsPerPage = 10
	const totalToShow = 15 // Show only the first N items in detail by default

	// Display total counts and risks
	vulnerableCount := 0
	for _, finding := range findings {
		if finding.IsVulnerable {
			vulnerableCount++
		}
	}

	// Show security highlights if any vulnerable resources found
	if vulnerableCount > 0 {
		fmt.Printf("%s %s public/vulnerable resources detected\n",
			color.HiRedString("SECURITY ALERT:"),
			color.HiRedString("%d", vulnerableCount))
	}

	// If there are many findings, only show details for the first few
	totalItems := len(findings)
	itemsToShow := totalItems
	if totalItems > totalToShow {
		fmt.Printf("%s Showing first %d of %d assets (see output file for full list)\n",
			color.HiYellowString("NOTE:"),
			totalToShow,
			totalItems)
		itemsToShow = totalToShow
	}

	// Display findings with pagination if needed
	for i := 0; i < itemsToShow; i++ {
		finding := findings[i]

		// Show page break for better readability
		if i > 0 && i%maxItemsPerPage == 0 {
			fmt.Println(color.HiWhiteString(strings.Repeat("─", 40)))
			fmt.Printf("%s Press Enter to see more results (%d-%d of %d)...",
				color.HiYellowString("PAGE:"),
				i+1,
				min(i+maxItemsPerPage, itemsToShow),
				totalItems)
			fmt.Scanln() // Wait for user to press Enter
			fmt.Println(color.HiWhiteString(strings.Repeat("─", 80)))
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

		if i < itemsToShow-1 {
			fmt.Println(color.HiWhiteString(strings.Repeat("·", 40)))
		}
	}

	// If there are more findings beyond what we've shown
	if totalItems > totalToShow {
		fmt.Println(color.HiWhiteString(strings.Repeat("─", 80)))
		fmt.Printf("%s Additional %d assets not shown here (see output file for complete results)\n",
			color.HiYellowString("NOTE:"),
			totalItems-totalToShow)
	}

	fmt.Println(color.HiWhiteString(strings.Repeat("─", 80)))
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
