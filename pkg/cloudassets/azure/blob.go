package azure

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zarni99/bbrecon/pkg/cloudassets/common"
)

// Constants for Azure Blob discovery
const (
	azureBlobURLFormat = "https://%s.blob.core.windows.net"
)

// DiscoverAzureBlobByPermutation checks if a storage account with the given name exists
func DiscoverAzureBlobByPermutation(ctx context.Context, accountName string) (*common.AssetFinding, error) {
	// Create URL to check
	blobURL := fmt.Sprintf(azureBlobURLFormat, accountName)

	// Check if storage account exists and is accessible
	isPublic, err := checkAzureBlobAccess(blobURL)
	if err != nil {
		return nil, fmt.Errorf("storage account %s not found or not accessible", accountName)
	}

	// Determine access level
	accessLevel := common.AccessLevelPrivate
	if isPublic {
		accessLevel = common.AccessLevelPublic
	}

	// Create a finding
	finding := &common.AssetFinding{
		Provider:        common.ProviderAzure,
		Type:            common.AssetTypeAzureBlob,
		Name:            accountName,
		Region:          "", // We don't know the region from just the URL
		AccessLevel:     accessLevel,
		URL:             blobURL,
		LastModified:    time.Now().Format("2006-01-02 15:04:05"),
		IsVulnerable:    isPublic,
		DiscoveryMethod: "permutation",
		Metadata: map[string]string{
			"account_type": "Storage Account",
		},
	}

	if isPublic {
		finding.VulnDescription = "Azure Blob storage is publicly accessible and may contain sensitive data"
	}

	return finding, nil
}

// DiscoverAzureBlobsByPermutation uses permutation to discover Azure Blob storage accounts
func DiscoverAzureBlobsByPermutation(ctx context.Context, permutations []string, concurrency int) ([]common.AssetFinding, error) {
	findings := []common.AssetFinding{}
	var mu sync.Mutex

	// Create a semaphore to limit concurrency
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, perm := range permutations {
		// Skip if permutation contains invalid Azure storage account name characters
		if !isValidAzureStorageAccountName(perm) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(p string) {
			defer func() {
				<-sem
				wg.Done()
			}()

			// Check if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
			}

			finding, err := DiscoverAzureBlobByPermutation(ctx, p)
			if err == nil && finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
			}
		}(perm)
	}

	wg.Wait()

	return findings, nil
}

// checkAzureBlobAccess checks if a blob storage URL is accessible
func checkAzureBlobAccess(url string) (bool, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Check if this is an Azure Blob storage by looking for Azure specific headers
	isAzureStorage := false
	for name := range resp.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-ms-") {
			isAzureStorage = true
			break
		}
	}

	if !isAzureStorage {
		return false, fmt.Errorf("not an Azure storage account")
	}

	// Check if it's publicly accessible
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	} else if resp.StatusCode == 400 || resp.StatusCode == 403 {
		// 400 or 403 means the storage exists but is not public or requires SAS token
		return false, nil
	}

	return false, fmt.Errorf("storage not found or not accessible")
}

// isValidAzureStorageAccountName checks if a name is a valid Azure storage account name
func isValidAzureStorageAccountName(name string) bool {
	// Storage account names must be between 3 and 24 characters
	if len(name) < 3 || len(name) > 24 {
		return false
	}

	// Storage account names can only contain lowercase letters and numbers
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}

	return true
}
