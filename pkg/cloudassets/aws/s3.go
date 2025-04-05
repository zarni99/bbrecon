package aws

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zarni99/bbrecon/pkg/cloudassets/common"
)

// Constants for S3 discovery
const (
	s3URLFormat = "https://%s.s3.amazonaws.com"
	s3WebFormat = "http://%s.s3-website-%s.amazonaws.com"
)

// DiscoverS3BucketByPermutation checks if a bucket with the given name exists
func DiscoverS3BucketByPermutation(ctx context.Context, bucketName, region string) (*common.AssetFinding, error) {
	// Create URLs to check
	s3URL := fmt.Sprintf(s3URLFormat, bucketName)
	s3WebURL := fmt.Sprintf(s3WebFormat, bucketName, region)

	// Check if bucket exists and is accessible
	isPublic, err := checkS3BucketAccess(s3URL)
	if err != nil {
		// Try web hosting URL as fallback
		isPublic, err = checkS3BucketAccess(s3WebURL)
		if err != nil {
			return nil, fmt.Errorf("bucket %s not found or not accessible", bucketName)
		}
	}

	// Determine access level
	accessLevel := common.AccessLevelPrivate
	if isPublic {
		accessLevel = common.AccessLevelPublic
	}

	// Create a finding
	finding := &common.AssetFinding{
		Provider:        common.ProviderAWS,
		Type:            common.AssetTypeS3Bucket,
		Name:            bucketName,
		Region:          region,
		AccessLevel:     accessLevel,
		URL:             s3URL,
		CreationDate:    "",
		LastModified:    time.Now().Format("2006-01-02 15:04:05"),
		IsVulnerable:    isPublic,
		DiscoveryMethod: "permutation",
		Metadata: map[string]string{
			"web_url": s3WebURL,
		},
	}

	if isPublic {
		finding.VulnDescription = "S3 bucket is publicly accessible and may contain sensitive data"
	}

	return finding, nil
}

// DiscoverS3BucketsByPermutation uses permutation to discover S3 buckets
func DiscoverS3BucketsByPermutation(ctx context.Context, permutations []string, region string, concurrency int) ([]common.AssetFinding, error) {
	findings := []common.AssetFinding{}
	var mu sync.Mutex

	// Create a semaphore to limit concurrency
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, perm := range permutations {
		// Skip if permutation contains invalid S3 bucket name characters
		if !isValidS3BucketName(perm) {
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

			finding, err := DiscoverS3BucketByPermutation(ctx, p, region)
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

// checkS3BucketAccess checks if a bucket URL is accessible
func checkS3BucketAccess(url string) (bool, error) {
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

	// 200 OK means the bucket exists and is public
	if resp.StatusCode == 200 {
		return true, nil
	}

	// 403 Forbidden means the bucket exists but is not public
	if resp.StatusCode == 403 {
		// Check if this is an S3 bucket by looking for S3 specific headers
		if resp.Header.Get("x-amz-request-id") != "" {
			return false, nil
		}
	}

	// Other status codes likely mean the bucket doesn't exist
	return false, fmt.Errorf("bucket not found or not an S3 bucket")
}

// isValidS3BucketName checks if a name is a valid S3 bucket name
func isValidS3BucketName(name string) bool {
	// S3 bucket names must be between 3 and 63 characters long
	if len(name) < 3 || len(name) > 63 {
		return false
	}

	// S3 bucket names can only contain lowercase letters, numbers, dots, and hyphens
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}

	// S3 bucket names must start and end with a lowercase letter or number
	if !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= '0' && name[0] <= '9')) {
		return false
	}

	if !((name[len(name)-1] >= 'a' && name[len(name)-1] <= 'z') || (name[len(name)-1] >= '0' && name[len(name)-1] <= '9')) {
		return false
	}

	// S3 bucket names cannot contain two adjacent periods
	if strings.Contains(name, "..") {
		return false
	}

	// S3 bucket names cannot be formatted as an IP address
	if isIPAddress(name) {
		return false
	}

	return true
}

// isIPAddress checks if a string is formatted as an IP address
func isIPAddress(name string) bool {
	// Simple check for IP address format
	parts := strings.Split(name, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 {
			return false
		}

		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}

	return true
}
