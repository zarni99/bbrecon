package cloudassets

import (
	"strings"
)

// Common permutation patterns for cloud resource names
var permutationPatterns = []string{
	"{domain}",        // example.com
	"{domainname}",    // examplecom
	"{name}",          // example
	"{name}-prod",     // example-prod
	"{name}-dev",      // example-dev
	"{name}-staging",  // example-staging
	"{name}-test",     // example-test
	"{name}-backup",   // example-backup
	"backup-{name}",   // backup-example
	"prod-{name}",     // prod-example
	"dev-{name}",      // dev-example
	"stage-{name}",    // stage-example
	"test-{name}",     // test-example
	"{name}-files",    // example-files
	"{name}-assets",   // example-assets
	"{name}-media",    // example-media
	"{name}-static",   // example-static
	"{name}-data",     // example-data
	"{name}-public",   // example-public
	"{name}-private",  // example-private
	"{name}-internal", // example-internal
	"{name}-external", // example-external
	"{name}-web",      // example-web
	"{name}-app",      // example-app
	"{name}-api",      // example-api
	"{name}.{tld}",    // example.com
	"{name}-{tld}",    // example-com
}

// CloudProviderPatterns holds specific patterns for each cloud provider
var CloudProviderPatterns = map[string][]string{
	"aws": {
		"{name}-s3",
		"{name}.s3",
		"{name}-bucket",
		"{name}-lambda",
		"{name}-function",
		"lambda-{name}",
	},
	"azure": {
		"{name}blob",
		"{name}storage",
		"{name}function",
		"{name}app",
		"blob-{name}",
	},
	"gcp": {
		"{name}-storage",
		"{name}-function",
		"{name}-gcp",
		"storage-{name}",
		"gcp-{name}",
	},
}

// GenerateNamePermutations generates permutations for cloud assets based on a domain
func GenerateNamePermutations(domain string) []string {
	// Extract domain name without TLD
	parts := strings.Split(domain, ".")
	name := parts[0]

	// For domains like sub.example.com, use example as the name
	if len(parts) > 2 {
		name = parts[len(parts)-2]
	}

	tld := ""
	if len(parts) > 1 {
		tld = parts[len(parts)-1]
	}

	// Remove special characters from domain name
	domainName := strings.ReplaceAll(domain, ".", "")

	permutations := []string{}

	// Generate permutations using common patterns
	for _, pattern := range permutationPatterns {
		p := pattern
		p = strings.ReplaceAll(p, "{domain}", domain)
		p = strings.ReplaceAll(p, "{domainname}", domainName)
		p = strings.ReplaceAll(p, "{name}", name)
		p = strings.ReplaceAll(p, "{tld}", tld)
		permutations = append(permutations, p)
	}

	return permutations
}

// GenerateProviderSpecificPermutations generates provider-specific permutations
func GenerateProviderSpecificPermutations(domain string, provider string) []string {
	basePermutations := GenerateNamePermutations(domain)
	permutations := make([]string, len(basePermutations))
	copy(permutations, basePermutations)

	// Extract domain name without TLD
	parts := strings.Split(domain, ".")
	name := parts[0]

	// For domains like sub.example.com, use example as the name
	if len(parts) > 2 {
		name = parts[len(parts)-2]
	}

	tld := ""
	if len(parts) > 1 {
		tld = parts[len(parts)-1]
	}

	// Remove special characters from domain name
	domainName := strings.ReplaceAll(domain, ".", "")

	// Add provider-specific patterns
	if providerPatterns, ok := CloudProviderPatterns[provider]; ok {
		for _, pattern := range providerPatterns {
			p := pattern
			p = strings.ReplaceAll(p, "{domain}", domain)
			p = strings.ReplaceAll(p, "{domainname}", domainName)
			p = strings.ReplaceAll(p, "{name}", name)
			p = strings.ReplaceAll(p, "{tld}", tld)
			permutations = append(permutations, p)
		}
	}

	return permutations
}
