package common

// AssetType represents the type of cloud asset discovered
type AssetType string

const (
	// AWS asset types
	AssetTypeS3Bucket       AssetType = "s3_bucket"
	AssetTypeLambdaFunction AssetType = "lambda_function"
	AssetTypeEC2Instance    AssetType = "ec2_instance"

	// Azure asset types
	AssetTypeAzureBlob     AssetType = "azure_blob"
	AssetTypeAzureFunction AssetType = "azure_function"
	AssetTypeAzureVM       AssetType = "azure_vm"

	// GCP asset types
	AssetTypeGCPStorage  AssetType = "gcp_storage"
	AssetTypeGCPFunction AssetType = "gcp_function"
	AssetTypeGCPCompute  AssetType = "gcp_compute"
)

// AccessLevel defines the access level of the discovered asset
type AccessLevel string

const (
	AccessLevelPublic     AccessLevel = "public"
	AccessLevelPrivate    AccessLevel = "private"
	AccessLevelRestricted AccessLevel = "restricted"
	AccessLevelUnknown    AccessLevel = "unknown"
)

// CloudProvider defines the cloud provider
type CloudProvider string

const (
	ProviderAWS   CloudProvider = "aws"
	ProviderAzure CloudProvider = "azure"
	ProviderGCP   CloudProvider = "gcp"
)

// AssetFinding represents a discovered cloud asset
type AssetFinding struct {
	Provider        CloudProvider     `json:"provider"`
	Type            AssetType         `json:"type"`
	Name            string            `json:"name"`
	Region          string            `json:"region"`
	AccessLevel     AccessLevel       `json:"access_level"`
	URL             string            `json:"url"`
	CreationDate    string            `json:"creation_date,omitempty"`
	LastModified    string            `json:"last_modified,omitempty"`
	Size            int64             `json:"size,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	IsVulnerable    bool              `json:"is_vulnerable"`
	VulnDescription string            `json:"vuln_description,omitempty"`
	DiscoveryMethod string            `json:"discovery_method"`
}
