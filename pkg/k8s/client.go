package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// VulnerabilityManifest represents the relevant fields from the
// kubescape/storage VulnerabilityManifest CRD.
// We use our own struct to avoid pulling in the full kubescape/storage
// dependency tree in early development. Once we stabilize, we can
// switch to the generated types from kubescape/storage.
type VulnerabilityManifest struct {
	Name        string
	Namespace   string
	CreatedAt   time.Time
	ToolName    string
	ToolVersion string
	DBVersion   string
	Matches     []VulnMatch
}

// VulnMatch represents a single vulnerability match from the GrypeDocument payload.
type VulnMatch struct {
	ID          string
	Severity    string
	Description string
	DataSource  string
	URLs        []string
	FixVersions []string
	FixState    string
	PkgName     string
	PkgVersion  string
	PkgType     string
	PkgLanguage string
	CVSS        []VulnCVSS
	// CweIDs is the deduplicated list of CWE identifiers associated with this
	// match. Sourced from the top-level vulnerability and any related
	// vulnerabilities in the Grype payload (NVD-derived CWEs typically appear
	// on the relatedVulnerabilities entry rather than on the matched
	// vulnerability itself).
	CweIDs []string
}

// VulnCVSS holds CVSS data from a vulnerability match.
type VulnCVSS struct {
	Version   string
	Vector    string
	BaseScore float64
}

// Client provides access to VulnerabilityManifest CRDs in the cluster.
type Client interface {
	// GetVulnerabilityManifest retrieves a VulnerabilityManifest by name.
	// Returns nil, nil if not found.
	GetVulnerabilityManifest(ctx context.Context, namespace, name string) (*VulnerabilityManifest, error)

	// ListVulnerabilityManifests lists VulnerabilityManifests in a namespace,
	// optionally filtered by label selector.
	ListVulnerabilityManifests(ctx context.Context, namespace, labelSelector string) ([]VulnerabilityManifest, error)
}

const (
	maxDNSSubdomainLength = 253
	imageIDSlugHashLength = 6
	maxImageNameLength    = maxDNSSubdomainLength - imageIDSlugHashLength - 1 // 246
)

// imageToDNSSubdomainReplacer matches kubescape/k8s-interface's replacer exactly.
var imageToDNSSubdomainReplacer = strings.NewReplacer(
	"://", "-",
	":", "-",
	"/", "-",
	"_", "-",
	"@", "-",
)

// ImageSlug generates a K8s-safe resource name from an image reference and digest.
// This is a faithful port of kubescape/k8s-interface/names.ImageInfoToSlug so that
// CRD names produced by kubevuln can be looked up correctly.
//
// Algorithm:
//  1. Sanitize the image string (replace :, /, _, @, :// with -)
//  2. Truncate to maxImageNameLength (246 chars)
//  3. Append the last 6 characters of imageHash
//  4. Lowercase the result
//  5. Validate as DNS subdomain
func ImageSlug(image, imageHash string) string {
	if len(image) == 0 || len(imageHash) < imageIDSlugHashLength {
		return ""
	}

	imageHashStub := imageHash[len(imageHash)-imageIDSlugHashLength:]
	sanitizedImage := imageToDNSSubdomainReplacer.Replace(image)
	if len(sanitizedImage) >= maxImageNameLength {
		sanitizedImage = sanitizedImage[:maxImageNameLength]
	}

	slug := fmt.Sprintf("%s-%s", sanitizedImage, imageHashStub)
	slug = strings.ToLower(slug)

	return slug
}
