package harbor

import (
	"bytes"
	"encoding/json"
	"time"
)

// Severity represents the severity of a vulnerability.
type Severity int64

const (
	_ Severity = iota
	SevUnknown
	SevNegligible
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return severityToString[s]
}

var severityToString = map[Severity]string{
	SevUnknown:    "Unknown",
	SevNegligible: "Negligible",
	SevLow:        "Low",
	SevMedium:     "Medium",
	SevHigh:       "High",
	SevCritical:   "Critical",
}

var StringToSeverity = map[string]Severity{
	"Unknown":    SevUnknown,
	"Negligible": SevNegligible,
	"Low":        SevLow,
	"Medium":     SevMedium,
	"High":       SevHigh,
	"Critical":   SevCritical,
}

func (s Severity) MarshalJSON() ([]byte, error) {
	str, ok := severityToString[s]
	if !ok || str == "" {
		str = "Unknown"
	}
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(str)
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (s *Severity) UnmarshalJSON(b []byte) error {
	var value string
	err := json.Unmarshal(b, &value)
	if err != nil {
		return err
	}
	*s = StringToSeverity[value]
	return nil
}

// Registry represents a Docker Registry.
type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

// Artifact represents a container image artifact.
type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Tag        string `json:"tag,omitempty"`
	MimeType   string `json:"mime_type,omitempty"`
}

// ScanRequest represents a Harbor scan request.
type ScanRequest struct {
	Registry     Registry     `json:"registry"`
	Artifact     Artifact     `json:"artifact"`
	Capabilities []Capability `json:"enabled_capabilities,omitempty"`
}

// ScanResponse represents a Harbor scan response.
type ScanResponse struct {
	ID string `json:"id"`
}

// ScanReport is the vulnerability report returned to Harbor.
type ScanReport struct {
	GeneratedAt     time.Time           `json:"generated_at"`
	Artifact        Artifact            `json:"artifact"`
	Scanner         Scanner             `json:"scanner"`
	Severity        Severity            `json:"severity,omitempty"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities,omitempty"`
}

// VulnerabilityItem is an individual vulnerability.
type VulnerabilityItem struct {
	ID          string       `json:"id"`
	Pkg         string       `json:"package"`
	Version     string       `json:"version"`
	FixVersion  string       `json:"fix_version,omitempty"`
	Severity    Severity     `json:"severity"`
	Description string       `json:"description"`
	Links       []string     `json:"links"`
	CweIDs      []string     `json:"cwe_ids,omitempty"`
	CVSS        *CVSSDetails `json:"preferred_cvss,omitempty"`
}

// CVSSDetails holds CVSS scoring information.
type CVSSDetails struct {
	ScoreV3  *float32 `json:"score_v3,omitempty"`
	ScoreV2  *float32 `json:"score_v2,omitempty"`
	VectorV3 string   `json:"vector_v3,omitempty"`
	VectorV2 string   `json:"vector_v2,omitempty"`
}

// Scanner describes the scanner implementation.
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// ScannerAdapterMetadata is returned by GET /api/v1/metadata.
type ScannerAdapterMetadata struct {
	Scanner      Scanner            `json:"scanner"`
	Capabilities []ScannerCapability `json:"capabilities"`
	Properties   map[string]string  `json:"properties"`
}

// ScannerCapability describes what the scanner can do.
type ScannerCapability struct {
	Type              string   `json:"type"`
	ConsumesMIMETypes []string `json:"consumes_mime_types"`
	ProducesMIMETypes []string `json:"produces_mime_types"`
}

// Capability represents an enabled capability in a scan request.
type Capability struct {
	Type              string   `json:"type"`
	ProducesMIMETypes []string `json:"produces_mime_types,omitempty"`
}

// ErrorResponse is the standard Harbor error response.
type ErrorResponse struct {
	Err ErrorMessage `json:"error"`
}

// ErrorMessage wraps an error message string.
type ErrorMessage struct {
	Message string `json:"message"`
}
