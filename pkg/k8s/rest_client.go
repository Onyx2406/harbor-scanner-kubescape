package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"time"

	v1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// RESTClient implements Client by calling the Kubernetes API directly via REST.
//
// We deliberately avoid client-go to keep the binary lean. We do, however,
// import the canonical v1beta1.VulnerabilityManifest types from
// github.com/kubescape/storage and decode the API response into them. That
// makes any schema drift between this adapter and kubescape — renamed
// fields, type changes — a compile-time failure in the converter below
// rather than silent data loss. See issue #3.
//
// CWE IDs are not (yet) part of the canonical v1beta1.VulnerabilityMetadata
// schema in kubescape/storage, but kubevuln/Grype payloads do carry them.
// We parse them out via a tiny overlay decode against the raw response
// body. See issue #5.
type RESTClient struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// NewRESTClient creates a Client that reads VulnerabilityManifest CRDs via the K8s API.
// baseURL is the Kubernetes API server URL (e.g., https://kubernetes.default.svc).
// token is a ServiceAccount bearer token.
// It automatically loads the in-cluster CA certificate for TLS verification.
func NewRESTClient(baseURL, token string) *RESTClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	// Load in-cluster CA cert for TLS verification against the K8s API server.
	const caCertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	if caCert, err := os.ReadFile(caCertPath); err == nil {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		transport.TLSClientConfig = &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		}
	} else {
		slog.Warn("Failed to load in-cluster CA cert, using system roots",
			slog.String("path", caCertPath),
			slog.String("err", err.Error()),
		)
	}

	return &RESTClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		token: token,
	}
}

const (
	apiGroup   = "spdx.softwarecomposition.kubescape.io"
	apiVersion = "v1beta1"
	resource   = "vulnerabilitymanifests"
)

// cweOverlay captures CWE-related fields the canonical v1beta1 type does not
// (yet) carry. It is decoded from the same response body as the canonical
// type and merged in by index, so when kubescape/storage adds Cwes to its
// VulnerabilityMetadata we can drop this overlay in favor of the canonical
// field with no behavior change.
type cweOverlay struct {
	Spec struct {
		Payload struct {
			Matches []cweOverlayMatch `json:"matches"`
		} `json:"payload"`
	} `json:"spec"`
}

type cweOverlayMatch struct {
	Vulnerability struct {
		Cwes []string `json:"cwes"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []struct {
		Cwes []string `json:"cwes"`
	} `json:"relatedVulnerabilities"`
}

func (c *RESTClient) GetVulnerabilityManifest(ctx context.Context, namespace, name string) (*VulnerabilityManifest, error) {
	url := fmt.Sprintf("%s/apis/%s/%s/namespaces/%s/%s/%s",
		c.baseURL, apiGroup, apiVersion, namespace, resource, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching VulnerabilityManifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("K8s API returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading VulnerabilityManifest: %w", err)
	}

	var crd v1beta1.VulnerabilityManifest
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&crd); err != nil {
		return nil, fmt.Errorf("decoding VulnerabilityManifest: %w", err)
	}

	vm := canonicalToManifest(&crd)
	applyCweOverlay(body, vm)
	return vm, nil
}

func (c *RESTClient) ListVulnerabilityManifests(ctx context.Context, namespace, labelSelector string) ([]VulnerabilityManifest, error) {
	url := fmt.Sprintf("%s/apis/%s/%s/namespaces/%s/%s",
		c.baseURL, apiGroup, apiVersion, namespace, resource)
	if labelSelector != "" {
		url += "?labelSelector=" + neturl.QueryEscape(labelSelector)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing VulnerabilityManifests: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("K8s API returned %d: %s", resp.StatusCode, string(body))
	}

	var list v1beta1.VulnerabilityManifestList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("decoding VulnerabilityManifest list: %w", err)
	}

	result := make([]VulnerabilityManifest, 0, len(list.Items))
	for i := range list.Items {
		result = append(result, *canonicalToManifest(&list.Items[i]))
	}
	return result, nil
}

// canonicalToManifest converts the kubescape/storage v1beta1 type into the
// internal shape the transformer consumes. This is the choke point for
// schema drift: any rename or type change in v1beta1 fields we read here
// will fail the compile, not silently zero out a field.
func canonicalToManifest(crd *v1beta1.VulnerabilityManifest) *VulnerabilityManifest {
	createdAt := crd.CreationTimestamp.Time
	if reportTime := crd.Spec.Metadata.Report.CreatedAt.Time; !reportTime.IsZero() {
		createdAt = reportTime
	}

	vm := &VulnerabilityManifest{
		Name:        crd.Name,
		Namespace:   crd.Namespace,
		CreatedAt:   createdAt,
		ToolName:    crd.Spec.Metadata.Tool.Name,
		ToolVersion: crd.Spec.Metadata.Tool.Version,
	}

	for i := range crd.Spec.Payload.Matches {
		vm.Matches = append(vm.Matches, canonicalMatchToVulnMatch(&crd.Spec.Payload.Matches[i]))
	}
	return vm
}

func canonicalMatchToVulnMatch(m *v1beta1.Match) VulnMatch {
	match := VulnMatch{
		ID:          m.Vulnerability.ID,
		Severity:    m.Vulnerability.Severity,
		Description: m.Vulnerability.Description,
		DataSource:  m.Vulnerability.DataSource,
		URLs:        m.Vulnerability.URLs,
		FixVersions: m.Vulnerability.Fix.Versions,
		FixState:    m.Vulnerability.Fix.State,
		PkgName:     m.Artifact.Name,
		PkgVersion:  m.Artifact.Version,
		PkgType:     string(m.Artifact.Type),
		PkgLanguage: string(m.Artifact.Language),
	}
	for _, c := range m.Vulnerability.Cvss {
		match.CVSS = append(match.CVSS, VulnCVSS{
			Version:   c.Version,
			Vector:    c.Vector,
			BaseScore: c.Metrics.BaseScore,
		})
	}
	return match
}

// applyCweOverlay decodes CWE arrays from the raw response body and merges
// them onto vm.Matches by index. Failure to decode is non-fatal — the
// canonical fields are already populated and CWEs are an enrichment.
func applyCweOverlay(body []byte, vm *VulnerabilityManifest) {
	if vm == nil {
		return
	}
	var overlay cweOverlay
	if err := json.Unmarshal(body, &overlay); err != nil {
		return
	}
	n := len(overlay.Spec.Payload.Matches)
	if n > len(vm.Matches) {
		n = len(vm.Matches)
	}
	for i := 0; i < n; i++ {
		vm.Matches[i].CweIDs = unionCwes(overlay.Spec.Payload.Matches[i])
	}
}

// unionCwes returns the deduplicated union (first-seen order) of CWE IDs on
// the matched vulnerability and on each related vulnerability. Returns nil
// when no CWEs are present so the harbor.VulnerabilityItem.CweIDs JSON tag
// (omitempty) drops the field cleanly.
func unionCwes(m cweOverlayMatch) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(ids []string) {
		for _, id := range ids {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}

	add(m.Vulnerability.Cwes)
	for _, rv := range m.RelatedVulnerabilities {
		add(rv.Cwes)
	}
	return out
}
