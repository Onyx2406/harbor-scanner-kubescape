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
	"strings"
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
// TokenSource returns the current bearer token to use for the next API
// request. RESTClient calls it on every request so that kubelet's
// projected-token rotation is picked up without restart. See issue #30.
type TokenSource func() (string, error)

// FileTokenSource reads a bearer token from disk on every call. Production
// uses this with /var/run/secrets/kubernetes.io/serviceaccount/token, which
// kubelet rewrites periodically.
func FileTokenSource(path string) TokenSource {
	return func() (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading service account token from %s: %w", path, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
}

// StaticTokenSource returns the same token forever. Useful for tests that
// don't need to exercise rotation.
func StaticTokenSource(token string) TokenSource {
	return func() (string, error) { return token, nil }
}

type RESTClient struct {
	baseURL    string
	httpClient *http.Client
	tokenSrc   TokenSource
}

// NewRESTClient creates a Client that reads VulnerabilityManifest CRDs via the K8s API.
//
// baseURL is the Kubernetes API server URL (e.g., https://kubernetes.default.svc).
// tokenSrc supplies a fresh bearer token on every request. In production, use
// FileTokenSource("/var/run/secrets/kubernetes.io/serviceaccount/token") so
// kubelet's projected-token rotation is honored automatically (issue #30);
// pre-#30 we cached the token at startup and silently 401'd after rotation.
//
// The constructor automatically loads the in-cluster CA certificate for TLS
// verification.
func NewRESTClient(baseURL string, tokenSrc TokenSource) *RESTClient {
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
		tokenSrc: tokenSrc,
	}
}

// authorize attaches the freshest bearer token to the request. Callers in
// this package must use this instead of setting Authorization directly so
// rotation (issue #30) takes effect.
func (c *RESTClient) authorize(req *http.Request) error {
	token, err := c.tokenSrc()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
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
	if err := c.authorize(req); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching VulnerabilityManifest: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading VulnerabilityManifest: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		// Narrow 404 handling: only the specific "named object missing"
		// case is benign. A 404 for a missing namespace, an unserved
		// resource path, or a broken aggregator must surface as an error
		// — otherwise GetVulnerabilityManifest silently returns "no scan
		// result yet" and the controller polls until timeout instead of
		// failing fast. See issue #37.
		if isNamedObjectNotFound(body, resource, name) {
			return nil, nil
		}
		return nil, fmt.Errorf("K8s API 404 not for the requested object (likely missing namespace, unserved resource type, or broken path): %s", string(body))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("K8s API returned %d: %s", resp.StatusCode, string(body))
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
	if err := c.authorize(req); err != nil {
		return nil, err
	}
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

// readinessProbeName is GET-d by Ping on the configured namespace. The
// name is intentionally weird so it doesn't collide with a real CRD that
// kubevuln might write.
const readinessProbeName = "harbor-scanner-readiness-probe-does-not-exist"

// Ping verifies that the adapter can actually issue authenticated reads
// against the VulnerabilityManifest resource type — the same capability
// the scan path depends on. Issues GET on a guaranteed-missing CRD in
// `namespace` and treats 200 or 404 as healthy: both prove we reached
// the API server, the token was accepted, and we have read access on
// vulnerabilitymanifests. 401/403 surface as errors so /probe/ready
// flips the pod NotReady; other failures (5xx, network) likewise.
//
// See issue #35 — the previous /version-based probe was misaligned with
// the chart's RBAC and could be both falsely-NotReady on stricter clusters
// and falsely-Ready on permissive ones.
func (c *RESTClient) Ping(ctx context.Context, namespace string) error {
	url := fmt.Sprintf("%s/apis/%s/%s/namespaces/%s/%s/%s",
		c.baseURL, apiGroup, apiVersion, namespace, resource, readinessProbeName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating ping request: %w", err)
	}
	if err := c.authorize(req); err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("k8s ping: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		// Probe CRD exists by that name (extremely unlikely with our
		// chosen name, but means we have read access — healthy).
		return nil
	case http.StatusNotFound:
		// Healthy ONLY when the 404 is the specific "probe object not
		// found" Status. A 404 for a missing namespace or an unserved
		// resource type would falsely keep readiness green even though
		// real scan lookups can't work. See issue #37.
		if isNamedObjectNotFound(body, resource, readinessProbeName) {
			return nil
		}
		return fmt.Errorf("k8s API 404 not for the probe object (likely missing namespace, unserved resource type, or broken path): %s", string(body))
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("k8s API rejected VulnerabilityManifest GET (HTTP %d) — likely token rotation not picked up or RBAC missing", resp.StatusCode)
	default:
		return fmt.Errorf("k8s API ping returned %d: %s", resp.StatusCode, string(body))
	}
}

// isNamedObjectNotFound reports whether the body of a 404 response from
// the K8s API is the specific "named object does not exist" Status — as
// opposed to a path-level 404 (missing namespace, unserved resource type,
// broken aggregator). The named-object case is benign for both the scan
// path and the readiness probe; the others are configuration errors that
// should surface to the caller. See issue #37.
//
// We require all four signals: a Status object body, reason=NotFound,
// details.kind matches the requested resource (so a missing-namespace
// 404 — whose details.kind would be "namespaces" — is rejected), and
// details.name matches the requested object name.
func isNamedObjectNotFound(body []byte, expectedResource, expectedName string) bool {
	var st struct {
		Kind    string `json:"kind"`
		Reason  string `json:"reason"`
		Details struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"details"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		return false
	}
	if st.Kind != "Status" || st.Reason != "NotFound" {
		return false
	}
	if st.Details.Kind != expectedResource {
		return false
	}
	if st.Details.Name != expectedName {
		return false
	}
	return true
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
