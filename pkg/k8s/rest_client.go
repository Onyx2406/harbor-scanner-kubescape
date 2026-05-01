package k8s

import (
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
)

// RESTClient implements Client by calling the Kubernetes API directly via REST.
// This avoids pulling in client-go and kubescape/storage as compile-time dependencies
// while still reading VulnerabilityManifest CRDs. For production use, replace with
// the generated clientset from kubescape/storage.
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

// crdResponse is the JSON structure of a VulnerabilityManifest CRD from the K8s API.
type crdResponse struct {
	Metadata struct {
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		CreationTimestamp string            `json:"creationTimestamp"`
		Annotations       map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Metadata struct {
			Tool struct {
				Name            string `json:"name"`
				Version         string `json:"version"`
				DatabaseVersion string `json:"databaseVersion"`
			} `json:"tool"`
			Report struct {
				CreatedAt string `json:"createdAt"`
			} `json:"report"`
		} `json:"metadata"`
		Payload struct {
			Matches []crdMatch `json:"matches"`
		} `json:"payload"`
	} `json:"spec"`
}

type crdCvss struct {
	Version string `json:"version"`
	Vector  string `json:"vector"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

type crdRelatedVulnerability struct {
	ID         string   `json:"id"`
	DataSource string   `json:"dataSource"`
	Namespace  string   `json:"namespace"`
	Cwes       []string `json:"cwes"`
}

type crdMatch struct {
	Vulnerability struct {
		ID          string    `json:"id"`
		DataSource  string    `json:"dataSource"`
		Severity    string    `json:"severity"`
		URLs        []string  `json:"urls"`
		Description string    `json:"description"`
		Cvss        []crdCvss `json:"cvss"`
		Fix         struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
		// Some Grype vulnerabilities carry CWEs directly; most NVD-derived
		// CWEs live on relatedVulnerabilities below. Both are captured.
		Cwes []string `json:"cwes"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []crdRelatedVulnerability `json:"relatedVulnerabilities"`
	Artifact               struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Type     string `json:"type"`
		Language string `json:"language"`
	} `json:"artifact"`
}

type crdListResponse struct {
	Items []crdResponse `json:"items"`
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

	var crd crdResponse
	if err := json.NewDecoder(resp.Body).Decode(&crd); err != nil {
		return nil, fmt.Errorf("decoding VulnerabilityManifest: %w", err)
	}

	return crdToManifest(crd), nil
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

	var list crdListResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("decoding VulnerabilityManifest list: %w", err)
	}

	var result []VulnerabilityManifest
	for _, item := range list.Items {
		result = append(result, *crdToManifest(item))
	}
	return result, nil
}

func crdToManifest(crd crdResponse) *VulnerabilityManifest {
	createdAt, err := time.Parse(time.RFC3339, crd.Metadata.CreationTimestamp)
	if err != nil {
		slog.Warn("Failed to parse createdAt", "err", err)
	}

	vm := &VulnerabilityManifest{
		Name:        crd.Metadata.Name,
		Namespace:   crd.Metadata.Namespace,
		CreatedAt:   createdAt,
		ToolName:    crd.Spec.Metadata.Tool.Name,
		ToolVersion: crd.Spec.Metadata.Tool.Version,
		DBVersion:   crd.Spec.Metadata.Tool.DatabaseVersion,
	}

	for _, m := range crd.Spec.Payload.Matches {
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
			PkgType:     m.Artifact.Type,
			PkgLanguage: m.Artifact.Language,
			CweIDs:      collectCweIDs(m),
		}
		for _, c := range m.Vulnerability.Cvss {
			match.CVSS = append(match.CVSS, VulnCVSS{
				Version:   c.Version,
				Vector:    c.Vector,
				BaseScore: c.Metrics.BaseScore,
			})
		}
		vm.Matches = append(vm.Matches, match)
	}

	return vm
}

// collectCweIDs returns the union (preserving first-seen order) of CWE IDs on
// the matched vulnerability and on each related vulnerability. Returns nil
// when no CWEs are present so the harbor.VulnerabilityItem.CweIDs JSON tag
// (omitempty) drops the field cleanly.
func collectCweIDs(m crdMatch) []string {
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
