package scan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/config"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/k8s"
	"github.com/google/go-containerregistry/pkg/name"
)

// Scanner interfaces with kubevuln to perform image vulnerability scanning.
type Scanner interface {
	// TriggerScan sends a scan request to kubevuln's ScanCVE endpoint.
	// kubevuln returns immediately (async). Results appear in VulnerabilityManifest CRDs.
	TriggerScan(ctx context.Context, req harbor.ScanRequest) error
}

type kubevulnScanner struct {
	kubevulnURL string
	namespace   string
	httpClient  *http.Client
}

// NewScanner creates a scanner that delegates to kubevuln's CVE scanning endpoint.
func NewScanner(cfg config.KubevulnConfig) Scanner {
	return &kubevulnScanner{
		kubevulnURL: strings.TrimRight(cfg.URL, "/"),
		namespace:   cfg.Namespace,
		httpClient: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}
}

// kubevulnScanRequest is the WebsocketScanCommand-compatible request for kubevuln.
type kubevulnScanRequest struct {
	ImageTag        string                 `json:"imageTag"`
	ImageHash       string                 `json:"imageHash"`
	Wlid            string                 `json:"wlid,omitempty"`
	JobID           string                 `json:"jobID,omitempty"`
	CredentialsList []kubevulnRegistryAuth `json:"credentialsList,omitempty"`
	Args            map[string]interface{} `json:"args,omitempty"`
}

type kubevulnRegistryAuth struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Auth          string `json:"auth,omitempty"`
	ServerAddress string `json:"serveraddress,omitempty"`
}

func (s *kubevulnScanner) TriggerScan(ctx context.Context, req harbor.ScanRequest) error {
	imageRef := BuildImageRef(req)

	slog.Info("Triggering scan via kubevuln",
		slog.String("image", imageRef),
		slog.String("kubevuln_url", s.kubevulnURL),
	)

	scanReq := kubevulnScanRequest{
		ImageTag:  imageRef,
		ImageHash: req.Artifact.Digest,
		Args: map[string]interface{}{
			"name":      req.Artifact.Repository,
			"namespace": s.namespace,
		},
	}

	// Parse registry credentials from Harbor's authorization header
	if req.Registry.Authorization != "" {
		creds, err := parseRegistryAuth(req.Registry.Authorization)
		if err != nil {
			slog.Warn("Failed to parse registry auth", slog.String("err", err.Error()))
		} else {
			registryURL, _ := url.Parse(req.Registry.URL)
			creds.ServerAddress = registryURL.Host
			scanReq.CredentialsList = []kubevulnRegistryAuth{creds}
		}
	}

	body, err := json.Marshal(scanReq)
	if err != nil {
		return fmt.Errorf("marshalling kubevuln request: %w", err)
	}

	// POST to kubevuln's container scan endpoint
	// kubevuln route: /v1/scanImage (apis.ContainerScanCommandPath)
	scanURL := fmt.Sprintf("%s/v1/scanImage", s.kubevulnURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, scanURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating kubevuln request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("calling kubevuln: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("kubevuln returned %d: %s", resp.StatusCode, string(respBody))
	}

	slog.Info("Kubevuln scan request accepted", slog.String("image", imageRef))
	return nil
}

// BuildImageRef constructs a full image reference from a Harbor scan request,
// then applies the same normalization that kubevuln applies before computing
// VulnerabilityManifest CRD names. Without this, shortname inputs (e.g.
// docker.io/nginx:latest, or any reference that go-containerregistry
// rewrites) would produce a different slug here than in kubevuln, and the
// CRD lookup would never resolve. See issue #4.
func BuildImageRef(req harbor.ScanRequest) string {
	raw := buildRawImageRef(req)
	return normalizeImageRef(raw)
}

func buildRawImageRef(req harbor.ScanRequest) string {
	registryURL, err := url.Parse(req.Registry.URL)
	if err != nil {
		return fmt.Sprintf("%s@%s", req.Artifact.Repository, req.Artifact.Digest)
	}
	host := registryURL.Host
	return fmt.Sprintf("%s/%s@%s", host, req.Artifact.Repository, req.Artifact.Digest)
}

// normalizeImageRef mirrors kubevuln's tools.NormalizeReference: parse the
// input via go-containerregistry's name package and return its canonical
// Name(). For fully-qualified Harbor inputs this is a no-op; for shortnames
// it expands to the canonical docker.io form. If parsing fails we return the
// input unchanged so we never break a working slug computation.
func normalizeImageRef(ref string) string {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return ref
	}
	return parsed.Name()
}

// ImageSlugForRequest generates the VulnerabilityManifest CRD name for a Harbor scan request.
func ImageSlugForRequest(req harbor.ScanRequest) string {
	imageRef := BuildImageRef(req)
	return k8s.ImageSlug(imageRef, req.Artifact.Digest)
}

func parseRegistryAuth(authorization string) (kubevulnRegistryAuth, error) {
	tokens := strings.SplitN(authorization, " ", 2)
	if len(tokens) != 2 {
		return kubevulnRegistryAuth{}, fmt.Errorf("invalid authorization format")
	}

	switch tokens[0] {
	case "Basic":
		decoded, err := base64.StdEncoding.DecodeString(tokens[1])
		if err != nil {
			return kubevulnRegistryAuth{}, fmt.Errorf("decoding basic auth: %w", err)
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return kubevulnRegistryAuth{}, fmt.Errorf("invalid basic auth format")
		}
		return kubevulnRegistryAuth{
			Username: parts[0],
			Password: parts[1],
		}, nil
	case "Bearer":
		return kubevulnRegistryAuth{
			Auth: tokens[1],
		}, nil
	default:
		return kubevulnRegistryAuth{}, fmt.Errorf("unsupported auth type: %s", tokens[0])
	}
}
