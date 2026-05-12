package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/config"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
)

// TestBuildImageRef_NormalizesReference pins the fix from issue #4: the slug
// we compute on the adapter side must match the one kubevuln computes after
// applying tools.NormalizeReference. For fully-qualified inputs (the common
// Harbor case) this is a no-op; for shortnames it must expand.
func TestBuildImageRef_NormalizesReference(t *testing.T) {
	tests := []struct {
		name     string
		req      harbor.ScanRequest
		expected string
	}{
		{
			name: "fully-qualified Harbor reference is unchanged",
			req: harbor.ScanRequest{
				Registry: harbor.Registry{URL: "https://core.harbor.domain"},
				Artifact: harbor.Artifact{
					Repository: "library/nginx",
					Digest:     "sha256:abcdef0123456789",
				},
			},
			expected: "core.harbor.domain/library/nginx@sha256:abcdef0123456789",
		},
		{
			name: "registry with port preserved",
			req: harbor.ScanRequest{
				Registry: harbor.Registry{URL: "https://myregistry.com:5000"},
				Artifact: harbor.Artifact{
					Repository: "myapp/service",
					Digest:     "sha256:abcdef1234567890",
				},
			},
			expected: "myregistry.com:5000/myapp/service@sha256:abcdef1234567890",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildImageRef(tc.req)
			if got != tc.expected {
				t.Errorf("BuildImageRef = %q, want %q", got, tc.expected)
			}
		})
	}
}

// TestNormalizeImageRef_ExpandsShortnames covers the scenario the issue
// flags as broken: if anything ever feeds a docker.io shortname into the
// path, kubevuln expands it to index.docker.io/library/... and our slug
// must match.
func TestNormalizeImageRef_ExpandsShortnames(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "docker.io shortname expands to index.docker.io/library",
			input:    "nginx:latest",
			expected: "index.docker.io/library/nginx:latest",
		},
		{
			name:     "user/repo shortname expands to index.docker.io",
			input:    "bitnami/redis:7.0",
			expected: "index.docker.io/bitnami/redis:7.0",
		},
		{
			name:     "fully qualified reference is a no-op",
			input:    "core.harbor.domain/library/nginx@sha256:abc123",
			expected: "core.harbor.domain/library/nginx@sha256:abc123",
		},
		{
			name:     "registry with port is a no-op",
			input:    "myregistry.com:5000/myapp@sha256:abc123",
			expected: "myregistry.com:5000/myapp@sha256:abc123",
		},
		{
			name:     "unparseable input returned unchanged",
			input:    "::not-a-valid-ref::",
			expected: "::not-a-valid-ref::",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeImageRef(tc.input)
			if got != tc.expected {
				t.Errorf("normalizeImageRef(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseRegistryAuth_Basic(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("robot$svc:hunter2"))

	got, err := parseRegistryAuth("Basic " + encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Username != "robot$svc" {
		t.Errorf("username: got %q, want %q", got.Username, "robot$svc")
	}
	if got.Password != "hunter2" {
		t.Errorf("password: got %q, want %q", got.Password, "hunter2")
	}
	if got.RegistryToken != "" {
		t.Errorf("RegistryToken should be empty for Basic auth, got %q", got.RegistryToken)
	}
	if got.Auth != "" {
		t.Errorf("Auth should be empty for Basic auth, got %q", got.Auth)
	}
}

func TestParseRegistryAuth_Bearer(t *testing.T) {
	const token = "eyJhbGciOiJSUzI1NiJ9.payload.sig"

	got, err := parseRegistryAuth("Bearer " + token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Bearer tokens MUST land in RegistryToken — that is the field kubevuln's
	// credential conversion (registryCredentialsFromCredentialsList) actually
	// reads. Putting it in Auth silently drops the token. See issue #51.
	if got.RegistryToken != token {
		t.Errorf("RegistryToken: got %q, want %q", got.RegistryToken, token)
	}
	if got.Auth != "" {
		t.Errorf("Auth must remain empty for Bearer — kubevuln ignores it. got %q", got.Auth)
	}
	if got.Username != "" || got.Password != "" {
		t.Errorf("username/password should be empty for Bearer, got %q/%q", got.Username, got.Password)
	}
}

func TestParseRegistryAuth_InvalidFormat(t *testing.T) {
	cases := []string{
		"",
		"Bearer",
		"NoSpaceHere",
	}
	for _, in := range cases {
		if _, err := parseRegistryAuth(in); err == nil {
			t.Errorf("parseRegistryAuth(%q) expected error, got nil", in)
		}
	}
}

func TestParseRegistryAuth_UnsupportedType(t *testing.T) {
	if _, err := parseRegistryAuth("Digest abc123"); err == nil {
		t.Error("expected error for unsupported auth type, got nil")
	}
}

func TestParseRegistryAuth_BasicMalformed(t *testing.T) {
	// base64 without ':' separator
	bad := base64.StdEncoding.EncodeToString([]byte("notuserpassword"))
	if _, err := parseRegistryAuth("Basic " + bad); err == nil {
		t.Error("expected error for basic auth without colon, got nil")
	}
	// invalid base64
	if _, err := parseRegistryAuth("Basic !!!not-base64!!!"); err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

// JSON tag for RegistryToken must match docker's registry.AuthConfig
// (`registrytoken`) so kubevuln's json.Unmarshal lands the value on the
// RegistryToken field its credential conversion reads.
func TestKubevulnRegistryAuth_JSONFieldNames(t *testing.T) {
	auth := kubevulnRegistryAuth{
		Username:      "u",
		Password:      "p",
		Auth:          "a",
		ServerAddress: "registry.example.com",
		RegistryToken: "tok",
	}

	out, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]string
	if err := json.Unmarshal(out, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if generic["registrytoken"] != "tok" {
		t.Errorf("expected JSON key registrytoken=tok, got %v", generic)
	}
	if generic["serveraddress"] != "registry.example.com" {
		t.Errorf("expected JSON key serveraddress, got %v", generic)
	}
}

// captureRequest spins up an httptest server that records the kubevuln scan
// payload, so we can assert the wire format end-to-end.
func captureRequest(t *testing.T) (*httptest.Server, func() *kubevulnScanRequest) {
	t.Helper()
	var captured kubevulnScanRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/scanImage" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() *kubevulnScanRequest { return &captured }
}

func TestTriggerScan_BasicAuth_ForwardsUsernamePassword(t *testing.T) {
	srv, getCaptured := captureRequest(t)

	encoded := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	scanner := NewScanner(config.KubevulnConfig{URL: srv.URL, Namespace: "kubescape"})

	err := scanner.TriggerScan(context.Background(), harbor.ScanRequest{
		Registry: harbor.Registry{
			URL:           "https://registry.example.com",
			Authorization: "Basic " + encoded,
		},
		Artifact: harbor.Artifact{
			Repository: "library/nginx",
			Digest:     "sha256:abc",
		},
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	got := getCaptured()
	if len(got.CredentialsList) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(got.CredentialsList))
	}
	c := got.CredentialsList[0]
	if c.Username != "alice" || c.Password != "s3cret" {
		t.Errorf("got user/pass %q/%q, want alice/s3cret", c.Username, c.Password)
	}
	if c.RegistryToken != "" {
		t.Errorf("RegistryToken should be empty for Basic, got %q", c.RegistryToken)
	}
	if c.ServerAddress != "registry.example.com" {
		t.Errorf("ServerAddress: got %q, want registry.example.com", c.ServerAddress)
	}
}

func TestTriggerScan_BearerAuth_ForwardsRegistryToken(t *testing.T) {
	srv, getCaptured := captureRequest(t)

	const token = "harbor-issued-bearer-token-abc.def.ghi"
	scanner := NewScanner(config.KubevulnConfig{URL: srv.URL, Namespace: "kubescape"})

	err := scanner.TriggerScan(context.Background(), harbor.ScanRequest{
		Registry: harbor.Registry{
			URL:           "https://registry.example.com",
			Authorization: "Bearer " + token,
		},
		Artifact: harbor.Artifact{
			Repository: "library/nginx",
			Digest:     "sha256:def",
		},
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	got := getCaptured()
	if len(got.CredentialsList) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(got.CredentialsList))
	}
	c := got.CredentialsList[0]
	if c.RegistryToken != token {
		t.Errorf("RegistryToken: got %q, want %q", c.RegistryToken, token)
	}
	if c.Auth != "" {
		t.Errorf("Auth must be empty so kubevuln does not silently drop the token, got %q", c.Auth)
	}
	if c.Username != "" || c.Password != "" {
		t.Errorf("Bearer must not set user/pass, got %q/%q", c.Username, c.Password)
	}
	if c.ServerAddress != "registry.example.com" {
		t.Errorf("ServerAddress: got %q, want registry.example.com", c.ServerAddress)
	}

	// Also assert the raw JSON wire format includes registrytoken — a refactor
	// that drops the json tag would make kubevuln silently ignore the token.
	body, _ := json.Marshal(got)
	if !strings.Contains(string(body), `"registrytoken":"`+token+`"`) {
		t.Errorf("expected JSON to contain registrytoken field with token, got: %s", body)
	}
}

func TestTriggerScan_NoAuth_OmitsCredentials(t *testing.T) {
	srv, getCaptured := captureRequest(t)

	scanner := NewScanner(config.KubevulnConfig{URL: srv.URL, Namespace: "kubescape"})

	err := scanner.TriggerScan(context.Background(), harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://registry.example.com"},
		Artifact: harbor.Artifact{
			Repository: "library/alpine",
			Digest:     "sha256:000",
		},
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	got := getCaptured()
	if len(got.CredentialsList) != 0 {
		t.Errorf("expected no credentials, got %d", len(got.CredentialsList))
	}
}
