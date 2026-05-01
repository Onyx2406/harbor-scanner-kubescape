package scan

import (
	"testing"

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
