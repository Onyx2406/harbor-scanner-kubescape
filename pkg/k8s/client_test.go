package k8s

import (
	"strings"
	"testing"
)

func TestImageSlug(t *testing.T) {
	tests := []struct {
		name      string
		image     string
		imageHash string
		want      string
	}{
		{
			name:      "standard docker image with sha256 digest",
			image:     "docker.io/library/nginx:1.25",
			imageHash: "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
			want:      "docker.io-library-nginx-1.25-709b3b",
		},
		{
			name:      "image with registry port",
			image:     "myregistry.com:5000/myapp/service:v2.1",
			imageHash: "sha256:abcdef1234567890",
			want:      "myregistry.com-5000-myapp-service-v2.1-567890",
		},
		{
			name:      "image with digest reference",
			image:     "core.harbor.domain/scanners/mysql@sha256:3b00a364fb74246c",
			imageHash: "sha256:3b00a364fb74246c",
			want:      "core.harbor.domain-scanners-mysql-sha256-3b00a364fb74246c-74246c",
		},
		{
			name:      "empty image",
			image:     "",
			imageHash: "sha256:abc123",
			want:      "",
		},
		{
			name:      "hash too short",
			image:     "nginx",
			imageHash: "abc",
			want:      "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ImageSlug(tc.image, tc.imageHash)
			if got != tc.want {
				t.Errorf("ImageSlug(%q, %q) = %q, want %q", tc.image, tc.imageHash, got, tc.want)
			}
		})
	}
}

func TestImageSlug_DNSCompliant(t *testing.T) {
	slug := ImageSlug("docker.io/library/nginx:latest", "sha256:abcdef1234567890abcdef")
	if slug == "" {
		t.Fatal("expected non-empty slug")
	}
	if len(slug) > 253 {
		t.Errorf("slug exceeds DNS subdomain max length: %d", len(slug))
	}
	if slug != strings.ToLower(slug) {
		t.Errorf("slug is not lowercase: %s", slug)
	}
}

func TestImageSlug_LongImage(t *testing.T) {
	// Image name longer than 246 chars should be truncated
	longImage := "registry.example.com/" + strings.Repeat("a", 250) + ":latest"
	hash := "sha256:abcdef1234567890"
	slug := ImageSlug(longImage, hash)

	if len(slug) > 253 {
		t.Errorf("slug exceeds max length: %d", len(slug))
	}
	if !strings.HasSuffix(slug, "567890") {
		t.Errorf("slug should end with hash stub, got: %s", slug)
	}
}
