package scan

import (
	"testing"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/k8s"
)

func TestTransformManifestToReport(t *testing.T) {
	vm := &k8s.VulnerabilityManifest{
		Name:        "test-image-abc123",
		CreatedAt:   time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		ToolName:    "grype",
		ToolVersion: "0.74.0",
		Matches: []k8s.VulnMatch{
			{
				ID:          "CVE-2024-1234",
				Severity:    "Critical",
				Description: "A critical vulnerability in libfoo",
				URLs:        []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
				FixVersions: []string{"1.2.4"},
				FixState:    "fixed",
				PkgName:     "libfoo",
				PkgVersion:  "1.2.3",
				CweIDs:      []string{"CWE-79", "CWE-89"},
				CVSS: []k8s.VulnCVSS{
					{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: 9.8},
				},
			},
			{
				ID:          "CVE-2024-5678",
				Severity:    "Low",
				Description: "A low severity issue in libbar",
				URLs:        []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-5678"},
				FixVersions: nil,
				FixState:    "not-fixed",
				PkgName:     "libbar",
				PkgVersion:  "2.0.0",
			},
		},
	}

	artifact := harbor.Artifact{
		Repository: "library/nginx",
		Digest:     "sha256:abc123",
	}

	report := TransformManifestToReport(vm, artifact)

	// Check scanner info
	if report.Scanner.Name != "Kubescape" {
		t.Errorf("expected scanner name Kubescape, got %s", report.Scanner.Name)
	}
	if report.Scanner.Version != "0.74.0" {
		t.Errorf("expected scanner version 0.74.0, got %s", report.Scanner.Version)
	}

	// Check artifact
	if report.Artifact.Repository != "library/nginx" {
		t.Errorf("expected repository library/nginx, got %s", report.Artifact.Repository)
	}

	// Check vulnerabilities count
	if len(report.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(report.Vulnerabilities))
	}

	// Check first vulnerability
	v1 := report.Vulnerabilities[0]
	if v1.ID != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", v1.ID)
	}
	if v1.Severity != harbor.SevCritical {
		t.Errorf("expected Critical severity, got %s", v1.Severity.String())
	}
	if v1.Pkg != "libfoo" {
		t.Errorf("expected package libfoo, got %s", v1.Pkg)
	}
	if v1.FixVersion != "1.2.4" {
		t.Errorf("expected fix version 1.2.4, got %s", v1.FixVersion)
	}
	if v1.CVSS == nil {
		t.Fatal("expected CVSS details")
	}
	if v1.CVSS.ScoreV3 == nil || *v1.CVSS.ScoreV3 != 9.8 {
		t.Errorf("expected CVSS v3 score 9.8, got %v", v1.CVSS.ScoreV3)
	}
	if got, want := v1.CweIDs, []string{"CWE-79", "CWE-89"}; !equalStrings(got, want) {
		t.Errorf("expected CweIDs %v, got %v", want, got)
	}

	// Second vulnerability has no CWEs — confirm we don't accidentally invent some.
	if len(report.Vulnerabilities[1].CweIDs) != 0 {
		t.Errorf("expected no CweIDs on v2, got %v", report.Vulnerabilities[1].CweIDs)
	}

	// Check second vulnerability
	v2 := report.Vulnerabilities[1]
	if v2.ID != "CVE-2024-5678" {
		t.Errorf("expected CVE-2024-5678, got %s", v2.ID)
	}
	if v2.Severity != harbor.SevLow {
		t.Errorf("expected Low severity, got %s", v2.Severity.String())
	}
	if v2.FixVersion != "" {
		t.Errorf("expected empty fix version, got %s", v2.FixVersion)
	}

	// Check overall severity is Critical (highest)
	if report.Severity != harbor.SevCritical {
		t.Errorf("expected overall severity Critical, got %s", report.Severity.String())
	}
}

func TestTransformManifestToReport_Empty(t *testing.T) {
	vm := &k8s.VulnerabilityManifest{
		Name:        "clean-image",
		CreatedAt:   time.Now(),
		ToolVersion: "0.74.0",
		Matches:     nil,
	}

	report := TransformManifestToReport(vm, harbor.Artifact{Repository: "library/alpine"})

	if len(report.Vulnerabilities) != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", len(report.Vulnerabilities))
	}
	if report.Vulnerabilities == nil {
		t.Error("expected non-nil vulnerabilities slice for JSON serialization")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected harbor.Severity
	}{
		{"Critical", harbor.SevCritical},
		{"CRITICAL", harbor.SevCritical},
		{"High", harbor.SevHigh},
		{"Medium", harbor.SevMedium},
		{"Low", harbor.SevLow},
		{"Negligible", harbor.SevNegligible},
		{"Unknown", harbor.SevUnknown},
		{"", harbor.SevUnknown},
		{"Bogus", harbor.SevUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := mapSeverity(tc.input)
			if got != tc.expected {
				t.Errorf("mapSeverity(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}
