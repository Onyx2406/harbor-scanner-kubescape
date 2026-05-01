package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/k8s"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence/memory"
)

// fakeK8sClient is a minimal in-memory k8s.Client for testing the controller.
// GetVulnerabilityManifest returns the seeded manifest (or nil to simulate not
// found). TriggerCount is incremented every time the controller asks the
// scanner to run, which lets tests assert reuse vs rescan decisions.
type fakeK8sClient struct {
	manifest *k8s.VulnerabilityManifest
}

func (f *fakeK8sClient) GetVulnerabilityManifest(_ context.Context, _, _ string) (*k8s.VulnerabilityManifest, error) {
	return f.manifest, nil
}

func (f *fakeK8sClient) ListVulnerabilityManifests(_ context.Context, _, _ string) ([]k8s.VulnerabilityManifest, error) {
	return nil, nil
}

// fakeScanner increments triggers on every call.
type fakeScanner struct {
	triggers int
}

func (f *fakeScanner) TriggerScan(_ context.Context, _ harbor.ScanRequest) error {
	f.triggers++
	return nil
}

// TestScan_NoK8sClient_ReturnsError pins the security-relevant fix from #6:
// when the k8s client is nil the controller must error rather than silently
// store a placeholder zero-vulnerability report. Otherwise Harbor would mark
// the image clean even though the scan never ran.
func TestScan_NoK8sClient_ReturnsError(t *testing.T) {
	store := memory.NewStore()
	ctx := context.Background()

	job := persistence.ScanJob{
		ID: "job-no-k8s",
		Request: harbor.ScanRequest{
			Registry: harbor.Registry{URL: "https://registry.example.com"},
			Artifact: harbor.Artifact{
				Repository: "library/nginx",
				Digest:     "sha256:abcdef0123456789",
			},
		},
		Status: persistence.Queued,
	}
	if err := store.Create(ctx, job); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// k8sClient explicitly nil; scanner is also nil because we should error
	// before reaching it.
	c := NewController(store, nil, nil, "kubescape", DefaultReuseTTL)

	err := c.Scan(ctx, job.ID)
	if err == nil {
		t.Fatal("expected error when k8sClient is nil, got nil (Harbor would receive a false-clean report)")
	}
	if !errors.Is(err, ErrK8sUnavailable) {
		t.Errorf("expected ErrK8sUnavailable, got %v", err)
	}

	got, err := store.Get(ctx, job.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != persistence.Failed {
		t.Errorf("expected job status Failed, got %s", got.Status)
	}
	if got.Error == "" {
		t.Errorf("expected job.Error to be populated with the failure reason")
	}
	if len(got.Report.Vulnerabilities) > 0 {
		t.Errorf("expected no report on failure, got %d vulnerabilities", len(got.Report.Vulnerabilities))
	}
}

// TestCanReuse covers issue #14: an existing VulnerabilityManifest is
// reusable iff it is younger than reuseTTL, regardless of whether it has
// matches. A zero TTL disables reuse outright; a zero CreatedAt is treated
// as stale (we won't reuse a manifest of unknown age).
func TestCanReuse(t *testing.T) {
	fixedNow := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return fixedNow }
	t.Cleanup(func() { now = time.Now })

	tests := []struct {
		name      string
		ttl       time.Duration
		createdAt time.Time
		want      bool
	}{
		{
			name:      "fresh manifest within TTL is reusable",
			ttl:       24 * time.Hour,
			createdAt: fixedNow.Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "stale manifest beyond TTL is not reusable",
			ttl:       24 * time.Hour,
			createdAt: fixedNow.Add(-25 * time.Hour),
			want:      false,
		},
		{
			name:      "TTL boundary: exactly TTL old is not reusable",
			ttl:       24 * time.Hour,
			createdAt: fixedNow.Add(-24 * time.Hour),
			want:      false,
		},
		{
			name:      "zero TTL disables reuse",
			ttl:       0,
			createdAt: fixedNow.Add(-1 * time.Second),
			want:      false,
		},
		{
			name:      "negative TTL disables reuse",
			ttl:       -1 * time.Hour,
			createdAt: fixedNow.Add(-1 * time.Second),
			want:      false,
		},
		{
			name:      "zero CreatedAt is treated as stale",
			ttl:       24 * time.Hour,
			createdAt: time.Time{},
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &controller{reuseTTL: tc.ttl}
			got := c.canReuse(&k8s.VulnerabilityManifest{CreatedAt: tc.createdAt})
			if got != tc.want {
				t.Errorf("canReuse() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestScan_FreshManifestIsReused pins issue #14: a fresh existing manifest
// (within TTL) must be reused, and the scanner must NOT be triggered.
func TestScan_FreshManifestIsReused(t *testing.T) {
	fixedNow := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return fixedNow }
	t.Cleanup(func() { now = time.Now })

	tests := []struct {
		name    string
		matches []k8s.VulnMatch
	}{
		{
			name: "fresh non-clean manifest is reused",
			matches: []k8s.VulnMatch{
				{ID: "CVE-2024-9999", Severity: "High", PkgName: "libfoo", PkgVersion: "1.0"},
			},
		},
		{
			// This is the symmetry half of #14: clean (zero matches) used
			// to be re-scanned every time. After the fix it must be reused.
			name:    "fresh clean manifest is reused",
			matches: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.NewStore()
			ctx := context.Background()

			job := persistence.ScanJob{
				ID: "job-fresh",
				Request: harbor.ScanRequest{
					Registry: harbor.Registry{URL: "https://core.harbor.domain"},
					Artifact: harbor.Artifact{
						Repository: "library/nginx",
						Digest:     "sha256:abcdef0123456789",
					},
				},
				Status: persistence.Queued,
			}
			if err := store.Create(ctx, job); err != nil {
				t.Fatalf("seed: %v", err)
			}

			fakeK8s := &fakeK8sClient{
				manifest: &k8s.VulnerabilityManifest{
					Name:        "nginx-fresh",
					CreatedAt:   fixedNow.Add(-1 * time.Hour),
					ToolVersion: "0.74.0",
					Matches:     tc.matches,
				},
			}
			scanner := &fakeScanner{}

			c := NewController(store, scanner, fakeK8s, "kubescape", 24*time.Hour)
			if err := c.Scan(ctx, job.ID); err != nil {
				t.Fatalf("Scan: %v", err)
			}

			if scanner.triggers != 0 {
				t.Errorf("scanner triggered %d time(s); fresh manifest must be reused, not rescanned", scanner.triggers)
			}

			got, _ := store.Get(ctx, job.ID)
			if got.Status != persistence.Finished {
				t.Errorf("expected job status Finished, got %s", got.Status)
			}
			if len(got.Report.Vulnerabilities) != len(tc.matches) {
				t.Errorf("expected %d vulnerabilities in report, got %d", len(tc.matches), len(got.Report.Vulnerabilities))
			}
		})
	}
}

// TestScan_StaleManifestTriggersFreshScan confirms canReuse returns false for
// a stale manifest and the controller falls through to TriggerScan. We
// install a fake k8s client whose Get always returns the stale manifest,
// then short-circuit the test by cancelling the context once we observe the
// scanner trigger — we don't try to drive the full poll loop here.
func TestScan_StaleManifestTriggersFreshScan(t *testing.T) {
	fixedNow := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return fixedNow }
	t.Cleanup(func() { now = time.Now })

	store := memory.NewStore()
	ctx, cancel := context.WithCancel(context.Background())

	job := persistence.ScanJob{
		ID: "job-stale",
		Request: harbor.ScanRequest{
			Registry: harbor.Registry{URL: "https://core.harbor.domain"},
			Artifact: harbor.Artifact{
				Repository: "library/nginx",
				Digest:     "sha256:abcdef0123456789",
			},
		},
		Status: persistence.Queued,
	}
	if err := store.Create(ctx, job); err != nil {
		t.Fatalf("seed: %v", err)
	}

	fakeK8s := &fakeK8sClient{
		manifest: &k8s.VulnerabilityManifest{
			Name:      "nginx-stale",
			CreatedAt: fixedNow.Add(-30 * 24 * time.Hour), // 30 days old
			Matches:   []k8s.VulnMatch{{ID: "CVE-2024-1111", Severity: "High"}},
		},
	}
	// As soon as the controller calls TriggerScan we know it took the
	// rescan path; cancel the context so the subsequent poll bails out
	// instead of waiting for the 5s tick.
	scanner := &triggerCancellingScanner{cancel: cancel}

	c := NewController(store, scanner, fakeK8s, "kubescape", 24*time.Hour)
	_ = c.Scan(ctx, job.ID) // expected to fail with context.Canceled after trigger

	if scanner.triggers != 1 {
		t.Errorf("scanner triggered %d time(s); stale manifest must trigger exactly one fresh scan", scanner.triggers)
	}
}

type triggerCancellingScanner struct {
	triggers int
	cancel   context.CancelFunc
}

func (s *triggerCancellingScanner) TriggerScan(_ context.Context, _ harbor.ScanRequest) error {
	s.triggers++
	s.cancel()
	return nil
}
