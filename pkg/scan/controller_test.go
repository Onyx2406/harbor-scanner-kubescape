package scan

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/k8s"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence/memory"
	persistenceredis "github.com/goharbor/harbor-scanner-kubescape/pkg/persistence/redis"
	"github.com/redis/go-redis/v9"
)

// fakeK8sClient is a minimal in-memory k8s.Client for testing the controller.
// GetVulnerabilityManifest returns the current `manifest` field. Tests that
// need the response to change over time can use `getHook` — when set, it is
// invoked on every Get and may mutate `manifest` to simulate kubevuln
// asynchronously overwriting the CRD between polls.
type fakeK8sClient struct {
	manifest *k8s.VulnerabilityManifest
	getCalls int
	getHook  func(callIdx int, f *fakeK8sClient)
}

func (f *fakeK8sClient) GetVulnerabilityManifest(_ context.Context, _, _ string) (*k8s.VulnerabilityManifest, error) {
	f.getCalls++
	if f.getHook != nil {
		f.getHook(f.getCalls, f)
	}
	return f.manifest, nil
}

func (f *fakeK8sClient) ListVulnerabilityManifests(_ context.Context, _, _ string) ([]k8s.VulnerabilityManifest, error) {
	return nil, nil
}

func (f *fakeK8sClient) Ping(_ context.Context, _ string) error { return nil }

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

// TestScan_StaleManifestNotReturnedByPoll pins issue #23: after the
// controller decides an existing CRD is stale and triggers a rescan, the
// poll loop must NOT immediately accept that same stale CRD on the next
// tick. It must wait until kubevuln overwrites it with a strictly-newer
// CreatedAt.
//
// We drive the test with a stateful fake k8s client. Calls 1 (initial
// check) and 2 (first poll tick) return the stale CRD. On call 3, the
// fake mutates its state to simulate kubevuln finishing the scan: the
// manifest now has a fresh CreatedAt. The test asserts the final report
// reflects the fresh data, NOT the stale one.
func TestScan_StaleManifestNotReturnedByPoll(t *testing.T) {
	fixedNow := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return fixedNow }
	t.Cleanup(func() { now = time.Now })

	// Shorten the poll interval so the test finishes quickly.
	pollInterval = 5 * time.Millisecond
	t.Cleanup(func() { pollInterval = 5 * time.Second })

	staleCRD := &k8s.VulnerabilityManifest{
		Name:      "nginx",
		CreatedAt: fixedNow.Add(-30 * 24 * time.Hour),
		Matches:   []k8s.VulnMatch{{ID: "CVE-2024-OLD", Severity: "Low"}},
	}
	freshCRD := &k8s.VulnerabilityManifest{
		Name:      "nginx",
		CreatedAt: fixedNow,
		Matches: []k8s.VulnMatch{
			{ID: "CVE-2024-NEW", Severity: "Critical"},
		},
	}

	fakeK8s := &fakeK8sClient{
		manifest: staleCRD,
		// On the third Get (initial-check + one stale-poll + this one),
		// simulate kubevuln overwriting the CRD with the fresh version.
		getHook: func(callIdx int, f *fakeK8sClient) {
			if callIdx >= 3 {
				f.manifest = freshCRD
			}
		},
	}
	scanner := &fakeScanner{}

	store := memory.NewStore()
	ctx := context.Background()

	job := persistence.ScanJob{
		ID: "job-stale-poll",
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

	c := NewController(store, scanner, fakeK8s, "kubescape", 24*time.Hour)
	if err := c.Scan(ctx, job.ID); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if scanner.triggers != 1 {
		t.Errorf("scanner.triggers = %d, want 1 (stale CRD must trigger exactly one rescan)", scanner.triggers)
	}

	got, _ := store.Get(ctx, job.ID)
	if got.Status != persistence.Finished {
		t.Fatalf("expected status Finished, got %s (job.Error=%q)", got.Status, got.Error)
	}
	if len(got.Report.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability in report, got %d", len(got.Report.Vulnerabilities))
	}
	if got.Report.Vulnerabilities[0].ID != "CVE-2024-NEW" {
		t.Errorf("report contains stale data: got %q, want CVE-2024-NEW. The poll loop accepted the rejected stale CRD instead of waiting for kubevuln to overwrite.",
			got.Report.Vulnerabilities[0].ID)
	}
	// We expect at least 3 Get calls: initial check + at least one stale poll + the fresh one.
	if fakeK8s.getCalls < 3 {
		t.Errorf("expected at least 3 Get calls (init + stale poll + fresh), got %d", fakeK8s.getCalls)
	}
}

// TestPollForResults_ZeroStaleSeenAt confirms that when there is no prior
// stale CRD (staleSeenAt is zero), any non-nil manifest with a non-zero
// CreatedAt is accepted on the first tick — i.e. we don't break the
// fresh-scan path while fixing the stale-rescan path.
func TestPollForResults_ZeroStaleSeenAt(t *testing.T) {
	pollInterval = 5 * time.Millisecond
	t.Cleanup(func() { pollInterval = 5 * time.Second })

	freshCRD := &k8s.VulnerabilityManifest{
		Name:      "nginx",
		CreatedAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		Matches:   []k8s.VulnMatch{{ID: "CVE-2024-NEW", Severity: "High"}},
	}

	fakeK8s := &fakeK8sClient{manifest: freshCRD}
	c := &controller{k8sClient: fakeK8s, namespace: "kubescape"}

	report, err := c.pollForResults(context.Background(), "nginx", harbor.Artifact{}, time.Time{})
	if err != nil {
		t.Fatalf("pollForResults: %v", err)
	}
	if len(report.Vulnerabilities) != 1 || report.Vulnerabilities[0].ID != "CVE-2024-NEW" {
		t.Errorf("expected fresh CVE-2024-NEW in report, got %+v", report.Vulnerabilities)
	}
}

// TestScan_RedisFailedWrite_UsesUncancelledCtx pins issue #29.
//
// Issue #24 cancels the shared scanCtx on graceful shutdown. The controller
// inherits that ctx, sees ctx.Done in pollForResults, returns ctx.Err, and
// the wrapper Scan() must then write Failed status to the store. Before
// this fix the write reused the *same* cancelled ctx — Redis SET would
// race to context.Canceled, the status would stay Pending, and Harbor
// would keep getting 302 polling for a job that's never going to finish.
//
// The test simulates that exact path against a real-ish Redis (miniredis):
// pre-create a job in Redis, hand the controller a cancelled ctx, run
// Scan, then assert the job ends up Failed (not Pending or Queued) when
// read back via a fresh ctx.
func TestScan_RedisFailedWrite_UsesUncancelledCtx(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	store := persistenceredis.NewStore(rdb)
	freshCtx := context.Background()

	job := persistence.ScanJob{
		ID: "job-shutdown",
		Request: harbor.ScanRequest{
			Registry: harbor.Registry{URL: "https://core.harbor.domain"},
			Artifact: harbor.Artifact{
				Repository: "library/nginx",
				Digest:     "sha256:abcdef0123456789",
			},
		},
		Status: persistence.Queued,
	}
	if err := store.Create(freshCtx, job); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// k8sClient nil → controller's scan() returns ErrK8sUnavailable
	// without touching the network. The interesting part is what the
	// wrapper Scan() does afterwards: it MUST write Failed even though
	// the ctx we hand in is already done.
	c := NewController(store, &fakeScanner{}, nil, "kubescape", DefaultReuseTTL)

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	// Run Scan with the already-cancelled ctx, mimicking what happens
	// after main.go's cancelScans() fires on SIGTERM.
	_ = c.Scan(cancelledCtx, job.ID)

	// Read the persisted state with a FRESH ctx — the cancelled one
	// would itself fail the Redis GET. We want to know what was actually
	// written.
	got, err := store.Get(freshCtx, job.ID)
	if err != nil {
		t.Fatalf("post-scan Get: %v", err)
	}
	if got == nil {
		t.Fatal("job missing after Scan; expected Failed status")
	}
	if got.Status != persistence.Failed {
		t.Errorf("status = %s, want Failed — the wrapper used the cancelled ctx and the Redis SET silently failed (issue #29 regression)", got.Status)
	}
	if got.Error == "" {
		t.Errorf("expected job.Error to be populated, got empty string")
	}
}

// fatalErrK8sClient simulates a K8s client that always returns
// k8s.ErrFatalAPIRead — e.g. a cluster where RBAC is misconfigured or
// the namespace is wrong.
type fatalErrK8sClient struct {
	calls int
}

func (f *fatalErrK8sClient) GetVulnerabilityManifest(_ context.Context, _, _ string) (*k8s.VulnerabilityManifest, error) {
	f.calls++
	return nil, fmt.Errorf("test: %w", k8s.ErrFatalAPIRead)
}

func (f *fatalErrK8sClient) ListVulnerabilityManifests(_ context.Context, _, _ string) ([]k8s.VulnerabilityManifest, error) {
	return nil, nil
}

func (f *fatalErrK8sClient) Ping(_ context.Context, _ string) error { return nil }

// TestScan_FatalAPIError_BailsImmediately pins the fail-fast contract on
// k8s.ErrFatalAPIRead: when the initial CRD check returns an unrecoverable
// error (auth rejection, missing namespace, broken path), the controller
// must NOT trigger a kubevuln scan and then poll for 10 minutes against
// a cluster that will never produce a result. It must record Failed
// status immediately.
func TestScan_FatalAPIError_BailsImmediately(t *testing.T) {
	store := memory.NewStore()
	ctx := context.Background()

	job := persistence.ScanJob{
		ID: "job-fatal-init",
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

	fakeK8s := &fatalErrK8sClient{}
	scanner := &fakeScanner{}

	c := NewController(store, scanner, fakeK8s, "kubescape", DefaultReuseTTL)
	err := c.Scan(ctx, job.ID)
	if err == nil {
		t.Fatal("expected Scan to fail with the fatal API error, got nil")
	}
	if !errors.Is(err, k8s.ErrFatalAPIRead) {
		t.Errorf("expected error to wrap k8s.ErrFatalAPIRead, got %v", err)
	}

	// Critically, scanner.TriggerScan must NOT have been called: we should
	// have bailed before kicking off a kubevuln scan we can't observe.
	if scanner.triggers != 0 {
		t.Errorf("scanner.triggers = %d, want 0 — controller must bail before triggering kubevuln on fatal API error", scanner.triggers)
	}

	got, _ := store.Get(ctx, job.ID)
	if got.Status != persistence.Failed {
		t.Errorf("expected status Failed, got %s", got.Status)
	}
}

// TestPollForResults_FatalAPIError_Aborts pins the same fail-fast contract
// for the poll path: if the K8s client starts returning a fatal API error
// during polling (e.g. RBAC revoked mid-scan), the loop must abort
// immediately rather than spam the API for the full pollTimeout.
func TestPollForResults_FatalAPIError_Aborts(t *testing.T) {
	pollInterval = 5 * time.Millisecond
	t.Cleanup(func() { pollInterval = 5 * time.Second })

	fakeK8s := &fatalErrK8sClient{}
	c := &controller{k8sClient: fakeK8s, namespace: "kubescape"}

	_, err := c.pollForResults(context.Background(), "any-name", harbor.Artifact{}, time.Time{})
	if err == nil {
		t.Fatal("expected pollForResults to error, got nil")
	}
	if !errors.Is(err, k8s.ErrFatalAPIRead) {
		t.Errorf("expected error to wrap k8s.ErrFatalAPIRead, got %v", err)
	}
	// Should have bailed within a few ticks, NOT looped for the full
	// pollTimeout. The fakeK8sClient counts; one or two calls is fine,
	// dozens means the abort path didn't fire.
	if fakeK8s.calls > 3 {
		t.Errorf("fakeK8s.calls = %d, want ≤3 — poll loop kept retrying despite fatal error", fakeK8s.calls)
	}
}

// transientThenStaleClient simulates a transient init failure followed by
// the pre-existing stale CRD coming back on subsequent polls, then the
// fresh post-rescan CRD. Pre-fix the freshness gate was wide open in
// this scenario — staleSeenAt stayed zero on init error and the first
// stale-returning poll tick was accepted.
type transientThenStaleClient struct {
	calls   int
	stale   *k8s.VulnerabilityManifest
	fresh   *k8s.VulnerabilityManifest
	freshOn int // call number at which to start returning fresh
	failOn  int // call number that errors transiently (typically 1)
}

func (c *transientThenStaleClient) GetVulnerabilityManifest(_ context.Context, _, _ string) (*k8s.VulnerabilityManifest, error) {
	c.calls++
	if c.calls == c.failOn {
		return nil, fmt.Errorf("transient k8s error: i/o timeout")
	}
	if c.calls >= c.freshOn {
		return c.fresh, nil
	}
	return c.stale, nil
}

func (c *transientThenStaleClient) ListVulnerabilityManifests(_ context.Context, _, _ string) ([]k8s.VulnerabilityManifest, error) {
	return nil, nil
}

func (c *transientThenStaleClient) Ping(_ context.Context, _ string) error { return nil }

// TestScan_TransientInitError_StaleGuardStillHolds pins issue #46.
//
// Pre-fix: when the initial CRD lookup errored transiently, staleSeenAt
// stayed zero. The poll loop's freshness gate was therefore wide open,
// and the very first poll tick that successfully returned the
// pre-existing stale CRD would accept it as the "fresh rescan result."
// Harbor would then receive outdated vulnerability data despite our
// rescan kickoff.
//
// Post-fix: the transient init error sets staleSeenAt to a conservative
// "now() - 1s" floor, so any pre-existing CRD (which has a CreatedAt in
// the past) is rejected by the gate. Only a CRD created strictly after
// the trigger — i.e. the actual rescan output — passes.
func TestScan_TransientInitError_StaleGuardStillHolds(t *testing.T) {
	fixedNow := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return fixedNow }
	t.Cleanup(func() { now = time.Now })

	pollInterval = 5 * time.Millisecond
	t.Cleanup(func() { pollInterval = 5 * time.Second })

	staleCRD := &k8s.VulnerabilityManifest{
		Name:      "nginx-stale",
		CreatedAt: fixedNow.Add(-30 * 24 * time.Hour), // a month old
		Matches:   []k8s.VulnMatch{{ID: "CVE-2024-OLD", Severity: "Low"}},
	}
	freshCRD := &k8s.VulnerabilityManifest{
		Name:      "nginx-fresh",
		CreatedAt: fixedNow.Add(1 * time.Second), // post-trigger
		Matches: []k8s.VulnMatch{
			{ID: "CVE-2024-NEW", Severity: "Critical"},
		},
	}

	fakeK8s := &transientThenStaleClient{
		stale:   staleCRD,
		fresh:   freshCRD,
		failOn:  1, // initial Get errors transiently
		freshOn: 5, // by the 5th call kubevuln has overwritten
	}

	store := memory.NewStore()
	ctx := context.Background()

	job := persistence.ScanJob{
		ID: "job-transient-init",
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

	c := NewController(store, &fakeScanner{}, fakeK8s, "kubescape", DefaultReuseTTL)
	if err := c.Scan(ctx, job.ID); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	got, _ := store.Get(ctx, job.ID)
	if got.Status != persistence.Finished {
		t.Fatalf("expected Finished, got %s (job.Error=%q)", got.Status, got.Error)
	}
	if len(got.Report.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(got.Report.Vulnerabilities))
	}
	// Headline assertion: the report contains CVE-2024-NEW (the
	// post-trigger fresh CRD), NOT CVE-2024-OLD (the stale one that
	// pre-existed and would have been accepted under the pre-fix code).
	if got.Report.Vulnerabilities[0].ID != "CVE-2024-NEW" {
		t.Errorf("report contains stale data: got %q, want CVE-2024-NEW. The transient-init-error path leaked the stale CRD through the freshness guard (issue #46 regression).",
			got.Report.Vulnerabilities[0].ID)
	}
}
