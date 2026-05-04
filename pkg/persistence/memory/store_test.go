package memory

import (
	"context"
	"testing"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
)

// TestCleanup_EvictsTerminalJobsPastRetention pins issue #17: terminal jobs
// older than the retention window must be evicted by the janitor; non-terminal
// jobs and fresh terminal jobs must be preserved.
func TestCleanup_EvictsTerminalJobsPastRetention(t *testing.T) {
	fixedNow := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixedNow }

	s := NewStore(
		WithRetention(1*time.Hour),
		WithCleanupInterval(time.Hour), // long; we drive Cleanup() manually
		WithNow(clock),
	)
	defer s.Close()

	ctx := context.Background()

	// Three jobs: stale-finished, fresh-finished, in-progress.
	mustCreate(t, s, "stale-finished")
	mustCreate(t, s, "fresh-finished")
	mustCreate(t, s, "in-progress")

	// Stale terminal — TerminalAt set to 2h ago, well past 1h retention.
	clock = func() time.Time { return fixedNow.Add(-2 * time.Hour) }
	s.now = clock
	if err := s.UpdateStatus(ctx, "stale-finished", persistence.Finished); err != nil {
		t.Fatalf("UpdateStatus stale: %v", err)
	}

	// Fresh terminal — TerminalAt set "now-1m", well within retention.
	clock = func() time.Time { return fixedNow.Add(-1 * time.Minute) }
	s.now = clock
	if err := s.UpdateStatus(ctx, "fresh-finished", persistence.Failed, "transient error"); err != nil {
		t.Fatalf("UpdateStatus fresh: %v", err)
	}

	// in-progress is left as Queued (no UpdateStatus call) so TerminalAt is zero.

	// Restore the clock to "now" for the eviction pass.
	clock = func() time.Time { return fixedNow }
	s.now = clock

	if want, got := 3, s.Len(); got != want {
		t.Fatalf("seed expected %d jobs, got %d", want, got)
	}

	evicted := s.Cleanup()
	if evicted != 1 {
		t.Errorf("expected 1 eviction, got %d", evicted)
	}

	// Stale-finished is gone; the others remain.
	if got, _ := s.Get(ctx, "stale-finished"); got != nil {
		t.Errorf("stale-finished should have been evicted, got %+v", got)
	}
	if got, _ := s.Get(ctx, "fresh-finished"); got == nil {
		t.Errorf("fresh-finished should still be present")
	}
	if got, _ := s.Get(ctx, "in-progress"); got == nil {
		t.Errorf("in-progress should still be present (TerminalAt is zero)")
	}
}

// TestUpdateStatus_SetsTerminalAt confirms the timestamp is set on Finished
// and Failed transitions but stays zero for non-terminal transitions.
func TestUpdateStatus_SetsTerminalAt(t *testing.T) {
	fixedNow := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s := NewStore(WithNow(func() time.Time { return fixedNow }))
	defer s.Close()
	ctx := context.Background()

	mustCreate(t, s, "job1")
	mustCreate(t, s, "job2")
	mustCreate(t, s, "job3")

	if err := s.UpdateStatus(ctx, "job1", persistence.Pending); err != nil {
		t.Fatalf("Pending: %v", err)
	}
	got, _ := s.Get(ctx, "job1")
	if !got.TerminalAt.IsZero() {
		t.Errorf("Pending must not set TerminalAt, got %v", got.TerminalAt)
	}

	if err := s.UpdateStatus(ctx, "job2", persistence.Finished); err != nil {
		t.Fatalf("Finished: %v", err)
	}
	got, _ = s.Get(ctx, "job2")
	if !got.TerminalAt.Equal(fixedNow) {
		t.Errorf("Finished must set TerminalAt to fixedNow, got %v", got.TerminalAt)
	}

	if err := s.UpdateStatus(ctx, "job3", persistence.Failed, "boom"); err != nil {
		t.Fatalf("Failed: %v", err)
	}
	got, _ = s.Get(ctx, "job3")
	if !got.TerminalAt.Equal(fixedNow) {
		t.Errorf("Failed must set TerminalAt to fixedNow, got %v", got.TerminalAt)
	}
	if got.Error != "boom" {
		t.Errorf("Failed must propagate error message, got %q", got.Error)
	}
}

// TestCleanup_DisabledByZeroRetention confirms a zero/negative retention
// disables eviction entirely (useful for tests; never for prod).
func TestCleanup_DisabledByZeroRetention(t *testing.T) {
	fixedNow := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s := NewStore(
		WithRetention(0),
		WithCleanupInterval(time.Hour),
		WithNow(func() time.Time { return fixedNow }),
	)
	defer s.Close()
	ctx := context.Background()

	mustCreate(t, s, "ancient")
	// Use a separate clock helper to set TerminalAt to deep past.
	s.mu.Lock()
	s.jobs["ancient"].Status = persistence.Finished
	s.jobs["ancient"].TerminalAt = fixedNow.Add(-10000 * time.Hour)
	s.mu.Unlock()

	if n := s.Cleanup(); n != 0 {
		t.Errorf("Cleanup with retention=0 must evict nothing, got %d evicted", n)
	}
	if got, _ := s.Get(ctx, "ancient"); got == nil {
		t.Error("job should still be present when retention is disabled")
	}
}

// TestClose_StopsJanitor ensures Close() returns and is idempotent.
func TestClose_StopsJanitor(t *testing.T) {
	s := NewStore(
		WithRetention(time.Hour),
		WithCleanupInterval(10*time.Millisecond),
	)
	s.Close()
	s.Close() // safe to call again
}

func mustCreate(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.Create(context.Background(), persistence.ScanJob{ID: id, Status: persistence.Queued}); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

// TestSetFinished_PublishesAtomically pins issue #31 for the memory store:
// SetFinished moves the job to Finished AND saves the report in a single
// store operation. After it returns, no Get can observe Finished without
// the report or report without Finished.
func TestSetFinished_PublishesAtomically(t *testing.T) {
	fixedNow := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s := NewStore(WithNow(func() time.Time { return fixedNow }))
	defer s.Close()
	ctx := context.Background()

	mustCreate(t, s, "job-final")

	report := harbor.ScanReport{
		Scanner: harbor.Scanner{Name: "Kubescape", Version: "0.74.0"},
		Vulnerabilities: []harbor.VulnerabilityItem{
			{ID: "CVE-2024-9999", Severity: harbor.SevHigh},
		},
	}
	if err := s.SetFinished(ctx, "job-final", report); err != nil {
		t.Fatalf("SetFinished: %v", err)
	}

	got, err := s.Get(ctx, "job-final")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != persistence.Finished {
		t.Errorf("status = %s, want Finished", got.Status)
	}
	if len(got.Report.Vulnerabilities) != 1 || got.Report.Vulnerabilities[0].ID != "CVE-2024-9999" {
		t.Errorf("report not published with status: got %+v", got.Report.Vulnerabilities)
	}
	if !got.TerminalAt.Equal(fixedNow) {
		t.Errorf("TerminalAt = %v, want %v (SetFinished must mark the terminal moment)", got.TerminalAt, fixedNow)
	}
}

// TestSetFinished_NotFound mirrors UpdateStatus/UpdateReport: missing key
// returns an error rather than silently re-creating.
func TestSetFinished_NotFound(t *testing.T) {
	s := NewStore()
	defer s.Close()
	if err := s.SetFinished(context.Background(), "ghost", harbor.ScanReport{}); err == nil {
		t.Error("expected SetFinished on missing key to error")
	}
}
