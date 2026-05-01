package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T, opts ...Option) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewStore(client, opts...), mr
}

// TestRoundTrip confirms Create -> Get -> UpdateStatus -> UpdateReport
// produces the expected ScanJob via JSON serialization.
func TestRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	job := persistence.ScanJob{
		ID: "job-1",
		Request: harbor.ScanRequest{
			Registry: harbor.Registry{URL: "https://core.harbor.domain"},
			Artifact: harbor.Artifact{Repository: "library/nginx", Digest: "sha256:abc"},
		},
		Status: persistence.Queued,
	}

	if err := s.Create(ctx, job); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, "job-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected job, got nil")
	}
	if got.ID != "job-1" || got.Status != persistence.Queued {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.Request.Artifact.Digest != "sha256:abc" {
		t.Errorf("expected nested fields preserved, got %+v", got.Request)
	}

	if err := s.UpdateStatus(ctx, "job-1", persistence.Pending); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	got, _ = s.Get(ctx, "job-1")
	if got.Status != persistence.Pending {
		t.Errorf("expected Pending, got %s", got.Status)
	}

	if err := s.UpdateReport(ctx, "job-1", harbor.ScanReport{
		Scanner: harbor.Scanner{Name: "Kubescape", Version: "0.74.0"},
	}); err != nil {
		t.Fatalf("UpdateReport: %v", err)
	}
	got, _ = s.Get(ctx, "job-1")
	if got.Report.Scanner.Name != "Kubescape" {
		t.Errorf("expected report scanner name preserved, got %+v", got.Report.Scanner)
	}

	if err := s.UpdateStatus(ctx, "job-1", persistence.Failed, "boom"); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}
	got, _ = s.Get(ctx, "job-1")
	if got.Status != persistence.Failed || got.Error != "boom" {
		t.Errorf("expected Failed/boom, got %s/%q", got.Status, got.Error)
	}
}

// TestGet_NotFound mirrors the memory-store contract: missing keys return
// (nil, nil), not an error.
func TestGet_NotFound(t *testing.T) {
	s, _ := newTestStore(t)
	got, err := s.Get(context.Background(), "missing")
	if err != nil {
		t.Fatalf("expected nil error on missing key, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil job on missing key, got %+v", got)
	}
}

// TestTTLExpiry pins issue #17's bounded-retention property for the Redis
// backend: every write sets a TTL, and once that elapses the entry is
// gone. We use miniredis's FastForward to advance time deterministically.
func TestTTLExpiry(t *testing.T) {
	s, mr := newTestStore(t, WithTTL(30*time.Second))
	ctx := context.Background()

	if err := s.Create(ctx, persistence.ScanJob{ID: "job-ttl", Status: persistence.Finished}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Just after creation: still present.
	got, _ := s.Get(ctx, "job-ttl")
	if got == nil {
		t.Fatal("job should still exist immediately after Create")
	}

	mr.FastForward(31 * time.Second)

	got, err := s.Get(ctx, "job-ttl")
	if err != nil {
		t.Fatalf("Get after expiry: %v", err)
	}
	if got != nil {
		t.Errorf("job should have expired after TTL elapsed, got %+v", got)
	}
}

// TestUpdateRefreshesTTL confirms each save() resets the per-key TTL, so
// an in-flight job whose status keeps updating won't expire mid-scan even
// if the TTL is short.
func TestUpdateRefreshesTTL(t *testing.T) {
	s, mr := newTestStore(t, WithTTL(60*time.Second))
	ctx := context.Background()

	if err := s.Create(ctx, persistence.ScanJob{ID: "job-refresh", Status: persistence.Queued}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	mr.FastForward(45 * time.Second) // 15s remaining

	if err := s.UpdateStatus(ctx, "job-refresh", persistence.Pending); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	mr.FastForward(45 * time.Second) // 75s after Create, but only 45s after last write

	got, _ := s.Get(ctx, "job-refresh")
	if got == nil {
		t.Error("job should still exist — UpdateStatus must reset TTL")
	}
}

// TestUpdate_NotFoundReturnsError ensures we don't silently re-create a
// job that has already expired or never existed.
func TestUpdate_NotFoundReturnsError(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.UpdateStatus(ctx, "ghost", persistence.Pending); err == nil {
		t.Error("expected UpdateStatus on missing key to error")
	}
	if err := s.UpdateReport(ctx, "ghost", harbor.ScanReport{}); err == nil {
		t.Error("expected UpdateReport on missing key to error")
	}
}

// TestPing exercises the readiness hook.
func TestPing(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Errorf("Ping should succeed against miniredis, got %v", err)
	}
}

// TestPing_RedisDown returns the underlying error so a readiness probe
// can surface it.
func TestPing_RedisDown(t *testing.T) {
	s, mr := newTestStore(t)
	mr.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Error("expected Ping to fail when miniredis is closed")
	}
}
