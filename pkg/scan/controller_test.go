package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence/memory"
)

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
	c := NewController(store, nil, nil, "kubescape")

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
