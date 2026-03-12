package scan

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/k8s"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
)

const (
	// How often to poll for VulnerabilityManifest CRD after triggering a scan.
	pollInterval = 5 * time.Second
	// Maximum time to wait for a scan to complete.
	pollTimeout = 10 * time.Minute
)

// Controller orchestrates the scanning workflow:
// 1. Check if VulnerabilityManifest CRD already exists for the image
// 2. If yes, transform and return it
// 3. If no, trigger kubevuln ScanCVE, then poll for the CRD
type Controller interface {
	Scan(ctx context.Context, scanJobID string) error
}

type controller struct {
	store     persistence.Store
	scanner   Scanner
	k8sClient k8s.Client
	namespace string
}

// NewController creates a new scan controller.
func NewController(store persistence.Store, scanner Scanner, k8sClient k8s.Client, namespace string) Controller {
	return &controller{
		store:     store,
		scanner:   scanner,
		k8sClient: k8sClient,
		namespace: namespace,
	}
}

func (c *controller) Scan(ctx context.Context, scanJobID string) error {
	if err := c.scan(ctx, scanJobID); err != nil {
		slog.Error("Scan failed",
			slog.String("scan_job_id", scanJobID),
			slog.String("err", err.Error()),
		)
		if updateErr := c.store.UpdateStatus(ctx, scanJobID, persistence.Failed, err.Error()); updateErr != nil {
			slog.Error("Failed to update scan job status",
				slog.String("scan_job_id", scanJobID),
				slog.String("err", updateErr.Error()),
			)
		}
		return err
	}
	return nil
}

func (c *controller) scan(ctx context.Context, scanJobID string) error {
	job, err := c.store.Get(ctx, scanJobID)
	if err != nil {
		return err
	}
	if job == nil {
		return fmt.Errorf("scan job not found: %s", scanJobID)
	}

	if err := c.store.UpdateStatus(ctx, scanJobID, persistence.Pending); err != nil {
		return err
	}

	// Derive the VulnerabilityManifest CRD name from the image reference
	crdName := ImageSlugForRequest(job.Request)

	slog.Info("Checking for existing VulnerabilityManifest",
		slog.String("scan_job_id", scanJobID),
		slog.String("crd_name", crdName),
		slog.String("namespace", c.namespace),
	)

	// Step 1: Check if VulnerabilityManifest already exists
	if c.k8sClient != nil {
		existing, err := c.k8sClient.GetVulnerabilityManifest(ctx, c.namespace, crdName)
		if err != nil {
			slog.Warn("Failed to check existing VulnerabilityManifest, will trigger new scan",
				slog.String("err", err.Error()),
			)
		} else if existing != nil && len(existing.Matches) > 0 {
			slog.Info("Found existing VulnerabilityManifest, reusing results",
				slog.String("crd_name", crdName),
				slog.Int("matches", len(existing.Matches)),
			)
			report := TransformManifestToReport(existing, job.Request.Artifact)
			if err := c.store.UpdateReport(ctx, scanJobID, report); err != nil {
				return err
			}
			return c.store.UpdateStatus(ctx, scanJobID, persistence.Finished)
		}
	}

	// Step 2: No existing CRD — trigger kubevuln scan
	slog.Info("No existing VulnerabilityManifest found, triggering kubevuln scan",
		slog.String("scan_job_id", scanJobID),
	)

	if err := c.scanner.TriggerScan(ctx, job.Request); err != nil {
		return fmt.Errorf("triggering kubevuln scan: %w", err)
	}

	// Step 3: Poll for VulnerabilityManifest CRD
	if c.k8sClient != nil {
		report, err := c.pollForResults(ctx, crdName, job.Request.Artifact)
		if err != nil {
			return fmt.Errorf("waiting for scan results: %w", err)
		}
		if err := c.store.UpdateReport(ctx, scanJobID, report); err != nil {
			return err
		}
	} else {
		// No K8s client available (e.g., local dev) — store a placeholder
		report := BuildPlaceholderReport(job.Request.Artifact)
		if err := c.store.UpdateReport(ctx, scanJobID, report); err != nil {
			return err
		}
	}

	if err := c.store.UpdateStatus(ctx, scanJobID, persistence.Finished); err != nil {
		return err
	}

	slog.Info("Scan completed", slog.String("scan_job_id", scanJobID))
	return nil
}

// pollForResults polls the Kubernetes API for the VulnerabilityManifest CRD
// until it appears with results or the timeout is reached.
func (c *controller) pollForResults(ctx context.Context, crdName string, artifact harbor.Artifact) (harbor.ScanReport, error) {
	deadline := time.Now().Add(pollTimeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return harbor.ScanReport{}, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return harbor.ScanReport{}, fmt.Errorf("timed out waiting for VulnerabilityManifest %s after %v", crdName, pollTimeout)
			}

			vm, err := c.k8sClient.GetVulnerabilityManifest(ctx, c.namespace, crdName)
			if err != nil {
				slog.Warn("Error polling VulnerabilityManifest",
					slog.String("crd_name", crdName),
					slog.String("err", err.Error()),
				)
				continue
			}

			if vm != nil {
				slog.Info("VulnerabilityManifest found",
					slog.String("crd_name", crdName),
					slog.Int("matches", len(vm.Matches)),
				)
				return TransformManifestToReport(vm, artifact), nil
			}

			slog.Debug("VulnerabilityManifest not yet available, retrying",
				slog.String("crd_name", crdName),
			)
		}
	}
}
