package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/k8s"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
)

// pollInterval and pollTimeout are vars (not consts) so tests can shorten
// them via t.Cleanup. Production always uses the defaults.
var (
	// pollInterval is how often to poll for VulnerabilityManifest CRD after
	// triggering a scan.
	pollInterval = 5 * time.Second
	// pollTimeout is the maximum time to wait for a scan to complete.
	pollTimeout = 10 * time.Minute
)

const (
	// DefaultReuseTTL is the default freshness window for reusing an existing
	// VulnerabilityManifest. Anything older triggers a fresh scan so newly
	// disclosed CVEs in the Grype DB get picked up. See issue #14.
	DefaultReuseTTL = 24 * time.Hour
)

// now is overridable in tests. Production always uses time.Now.
var now = time.Now

// Controller orchestrates the scanning workflow:
// 1. Check if a fresh VulnerabilityManifest CRD already exists for the image
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
	reuseTTL  time.Duration
}

// NewController creates a new scan controller.
//
// reuseTTL is the freshness window for an existing VulnerabilityManifest CRD;
// anything older is treated as stale and triggers a fresh scan. Pass 0 to
// disable reuse entirely (always rescan), or use DefaultReuseTTL for the
// recommended default.
func NewController(store persistence.Store, scanner Scanner, k8sClient k8s.Client, namespace string, reuseTTL time.Duration) Controller {
	return &controller{
		store:     store,
		scanner:   scanner,
		k8sClient: k8sClient,
		namespace: namespace,
		reuseTTL:  reuseTTL,
	}
}

// failedWriteTimeout caps the time we'll spend persisting a terminal
// Failed status during shutdown. Long enough for a healthy Redis to ACK,
// short enough that a stuck Redis can't block process exit.
const failedWriteTimeout = 5 * time.Second

func (c *controller) Scan(ctx context.Context, scanJobID string) error {
	if err := c.scan(ctx, scanJobID); err != nil {
		slog.Error("Scan failed",
			slog.String("scan_job_id", scanJobID),
			slog.String("err", err.Error()),
		)
		// IMPORTANT: write Failed status using a fresh, uncancelled
		// context. The inbound ctx may already be Done — that's exactly
		// why we're here on the graceful-shutdown path (issue #24
		// cancels scanCtx, which propagates through pollForResults).
		// Reusing it for the store write would race the Redis SET to
		// context.Canceled and leave the job Pending until TTL expiry.
		// See issue #29.
		writeCtx, cancel := context.WithTimeout(context.Background(), failedWriteTimeout)
		defer cancel()
		if updateErr := c.store.UpdateStatus(writeCtx, scanJobID, persistence.Failed, err.Error()); updateErr != nil {
			slog.Error("Failed to update scan job status",
				slog.String("scan_job_id", scanJobID),
				slog.String("err", updateErr.Error()),
			)
		}
		return err
	}
	return nil
}

// ErrK8sUnavailable is returned when the controller cannot read
// VulnerabilityManifest CRDs from Kubernetes. The adapter cannot observe scan
// results in this state, so propagating an error is the correct behavior —
// returning a placeholder zero-vulnerability report would be a security-
// relevant false negative (Harbor would mark images clean that were never
// scanned). See issue #6.
var ErrK8sUnavailable = fmt.Errorf("kubernetes client unavailable: cannot observe VulnerabilityManifest CRDs")

func (c *controller) scan(ctx context.Context, scanJobID string) error {
	job, err := c.store.Get(ctx, scanJobID)
	if err != nil {
		return err
	}
	if job == nil {
		return fmt.Errorf("scan job not found: %s", scanJobID)
	}

	if c.k8sClient == nil {
		return ErrK8sUnavailable
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

	// Step 1: Check if a fresh VulnerabilityManifest already exists. The
	// freshness check is uniform: a CRD is reusable iff it is younger than
	// reuseTTL, regardless of whether it carries zero or many matches. The
	// previous len(Matches) > 0 gate caused two bugs: clean images were
	// rescanned every time, and vulnerable manifests were reused forever
	// even after the Grype DB or scanner version changed (issue #14).
	existing, err := c.k8sClient.GetVulnerabilityManifest(ctx, c.namespace, crdName)

	// staleSeenAt is the CreatedAt of any existing-but-stale CRD we observed
	// before triggering the rescan. The poll loop only accepts manifests with
	// CreatedAt strictly newer than this — otherwise it would happily return
	// the same stale CRD it just rejected on the very next tick, before
	// kubevuln has had a chance to overwrite it. See issue #23.
	var staleSeenAt time.Time

	if err != nil {
		// Bail fast on unrecoverable errors (auth rejection, missing
		// namespace, unserved resource type). Triggering a kubevuln
		// scan we can't observe would just burn the pollTimeout
		// budget for nothing.
		if errors.Is(err, k8s.ErrFatalAPIRead) {
			return fmt.Errorf("aborting scan on unrecoverable K8s API error: %w", err)
		}
		slog.Warn("Failed to check existing VulnerabilityManifest, will trigger new scan",
			slog.String("err", err.Error()),
		)
	} else if existing != nil && c.canReuse(existing) {
		slog.Info("Found fresh VulnerabilityManifest, reusing results",
			slog.String("crd_name", crdName),
			slog.Int("matches", len(existing.Matches)),
			slog.Time("created_at", existing.CreatedAt),
			slog.Duration("ttl", c.reuseTTL),
		)
		report := TransformManifestToReport(existing, job.Request.Artifact)
		// Atomic: publish report and Finished status in one store op so
		// Harbor cannot poll a Finished status before the report lands,
		// nor a Pending status while the report is already saved. See #31.
		return c.store.SetFinished(ctx, scanJobID, report)
	} else if existing != nil {
		staleSeenAt = existing.CreatedAt
		slog.Info("Existing VulnerabilityManifest is stale, triggering fresh scan",
			slog.String("crd_name", crdName),
			slog.Time("created_at", existing.CreatedAt),
			slog.Duration("age", now().Sub(existing.CreatedAt)),
			slog.Duration("ttl", c.reuseTTL),
		)
	}

	// Step 2: No existing CRD — trigger kubevuln scan
	slog.Info("No existing VulnerabilityManifest found, triggering kubevuln scan",
		slog.String("scan_job_id", scanJobID),
	)

	if err := c.scanner.TriggerScan(ctx, job.Request); err != nil {
		return fmt.Errorf("triggering kubevuln scan: %w", err)
	}

	// Step 3: Poll for VulnerabilityManifest CRD. Pass staleSeenAt so the
	// loop ignores any CRD with CreatedAt <= staleSeenAt — i.e. the very
	// stale object we just rejected, which kubevuln has not yet overwritten.
	report, err := c.pollForResults(ctx, crdName, job.Request.Artifact, staleSeenAt)
	if err != nil {
		return fmt.Errorf("waiting for scan results: %w", err)
	}

	// Atomic publication: a single store op transitions the job to
	// Finished AND saves the report. Eliminates the crash window between
	// UpdateReport and UpdateStatus that left reports invisible behind a
	// stale Pending status (issue #31).
	if err := c.store.SetFinished(ctx, scanJobID, report); err != nil {
		return err
	}

	slog.Info("Scan completed", slog.String("scan_job_id", scanJobID))
	return nil
}

// canReuse reports whether an existing VulnerabilityManifest is fresh enough
// to skip a fresh scan. A zero reuseTTL disables reuse outright. A zero or
// missing CreatedAt is treated as stale — we will not reuse a manifest of
// unknown age, since we can't tell whether it predates the current Grype DB.
func (c *controller) canReuse(vm *k8s.VulnerabilityManifest) bool {
	if c.reuseTTL <= 0 {
		return false
	}
	if vm.CreatedAt.IsZero() {
		return false
	}
	return now().Sub(vm.CreatedAt) < c.reuseTTL
}

// pollForResults polls the Kubernetes API for the VulnerabilityManifest CRD
// until a manifest strictly newer than staleSeenAt appears, or the timeout
// is reached.
//
// staleSeenAt is the CreatedAt of any pre-existing stale CRD the controller
// already rejected as too old (zero if no prior CRD existed). Without this
// gate, the very first poll tick after triggering a rescan would return the
// same stale object kubevuln has not yet overwritten — defeating the
// freshness check. See issue #23.
func (c *controller) pollForResults(ctx context.Context, crdName string, artifact harbor.Artifact, staleSeenAt time.Time) (harbor.ScanReport, error) {
	deadline := now().Add(pollTimeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return harbor.ScanReport{}, ctx.Err()
		case <-ticker.C:
			if now().After(deadline) {
				return harbor.ScanReport{}, fmt.Errorf("timed out waiting for VulnerabilityManifest %s after %v", crdName, pollTimeout)
			}

			vm, err := c.k8sClient.GetVulnerabilityManifest(ctx, c.namespace, crdName)
			if err != nil {
				// Unrecoverable errors (auth rejection, missing namespace,
				// broken resource path) won't fix themselves. Bail
				// immediately instead of burning the rest of pollTimeout
				// retrying against a misconfigured cluster.
				if errors.Is(err, k8s.ErrFatalAPIRead) {
					return harbor.ScanReport{}, fmt.Errorf("aborting poll on unrecoverable K8s API error: %w", err)
				}
				slog.Warn("Error polling VulnerabilityManifest (transient, will retry)",
					slog.String("crd_name", crdName),
					slog.String("err", err.Error()),
				)
				continue
			}

			if vm == nil {
				slog.Debug("VulnerabilityManifest not yet available, retrying",
					slog.String("crd_name", crdName),
				)
				continue
			}

			if !staleSeenAt.IsZero() && !vm.CreatedAt.After(staleSeenAt) {
				slog.Debug("Polled VulnerabilityManifest is the stale one, waiting for kubevuln to overwrite",
					slog.String("crd_name", crdName),
					slog.Time("created_at", vm.CreatedAt),
					slog.Time("stale_seen_at", staleSeenAt),
				)
				continue
			}

			if vm.CreatedAt.IsZero() {
				slog.Warn("Polled VulnerabilityManifest has zero CreatedAt, treating as not-yet-ready",
					slog.String("crd_name", crdName),
				)
				continue
			}

			slog.Info("VulnerabilityManifest found",
				slog.String("crd_name", crdName),
				slog.Int("matches", len(vm.Matches)),
				slog.Time("created_at", vm.CreatedAt),
			)
			return TransformManifestToReport(vm, artifact), nil
		}
	}
}
