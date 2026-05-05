package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/config"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/scan"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

const (
	pathVarScanRequestID = "scan_request_id"

	mimeTypeMetadata     = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	mimeTypeScanRequest  = "application/vnd.scanner.adapter.scan.request+json; version=1.0"
	mimeTypeScanResponse = "application/vnd.scanner.adapter.scan.response+json; version=1.0"
	mimeTypeVulnReport   = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	mimeTypeError        = "application/vnd.scanner.adapter.error+json; version=1.0"

	mimeTypeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mimeTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"

	// maxScanRequestBodyBytes caps how much of the POST /api/v1/scan body
	// we will read into memory. Harbor's scan request is a tiny JSON
	// document (registry URL + artifact digest + maybe a credentials
	// header); 1 MiB is well over what's plausibly legit and stops a
	// hostile / misbehaving Harbor instance from OOMing the pod with a
	// huge body.
	maxScanRequestBodyBytes = 1 * 1024 * 1024
)

// ReadinessCheck returns nil when the named subsystem is ready to serve scan
// traffic, or an error describing why it is not. Composed in NewAPIHandler so
// future dependencies (durable store, kubevuln reachability) can layer in
// without touching the probe handler. See issue #16.
type ReadinessCheck struct {
	Name  string
	Check func() error
}

type requestHandler struct {
	buildInfo       config.BuildInfo
	config          config.Config
	store           persistence.Store
	controller      scan.Controller
	readinessChecks []ReadinessCheck

	// scanCtx is the parent context inherited by every async scan goroutine.
	// When cancelled (typically on SIGTERM), the goroutines see ctx.Done in
	// pollForResults and the controller's wrapper records the job as Failed
	// instead of leaving it Pending until TTL expiry. See issue #24. May be
	// nil — falls back to context.Background() with no cancellation.
	scanCtx context.Context

	// scanWG counts in-flight scan goroutines so the shutdown path can wait
	// for them to record Failed status before the process exits. May be nil
	// in tests that don't care about graceful shutdown.
	scanWG *sync.WaitGroup
}

// NewAPIHandler creates the HTTP handler with all Harbor Scanner API routes.
//
// readinessChecks are evaluated on every /probe/ready hit. If any check
// returns an error the probe responds 503 with a JSON listing the failing
// subsystems, otherwise 200. /probe/healthy stays 200 unconditionally —
// liveness reflects the process being up, not its ability to serve.
//
// scanCtx and scanWG (both may be nil) plumb a process-lifetime cancellable
// context and an in-flight counter into async scan goroutines. main.go
// passes a real ctx + wg so SIGTERM can cancel running scans and wait for
// them to record Failed status; tests typically pass nil for both. See
// issue #24.
func NewAPIHandler(
	buildInfo config.BuildInfo,
	cfg config.Config,
	store persistence.Store,
	controller scan.Controller,
	scanCtx context.Context,
	scanWG *sync.WaitGroup,
	readinessChecks ...ReadinessCheck,
) http.Handler {
	if scanCtx == nil {
		scanCtx = context.Background()
	}
	h := &requestHandler{
		buildInfo:       buildInfo,
		config:          cfg,
		store:           store,
		controller:      controller,
		readinessChecks: readinessChecks,
		scanCtx:         scanCtx,
		scanWG:          scanWG,
	}

	router := mux.NewRouter()
	router.Use(h.logRequest)

	apiV1 := router.PathPrefix("/api/v1").Subrouter()
	apiV1.Methods(http.MethodGet).Path("/metadata").HandlerFunc(h.GetMetadata)
	apiV1.Methods(http.MethodPost).Path("/scan").HandlerFunc(h.AcceptScanRequest)
	apiV1.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(h.GetScanReport)

	router.Methods(http.MethodGet).Path("/probe/healthy").HandlerFunc(h.GetHealthy)
	router.Methods(http.MethodGet).Path("/probe/ready").HandlerFunc(h.GetReady)

	return router
}

func (h *requestHandler) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Request",
			slog.String("method", r.Method),
			slog.String("uri", r.URL.RequestURI()),
			slog.String("remote", r.RemoteAddr),
		)
		next.ServeHTTP(w, r)
	})
}

// GetMetadata returns scanner metadata and capabilities.
// Harbor calls this to discover what the scanner can do.
func (h *requestHandler) GetMetadata(w http.ResponseWriter, _ *http.Request) {
	metadata := harbor.ScannerAdapterMetadata{
		Scanner: harbor.Scanner{
			Name:    "Kubescape",
			Vendor:  "ARMO",
			Version: h.buildInfo.Version,
		},
		Capabilities: []harbor.ScannerCapability{
			{
				Type: "vulnerability",
				ConsumesMIMETypes: []string{
					mimeTypeOCIManifest,
					mimeTypeDockerManifest,
				},
				ProducesMIMETypes: []string{
					mimeTypeVulnReport,
				},
			},
		},
		Properties: map[string]string{
			"harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
			"org.label-schema.version":            h.buildInfo.Version,
			"org.label-schema.build-date":         h.buildInfo.Date,
			"org.label-schema.vcs-ref":            h.buildInfo.Commit,
			"org.label-schema.vcs":                "https://github.com/goharbor/harbor-scanner-kubescape",
		},
	}

	writeJSON(w, metadata, mimeTypeMetadata, http.StatusOK)
}

// AcceptScanRequest accepts a scan request from Harbor, enqueues it, and returns a scan ID.
func (h *requestHandler) AcceptScanRequest(w http.ResponseWriter, r *http.Request) {
	// Bound the request body so a hostile / misbehaving caller can't OOM
	// the pod with an unbounded POST. Harbor's scan request is tiny in
	// practice; 1 MiB is well above any plausible legit value.
	r.Body = http.MaxBytesReader(w, r.Body, maxScanRequestBodyBytes)
	var scanRequest harbor.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&scanRequest); err != nil {
		slog.Error("Failed to decode scan request", slog.String("err", err.Error()))
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unmarshalling scan request: %s", err.Error()))
		return
	}

	if err := validateScanRequest(scanRequest); err != nil {
		slog.Error("Invalid scan request", slog.String("err", err.Error()))
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	scanJobID := uuid.New().String()

	job := persistence.ScanJob{
		ID:      scanJobID,
		Request: scanRequest,
		Status:  persistence.Queued,
	}

	if err := h.store.Create(r.Context(), job); err != nil {
		slog.Error("Failed to create scan job", slog.String("err", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to enqueue scan job")
		return
	}

	// Launch scan asynchronously. The goroutine inherits h.scanCtx (NOT
	// r.Context(), which is cancelled when the HTTP response is sent) so
	// that on SIGTERM the controller's poll loop sees ctx.Done, returns
	// ctx.Err, and the wrapper Scan() writes Failed("interrupted") to the
	// store rather than leaving the job Pending until TTL expiry.
	// See issue #24.
	if h.controller != nil {
		if h.scanWG != nil {
			h.scanWG.Add(1)
		}
		go func() {
			if h.scanWG != nil {
				defer h.scanWG.Done()
			}
			if err := h.controller.Scan(h.scanCtx, scanJobID); err != nil {
				slog.Error("Async scan failed",
					slog.String("scan_job_id", scanJobID),
					slog.String("err", err.Error()),
				)
			}
		}()
	}

	slog.Info("Scan request accepted",
		slog.String("scan_job_id", scanJobID),
		slog.String("repository", scanRequest.Artifact.Repository),
		slog.String("digest", scanRequest.Artifact.Digest),
	)

	writeJSON(w, harbor.ScanResponse{ID: scanJobID}, mimeTypeScanResponse, http.StatusAccepted)
}

// GetScanReport returns the scan report for a given scan request ID.
// Harbor polls this endpoint until it returns 200 or 500.
func (h *requestHandler) GetScanReport(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanJobID, ok := vars[pathVarScanRequestID]
	if !ok {
		writeError(w, http.StatusBadRequest, "missing scan request id")
		return
	}

	job, err := h.store.Get(r.Context(), scanJobID)
	if err != nil {
		slog.Error("Failed to get scan job", slog.String("err", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to get scan job")
		return
	}

	if job == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("scan job not found: %s", scanJobID))
		return
	}

	switch job.Status {
	case persistence.Queued, persistence.Pending:
		// Scan is still in progress - return 302 so Harbor retries.
		// Harbor's scanner-spec client polls on its own schedule, so we
		// don't need a Refresh hint; the prior `Refresh-After` header
		// wasn't a real HTTP header anyway.
		slog.Debug("Scan in progress",
			slog.String("scan_job_id", scanJobID),
			slog.String("status", job.Status.String()),
		)
		w.Header().Set("Location", r.URL.String())
		w.WriteHeader(http.StatusFound)
		return

	case persistence.Failed:
		writeError(w, http.StatusInternalServerError, job.Error)
		return

	case persistence.Finished:
		writeJSON(w, job.Report, mimeTypeVulnReport, http.StatusOK)
		return

	default:
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("unexpected scan job status: %s", job.Status.String()))
	}
}

func (h *requestHandler) GetHealthy(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *requestHandler) GetReady(w http.ResponseWriter, _ *http.Request) {
	type checkResult struct {
		Name  string `json:"name"`
		Error string `json:"error,omitempty"`
		OK    bool   `json:"ok"`
	}

	results := make([]checkResult, 0, len(h.readinessChecks))
	allOK := true
	for _, c := range h.readinessChecks {
		err := c.Check()
		results = append(results, checkResult{
			Name:  c.Name,
			OK:    err == nil,
			Error: errString(err),
		})
		if err != nil {
			allOK = false
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if allOK {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "checks": results})
		return
	}

	slog.Warn("Readiness check failed", slog.Any("checks", results))
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "checks": results})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func validateScanRequest(req harbor.ScanRequest) error {
	if req.Registry.URL == "" {
		return fmt.Errorf("missing registry.url")
	}
	if _, err := url.ParseRequestURI(req.Registry.URL); err != nil {
		return fmt.Errorf("invalid registry.url")
	}
	if req.Artifact.Repository == "" {
		return fmt.Errorf("missing artifact.repository")
	}
	if req.Artifact.Digest == "" {
		return fmt.Errorf("missing artifact.digest")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v interface{}, contentType string, statusCode int) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("Failed to write JSON response", slog.String("err", err.Error()))
	}
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", mimeTypeError)
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(harbor.ErrorResponse{
		Err: harbor.ErrorMessage{Message: message},
	})
}
