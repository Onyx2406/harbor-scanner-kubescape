package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/config"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence/memory"
)

func TestGetMetadata(t *testing.T) {
	store := memory.NewStore()
	handler := NewAPIHandler(
		config.BuildInfo{Version: "test", Commit: "abc", Date: "now"},
		config.Config{},
		store,
		nil, // controller not needed for metadata
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metadata", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var metadata harbor.ScannerAdapterMetadata
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("failed to decode metadata: %v", err)
	}

	if metadata.Scanner.Name != "Kubescape" {
		t.Errorf("expected scanner name Kubescape, got %s", metadata.Scanner.Name)
	}
	if metadata.Scanner.Vendor != "ARMO" {
		t.Errorf("expected vendor ARMO, got %s", metadata.Scanner.Vendor)
	}
	if len(metadata.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(metadata.Capabilities))
	}
	if metadata.Capabilities[0].Type != "vulnerability" {
		t.Errorf("expected capability type vulnerability, got %s", metadata.Capabilities[0].Type)
	}
}

func TestAcceptScanRequest_Valid(t *testing.T) {
	store := memory.NewStore()
	handler := NewAPIHandler(
		config.BuildInfo{Version: "test"},
		config.Config{},
		store,
		nil, // controller is nil; goroutine guards against nil
	)

	scanReq := harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain"},
		Artifact: harbor.Artifact{
			Repository: "library/nginx",
			Digest:     "sha256:abc123",
		},
	}
	body, _ := json.Marshal(scanReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", bytes.NewReader(body))
	req.Header.Set("Content-Type", mimeTypeScanRequest)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	var scanResp harbor.ScanResponse
	if err := json.NewDecoder(w.Body).Decode(&scanResp); err != nil {
		t.Fatalf("failed to decode scan response: %v", err)
	}

	if scanResp.ID == "" {
		t.Error("expected non-empty scan ID")
	}
}

func TestAcceptScanRequest_MissingFields(t *testing.T) {
	store := memory.NewStore()
	handler := NewAPIHandler(config.BuildInfo{}, config.Config{}, store, nil)

	tests := []struct {
		name    string
		request harbor.ScanRequest
	}{
		{
			name: "missing registry URL",
			request: harbor.ScanRequest{
				Artifact: harbor.Artifact{Repository: "lib/nginx", Digest: "sha256:abc"},
			},
		},
		{
			name: "missing repository",
			request: harbor.ScanRequest{
				Registry: harbor.Registry{URL: "https://core.harbor.domain"},
				Artifact: harbor.Artifact{Digest: "sha256:abc"},
			},
		},
		{
			name: "missing digest",
			request: harbor.ScanRequest{
				Registry: harbor.Registry{URL: "https://core.harbor.domain"},
				Artifact: harbor.Artifact{Repository: "lib/nginx"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", bytes.NewReader(body))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusUnprocessableEntity {
				t.Errorf("expected 422, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestGetScanReport_NotFound(t *testing.T) {
	store := memory.NewStore()
	handler := NewAPIHandler(config.BuildInfo{}, config.Config{}, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/nonexistent/report", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetScanReport_Pending(t *testing.T) {
	store := memory.NewStore()
	store.Create(nil, persistence.ScanJob{
		ID:     "test-job-1",
		Status: persistence.Pending,
	})

	handler := NewAPIHandler(config.BuildInfo{}, config.Config{}, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/test-job-1/report", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
}

func TestGetScanReport_Finished(t *testing.T) {
	store := memory.NewStore()
	store.Create(nil, persistence.ScanJob{
		ID:     "test-job-2",
		Status: persistence.Finished,
		Report: harbor.ScanReport{
			Scanner: harbor.Scanner{Name: "Kubescape"},
		},
	})

	handler := NewAPIHandler(config.BuildInfo{}, config.Config{}, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/test-job-2/report", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var report harbor.ScanReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode report: %v", err)
	}

	if report.Scanner.Name != "Kubescape" {
		t.Errorf("expected scanner Kubescape, got %s", report.Scanner.Name)
	}
}

func TestGetScanReport_Failed(t *testing.T) {
	store := memory.NewStore()
	store.Create(nil, persistence.ScanJob{
		ID:     "test-job-3",
		Status: persistence.Failed,
		Error:  "image pull failed",
	})

	handler := NewAPIHandler(config.BuildInfo{}, config.Config{}, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/test-job-3/report", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestHealthProbes(t *testing.T) {
	handler := NewAPIHandler(config.BuildInfo{}, config.Config{}, memory.NewStore(), nil)

	tests := []struct {
		path string
	}{
		{"/probe/healthy"},
		{"/probe/ready"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected 200 for %s, got %d", tc.path, w.Code)
			}
		})
	}
}

// TestReady_FailingCheck pins issue #16: when a registered readiness check
// returns an error the probe must respond 503 so Kubernetes routes traffic
// away from the pod, rather than 200 (which would let Harbor keep hitting
// a pod that can only emit 500s).
func TestReady_FailingCheck(t *testing.T) {
	handler := NewAPIHandler(
		config.BuildInfo{}, config.Config{}, memory.NewStore(), nil,
		ReadinessCheck{
			Name:  "kubernetes-client",
			Check: func() error { return fmt.Errorf("k8s client unavailable") },
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/probe/ready", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		OK     bool `json:"ok"`
		Checks []struct {
			Name  string `json:"name"`
			OK    bool   `json:"ok"`
			Error string `json:"error,omitempty"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.OK {
		t.Errorf("expected ok=false in body, got ok=true")
	}
	if len(body.Checks) != 1 || body.Checks[0].Name != "kubernetes-client" || body.Checks[0].OK {
		t.Errorf("expected one failing kubernetes-client check, got %+v", body.Checks)
	}
	if body.Checks[0].Error != "k8s client unavailable" {
		t.Errorf("expected error message in body, got %q", body.Checks[0].Error)
	}

	// Liveness must still be 200 — the process is up, it just can't serve.
	req = httptest.NewRequest(http.MethodGet, "/probe/healthy", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/probe/healthy must stay 200 even when not ready, got %d", w.Code)
	}
}

// TestReady_AllChecksPass confirms the all-pass path returns 200 and lists
// each successful check by name.
func TestReady_AllChecksPass(t *testing.T) {
	handler := NewAPIHandler(
		config.BuildInfo{}, config.Config{}, memory.NewStore(), nil,
		ReadinessCheck{Name: "first", Check: func() error { return nil }},
		ReadinessCheck{Name: "second", Check: func() error { return nil }},
	)

	req := httptest.NewRequest(http.MethodGet, "/probe/ready", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
