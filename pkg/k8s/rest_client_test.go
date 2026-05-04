package k8s

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestGetVulnerabilityManifest_CanonicalUnmarshal pins issue #3: the REST
// client decodes into v1beta1.VulnerabilityManifest from kubescape/storage
// rather than a hand-rolled struct, so any schema drift (renamed fields,
// new types) shows up at compile time in the converter. This test exercises
// the full path with a representative CRD payload and asserts every field
// the adapter reads makes it through.
func TestGetVulnerabilityManifest_CanonicalUnmarshal(t *testing.T) {
	const crdJSON = `{
	  "apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
	  "kind": "VulnerabilityManifest",
	  "metadata": {
	    "name": "core.harbor.domain-library-nginx-abc123",
	    "namespace": "kubescape",
	    "creationTimestamp": "2026-04-30T12:00:00Z"
	  },
	  "spec": {
	    "metadata": {
	      "tool": {"name":"grype","version":"0.74.0"},
	      "report": {"createdAt":"2026-04-30T12:00:00Z"}
	    },
	    "payload": {
	      "matches": [
	        {
	          "vulnerability": {
	            "id": "CVE-2024-1111",
	            "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-1111",
	            "namespace": "nvd:cpe",
	            "severity": "High",
	            "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1111"],
	            "description": "Buffer overflow in libfoo",
	            "cvss": [
	              {"version":"3.1","vector":"CVSS:3.1/AV:N","metrics":{"baseScore":7.5}}
	            ],
	            "fix": {"versions":["1.2.4"], "state":"fixed"}
	          },
	          "relatedVulnerabilities": [],
	          "matchDetails": [],
	          "artifact": {
	            "name":"libfoo",
	            "version":"1.2.3",
	            "type":"deb",
	            "language":"",
	            "locations":[],
	            "licenses":[],
	            "cpes":[],
	            "purl":"",
	            "upstreams":[]
	          }
	        }
	      ],
	      "source": null,
	      "distro": {"name":"alpine","version":"3.19","idLike":[]},
	      "descriptor": {"name":"grype","version":"0.74.0"}
	    }
	  }
	}`

	srv := newCRDServer(crdJSON)
	defer srv.Close()

	c := NewRESTClient(srv.URL, StaticTokenSource("test-token"))

	vm, err := c.GetVulnerabilityManifest(context.Background(), "kubescape", "core.harbor.domain-library-nginx-abc123")
	if err != nil {
		t.Fatalf("GetVulnerabilityManifest: %v", err)
	}
	if vm == nil {
		t.Fatal("expected manifest, got nil")
	}

	if vm.Name != "core.harbor.domain-library-nginx-abc123" {
		t.Errorf("Name = %q, want core.harbor.domain-library-nginx-abc123", vm.Name)
	}
	if vm.Namespace != "kubescape" {
		t.Errorf("Namespace = %q, want kubescape", vm.Namespace)
	}
	if vm.ToolName != "grype" {
		t.Errorf("ToolName = %q, want grype", vm.ToolName)
	}
	if vm.ToolVersion != "0.74.0" {
		t.Errorf("ToolVersion = %q, want 0.74.0", vm.ToolVersion)
	}
	if vm.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero — expected creationTimestamp parsing to work")
	}

	if len(vm.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(vm.Matches))
	}
	m := vm.Matches[0]
	if m.ID != "CVE-2024-1111" {
		t.Errorf("ID = %q, want CVE-2024-1111", m.ID)
	}
	if m.Severity != "High" {
		t.Errorf("Severity = %q, want High", m.Severity)
	}
	if m.PkgName != "libfoo" {
		t.Errorf("PkgName = %q, want libfoo", m.PkgName)
	}
	if m.PkgVersion != "1.2.3" {
		t.Errorf("PkgVersion = %q, want 1.2.3", m.PkgVersion)
	}
	if m.PkgType != "deb" {
		t.Errorf("PkgType = %q, want deb", m.PkgType)
	}
	if len(m.URLs) != 1 || m.URLs[0] != "https://nvd.nist.gov/vuln/detail/CVE-2024-1111" {
		t.Errorf("URLs = %v, want exactly the NVD link", m.URLs)
	}
	if len(m.FixVersions) != 1 || m.FixVersions[0] != "1.2.4" {
		t.Errorf("FixVersions = %v, want [1.2.4]", m.FixVersions)
	}
	if m.FixState != "fixed" {
		t.Errorf("FixState = %q, want fixed", m.FixState)
	}
	if len(m.CVSS) != 1 || m.CVSS[0].BaseScore != 7.5 {
		t.Errorf("CVSS = %v, want one entry with baseScore 7.5", m.CVSS)
	}
}

// TestGetVulnerabilityManifest_CweExtraction pins issue #5: CWE IDs in the
// raw payload — whether on the matched vulnerability itself or inside
// relatedVulnerabilities — must end up on VulnMatch.CweIDs and be
// deduplicated with order preserved. The canonical v1beta1 type at the
// pinned version doesn't carry a Cwes field, so we read CWEs out via a
// raw-JSON overlay and merge them onto the canonical-derived matches.
func TestGetVulnerabilityManifest_CweExtraction(t *testing.T) {
	const crdJSON = `{
	  "metadata": {
	    "name": "core.harbor.domain-library-nginx-abc123",
	    "namespace": "kubescape",
	    "creationTimestamp": "2026-04-30T12:00:00Z"
	  },
	  "spec": {
	    "metadata": {
	      "tool": {"name":"grype","version":"0.74.0"},
	      "report": {"createdAt":"2026-04-30T12:00:00Z"}
	    },
	    "payload": {
	      "matches": [
	        {
	          "vulnerability": {
	            "id": "CVE-2024-1111",
	            "severity": "High",
	            "description": "...",
	            "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1111"],
	            "cwes": ["CWE-79"],
	            "fix": {"versions":["1.2.4"], "state":"fixed"}
	          },
	          "relatedVulnerabilities": [
	            {
	              "id": "CVE-2024-1111",
	              "namespace": "nvd:cpe",
	              "cwes": ["CWE-79", "CWE-352"]
	            }
	          ],
	          "artifact": {"name":"libfoo","version":"1.2.3","type":"deb"}
	        },
	        {
	          "vulnerability": {
	            "id": "CVE-2024-2222",
	            "severity": "Low"
	          },
	          "relatedVulnerabilities": [
	            {
	              "id": "CVE-2024-2222",
	              "namespace": "nvd:cpe",
	              "cwes": ["CWE-200"]
	            }
	          ],
	          "artifact": {"name":"libbar","version":"2.0"}
	        },
	        {
	          "vulnerability": {
	            "id": "CVE-2024-3333",
	            "severity": "Medium"
	          },
	          "artifact": {"name":"libbaz","version":"3.0"}
	        }
	      ]
	    }
	  }
	}`

	srv := newCRDServer(crdJSON)
	defer srv.Close()

	c := NewRESTClient(srv.URL, StaticTokenSource("test-token"))

	vm, err := c.GetVulnerabilityManifest(context.Background(), "kubescape", "core.harbor.domain-library-nginx-abc123")
	if err != nil {
		t.Fatalf("GetVulnerabilityManifest: %v", err)
	}
	if vm == nil {
		t.Fatal("expected manifest, got nil")
	}
	if len(vm.Matches) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(vm.Matches))
	}

	// Match 1: dedupe across vulnerability.cwes and relatedVulnerabilities.cwes.
	if got, want := vm.Matches[0].CweIDs, []string{"CWE-79", "CWE-352"}; !equalStrings(got, want) {
		t.Errorf("match[0].CweIDs = %v, want %v (deduped union)", got, want)
	}
	// Match 2: CWEs only on relatedVulnerabilities — should still propagate.
	if got, want := vm.Matches[1].CweIDs, []string{"CWE-200"}; !equalStrings(got, want) {
		t.Errorf("match[1].CweIDs = %v, want %v", got, want)
	}
	// Match 3: no CWEs anywhere — should be empty (not panic, not nil-ptr).
	if len(vm.Matches[2].CweIDs) != 0 {
		t.Errorf("match[2].CweIDs = %v, want empty", vm.Matches[2].CweIDs)
	}
}

func TestGetVulnerabilityManifest_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, &http.Request{})
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, StaticTokenSource("test-token"))

	vm, err := c.GetVulnerabilityManifest(context.Background(), "kubescape", "missing")
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if vm != nil {
		t.Errorf("expected nil manifest on 404, got %+v", vm)
	}
}

func newCRDServer(crdJSON string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/vulnerabilitymanifests/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(crdJSON))
	}))
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

// TestFileTokenSource_RereadsOnEveryCall pins issue #30: the REST client
// must pick up service-account token rotation. We point FileTokenSource at
// a temp file, observe the bearer token sent to a httptest server, then
// rewrite the file and observe the new token on the next request — without
// reconstructing the client.
func TestFileTokenSource_RereadsOnEveryCall(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("token-v1"), 0600); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	var seenAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"major":"1","minor":"29"}`))
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, FileTokenSource(tokenPath))

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping #1: %v", err)
	}
	if got := seenAuth.Load().(string); got != "Bearer token-v1" {
		t.Errorf("first Ping Authorization = %q, want Bearer token-v1", got)
	}

	// Simulate kubelet rotating the token file underneath us.
	if err := os.WriteFile(tokenPath, []byte("token-v2"), 0600); err != nil {
		t.Fatalf("rotate token: %v", err)
	}

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping #2: %v", err)
	}
	if got := seenAuth.Load().(string); got != "Bearer token-v2" {
		t.Errorf("post-rotation Authorization = %q, want Bearer token-v2 — token was cached at startup, regression on issue #30", got)
	}
}

// TestPing_SurfacesAuthFailure confirms that a 401 from the K8s API turns
// into a Ping error, which is what the readiness check uses to flip the
// pod to NotReady.
func TestPing_SurfacesAuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, StaticTokenSource("expired"))

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected Ping to fail when API returns 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected error to mention 401, got %v", err)
	}
}

// TestPing_OK covers the happy path so a regression that ALWAYS errors
// would be caught.
func TestPing_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"major":"1","minor":"29"}`))
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, StaticTokenSource("test-token"))
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("Ping should succeed, got %v", err)
	}
}

// TestFileTokenSource_MissingFile surfaces a helpful error when the SA
// token path is wrong. main.go gates on os.Stat at startup so this won't
// happen in production, but the failure mode should still be informative.
func TestFileTokenSource_MissingFile(t *testing.T) {
	src := FileTokenSource("/nonexistent/no/such/path")
	if _, err := src(); err == nil {
		t.Error("expected error reading missing token file")
	}
}
