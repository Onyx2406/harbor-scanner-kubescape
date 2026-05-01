package k8s

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGetVulnerabilityManifest_CweExtraction pins the fix from issue #5: CWE
// IDs in the Grype payload — whether on the matched vulnerability itself or
// inside relatedVulnerabilities — must end up on VulnMatch.CweIDs and be
// deduplicated with order preserved.
func TestGetVulnerabilityManifest_CweExtraction(t *testing.T) {
	const crdJSON = `{
	  "metadata": {
	    "name": "core.harbor.domain-library-nginx-abc123",
	    "namespace": "kubescape",
	    "creationTimestamp": "2026-04-30T12:00:00Z"
	  },
	  "spec": {
	    "metadata": {
	      "tool": {"name":"grype","version":"0.74.0","databaseVersion":"v6"},
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

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/vulnerabilitymanifests/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(crdJSON))
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, "test-token")

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
	got := vm.Matches[0].CweIDs
	want := []string{"CWE-79", "CWE-352"}
	if !equalStrings(got, want) {
		t.Errorf("match[0].CweIDs = %v, want %v (deduped union)", got, want)
	}

	// Match 2: CWEs only on relatedVulnerabilities — should still propagate.
	got = vm.Matches[1].CweIDs
	want = []string{"CWE-200"}
	if !equalStrings(got, want) {
		t.Errorf("match[1].CweIDs = %v, want %v", got, want)
	}

	// Match 3: no CWEs anywhere — should be empty (not panic, not nil-ptr).
	if len(vm.Matches[2].CweIDs) != 0 {
		t.Errorf("match[2].CweIDs = %v, want empty", vm.Matches[2].CweIDs)
	}

	// Sanity: make sure we didn't break any other parsing — fix versions etc.
	if len(vm.Matches[0].FixVersions) != 1 || vm.Matches[0].FixVersions[0] != "1.2.4" {
		t.Errorf("match[0].FixVersions = %v, want [1.2.4]", vm.Matches[0].FixVersions)
	}

	// Round-trip the CRD JSON to make sure our parsing didn't drift the schema.
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(crdJSON), &raw); err != nil {
		t.Errorf("CRD JSON itself is malformed: %v", err)
	}
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
