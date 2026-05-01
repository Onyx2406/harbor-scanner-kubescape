package scan

import (
	"strings"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/k8s"
)

// TransformManifestToReport converts a VulnerabilityManifest CRD into a Harbor ScanReport.
func TransformManifestToReport(vm *k8s.VulnerabilityManifest, artifact harbor.Artifact) harbor.ScanReport {
	report := harbor.ScanReport{
		GeneratedAt: vm.CreatedAt,
		Artifact:    artifact,
		Scanner: harbor.Scanner{
			Name:    "Kubescape",
			Vendor:  "ARMO",
			Version: vm.ToolVersion,
		},
	}

	var highestSeverity harbor.Severity
	for _, m := range vm.Matches {
		fixVersion := ""
		if len(m.FixVersions) > 0 {
			fixVersion = m.FixVersions[0]
		}

		sev := mapSeverity(m.Severity)
		if sev > highestSeverity {
			highestSeverity = sev
		}

		item := harbor.VulnerabilityItem{
			ID:          m.ID,
			Pkg:         m.PkgName,
			Version:     m.PkgVersion,
			FixVersion:  fixVersion,
			Severity:    sev,
			Description: m.Description,
			Links:       m.URLs,
			CweIDs:      m.CweIDs,
		}

		// Map CVSS if available
		if len(m.CVSS) > 0 {
			cvss := &harbor.CVSSDetails{}
			for _, c := range m.CVSS {
				score := float32(c.BaseScore)
				if strings.HasPrefix(c.Version, "3") {
					cvss.ScoreV3 = &score
					cvss.VectorV3 = c.Vector
				} else if strings.HasPrefix(c.Version, "2") {
					cvss.ScoreV2 = &score
					cvss.VectorV2 = c.Vector
				}
			}
			item.CVSS = cvss
		}

		report.Vulnerabilities = append(report.Vulnerabilities, item)
	}

	report.Severity = highestSeverity

	// Ensure non-nil slice for JSON serialization
	if report.Vulnerabilities == nil {
		report.Vulnerabilities = []harbor.VulnerabilityItem{}
	}

	return report
}

// BuildPlaceholderReport creates a minimal report for when kubevuln has been triggered
// but VulnerabilityManifest CRD is not yet available.
func BuildPlaceholderReport(artifact harbor.Artifact) harbor.ScanReport {
	return harbor.ScanReport{
		GeneratedAt: time.Now().UTC(),
		Artifact:    artifact,
		Scanner: harbor.Scanner{
			Name:    "Kubescape",
			Vendor:  "ARMO",
			Version: "v3.0.0",
		},
		Vulnerabilities: []harbor.VulnerabilityItem{},
	}
}

var severityMap = map[string]harbor.Severity{
	"CRITICAL":   harbor.SevCritical,
	"HIGH":       harbor.SevHigh,
	"MEDIUM":     harbor.SevMedium,
	"LOW":        harbor.SevLow,
	"NEGLIGIBLE": harbor.SevNegligible,
	"UNKNOWN":    harbor.SevUnknown,
}

func mapSeverity(s string) harbor.Severity {
	sev, ok := severityMap[strings.ToUpper(s)]
	if !ok {
		return harbor.SevUnknown
	}
	return sev
}
