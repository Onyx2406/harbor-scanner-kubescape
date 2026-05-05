package scan

import (
	"strings"

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

		// Map CVSS — pick the HIGHEST base score per version. Grype can
		// emit multiple CVSS entries (NVD + vendor + RedHat) for the
		// same CVE; the previous "last entry wins" was deterministic
		// but order-dependent and could quietly understate severity if
		// the vendor's score happened to come last. Prefer worst-case.
		if len(m.CVSS) > 0 {
			cvss := &harbor.CVSSDetails{}
			for _, c := range m.CVSS {
				score := float32(c.BaseScore)
				if strings.HasPrefix(c.Version, "3") {
					if cvss.ScoreV3 == nil || score > *cvss.ScoreV3 {
						cvss.ScoreV3 = &score
						cvss.VectorV3 = c.Vector
					}
				} else if strings.HasPrefix(c.Version, "2") {
					if cvss.ScoreV2 == nil || score > *cvss.ScoreV2 {
						cvss.ScoreV2 = &score
						cvss.VectorV2 = c.Vector
					}
				}
			}
			item.CVSS = cvss
		}

		report.Vulnerabilities = append(report.Vulnerabilities, item)
	}

	// Overall severity. Two cases:
	//   * non-empty manifest → highest severity across matches
	//   * empty manifest     → SevNegligible. Pre-fix this stayed at the
	//     zero value, which the Severity.MarshalJSON fallback emits as
	//     "Unknown" — confusing for a clean image. Negligible is the
	//     lowest enum the Harbor scanner spec recognises and accurately
	//     conveys "scanned, nothing noteworthy."
	if len(report.Vulnerabilities) == 0 {
		report.Severity = harbor.SevNegligible
		report.Vulnerabilities = []harbor.VulnerabilityItem{}
	} else {
		report.Severity = highestSeverity
	}

	return report
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
