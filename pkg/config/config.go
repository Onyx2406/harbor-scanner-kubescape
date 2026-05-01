package config

import (
	"os"
	"time"
)

// BuildInfo holds version information set at build time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// Config holds all configuration for the scanner adapter.
type Config struct {
	API         APIConfig
	Kubevuln    KubevulnConfig
	Scan        ScanConfig
	Persistence PersistenceConfig
}

// ScanConfig holds policy knobs for the scan controller.
type ScanConfig struct {
	// ReuseTTL is the freshness window for an existing VulnerabilityManifest
	// CRD. Anything older triggers a fresh scan so newly disclosed CVEs in
	// the Grype DB get picked up. Zero disables reuse outright. See issue #14.
	ReuseTTL time.Duration
}

// PersistenceConfig holds knobs for the in-memory persistence store. See
// pkg/persistence/memory for behavior details. Issue #17.
type PersistenceConfig struct {
	// MemoryRetention is how long a Finished/Failed job is kept in memory
	// before the janitor evicts it. Long enough to outlast Harbor's poll
	// loop; short enough to bound memory.
	MemoryRetention time.Duration
	// MemoryCleanupInterval is how often the janitor runs.
	MemoryCleanupInterval time.Duration
}

// APIConfig holds HTTP server configuration.
//
// TLSCertFile and TLSKeyFile are optional. When both are set, the server
// uses HTTPS (ListenAndServeTLS). Otherwise the server uses plain HTTP and
// callers are expected to terminate TLS at an ingress / service mesh layer.
type APIConfig struct {
	Addr        string
	TLSCertFile string
	TLSKeyFile  string
}

// TLSEnabled reports whether both cert and key paths are set.
func (a APIConfig) TLSEnabled() bool {
	return a.TLSCertFile != "" && a.TLSKeyFile != ""
}

// KubevulnConfig holds configuration for communicating with kubevuln.
type KubevulnConfig struct {
	// URL is the base URL of the kubevuln service (e.g. http://kubevuln:8080)
	URL string
	// Namespace is the Kubernetes namespace where VulnerabilityManifest CRDs are stored.
	Namespace string
}

// Load reads configuration from environment variables with sensible defaults.
//
// The default listen address is :8080 (plain HTTP). To enable TLS, set both
// SCANNER_API_TLS_CERT and SCANNER_API_TLS_KEY to filesystem paths of a
// PEM-encoded certificate and key, and typically set SCANNER_API_ADDR to :8443.
func Load() (Config, error) {
	cfg := Config{
		API: APIConfig{
			Addr:        envOrDefault("SCANNER_API_ADDR", ":8080"),
			TLSCertFile: os.Getenv("SCANNER_API_TLS_CERT"),
			TLSKeyFile:  os.Getenv("SCANNER_API_TLS_KEY"),
		},
		Kubevuln: KubevulnConfig{
			URL:       envOrDefault("KUBEVULN_URL", "http://kubevuln:8080"),
			Namespace: envOrDefault("KUBEVULN_NAMESPACE", "kubescape"),
		},
		Scan: ScanConfig{
			ReuseTTL: durationFromEnv("SCAN_REUSE_TTL", 24*time.Hour),
		},
		Persistence: PersistenceConfig{
			MemoryRetention:       durationFromEnv("MEMORY_STORE_RETENTION", 1*time.Hour),
			MemoryCleanupInterval: durationFromEnv("MEMORY_STORE_CLEANUP_INTERVAL", 5*time.Minute),
		},
	}

	return cfg, nil
}

// durationFromEnv reads a Go duration from the named env var, falling back to
// the provided default if unset or unparseable. Examples: "1h", "30m", "0s".
// A non-positive duration disables the relevant feature.
func durationFromEnv(key string, defaultValue time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return defaultValue
	}
	return d
}

func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
