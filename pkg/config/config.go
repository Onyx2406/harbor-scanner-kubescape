package config

import (
	"os"
)

// BuildInfo holds version information set at build time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// Config holds all configuration for the scanner adapter.
type Config struct {
	API      APIConfig
	Kubevuln KubevulnConfig
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
	}

	return cfg, nil
}

func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
