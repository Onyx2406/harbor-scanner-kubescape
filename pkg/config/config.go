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
type APIConfig struct {
	Addr string
}

// KubevulnConfig holds configuration for communicating with kubevuln.
type KubevulnConfig struct {
	// URL is the base URL of the kubevuln service (e.g. http://kubevuln:8080)
	URL string
	// Namespace is the Kubernetes namespace where VulnerabilityManifest CRDs are stored.
	Namespace string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() (Config, error) {
	cfg := Config{
		API: APIConfig{
			Addr: envOrDefault("SCANNER_API_ADDR", ":8443"),
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
