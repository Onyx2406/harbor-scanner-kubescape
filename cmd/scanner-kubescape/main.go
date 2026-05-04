package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/config"
	v1 "github.com/goharbor/harbor-scanner-kubescape/pkg/http/api/v1"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/k8s"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence/memory"
	persistenceredis "github.com/goharbor/harbor-scanner-kubescape/pkg/persistence/redis"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/scan"
	"github.com/redis/go-redis/v9"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load config", slog.String("err", err.Error()))
		os.Exit(1)
	}

	buildInfo := config.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	ctx := context.Background()
	if err := run(ctx, cfg, buildInfo); err != nil {
		slog.Error("Unexpected error", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config.Config, buildInfo config.BuildInfo) error {
	slog.Info("Starting harbor-scanner-kubescape",
		slog.String("version", buildInfo.Version),
		slog.String("commit", buildInfo.Commit),
	)

	store, storeCloser, storeReadiness, err := buildStore(cfg.Persistence)
	if err != nil {
		return fmt.Errorf("initializing persistence backend: %w", err)
	}
	if storeCloser != nil {
		defer storeCloser()
	}
	slog.Info("Persistence backend ready", slog.String("backend", string(cfg.Persistence.Backend)))

	scanner := scan.NewScanner(cfg.Kubevuln)

	// Initialize K8s client for VulnerabilityManifest CRD access.
	// Uses in-cluster service account when running in Kubernetes.
	// Falls back to no-K8s mode (direct kubevuln only) when not in cluster.
	var k8sClient k8s.Client
	k8sAPIServer := os.Getenv("KUBERNETES_SERVICE_HOST")
	k8sToken, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if k8sAPIServer != "" && len(k8sToken) > 0 {
		k8sPort := os.Getenv("KUBERNETES_SERVICE_PORT")
		if k8sPort == "" {
			k8sPort = "443"
		}
		baseURL := "https://" + k8sAPIServer + ":" + k8sPort
		k8sClient = k8s.NewRESTClient(baseURL, string(k8sToken))
		slog.Info("K8s client initialized for VulnerabilityManifest CRD access",
			slog.String("api_server", baseURL),
		)
	} else {
		slog.Warn("Not running in Kubernetes cluster — VulnerabilityManifest CRD lookup disabled. " +
			"Scan requests will fail with HTTP 500 until k8s access is provided. " +
			"This warning is expected for local dev; in production, ensure the pod has " +
			"a service account with read access to vulnerabilitymanifests.spdx.softwarecomposition.kubescape.io.")
	}

	slog.Info("Scan controller configured",
		slog.Duration("reuse_ttl", cfg.Scan.ReuseTTL),
	)
	controller := scan.NewController(store, scanner, k8sClient, cfg.Kubevuln.Namespace, cfg.Scan.ReuseTTL)

	// Readiness gates. Composed from:
	//   * kubernetes-client — the adapter cannot observe scan results without
	//     it, so the pod must be NotReady when nil. See issue #16.
	//   * backend-specific checks returned by buildStore — for the Redis
	//     backend this is a live, timeout-bounded Ping so a Redis outage at
	//     runtime takes the pod out of rotation. See issue #25.
	readiness := []v1.ReadinessCheck{
		{
			Name: "kubernetes-client",
			Check: func() error {
				if k8sClient == nil {
					return fmt.Errorf("kubernetes client unavailable; pod cannot read VulnerabilityManifest CRDs")
				}
				return nil
			},
		},
	}
	readiness = append(readiness, storeReadiness...)

	handler := v1.NewAPIHandler(buildInfo, cfg, store, controller, readiness...)

	srv := &http.Server{
		Addr:         cfg.API.Addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		captured := <-sigint
		slog.Info("Received signal, shutting down", slog.String("signal", captured.String()))

		shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("Server shutdown error", slog.String("err", err.Error()))
		}
		close(shutdownComplete)
	}()

	if cfg.API.TLSEnabled() {
		slog.Info("Listening (TLS)",
			slog.String("addr", cfg.API.Addr),
			slog.String("cert", cfg.API.TLSCertFile),
		)
		if err := srv.ListenAndServeTLS(cfg.API.TLSCertFile, cfg.API.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			return err
		}
	} else {
		slog.Info("Listening (plain HTTP — terminate TLS at ingress/service mesh)",
			slog.String("addr", cfg.API.Addr),
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
	}

	<-shutdownComplete
	return nil
}

// readinessCheckTimeout is how long a backend readiness check is allowed to
// run before being treated as a failure. Tight on purpose — readiness fires
// every few seconds and we don't want a slow Redis to become a self-DoS.
const readinessCheckTimeout = 2 * time.Second

// buildStore selects and constructs a persistence.Store based on config and
// returns the backend-specific readiness checks the handler should run on
// every /probe/ready hit (issue #25).
//
// The returned closer (if non-nil) should be called on shutdown to release
// connections cleanly. Errors at startup are fatal: Harbor's scanner spec
// has no notion of an adapter without persistence, so misconfiguration
// fails closed rather than silently using memory.
func buildStore(cfg config.PersistenceConfig) (persistence.Store, func(), []v1.ReadinessCheck, error) {
	switch cfg.Backend {
	case "", config.BackendMemory:
		s := memory.NewStore(
			memory.WithRetention(cfg.Memory.Retention),
			memory.WithCleanupInterval(cfg.Memory.CleanupInterval),
		)
		slog.Info("Memory store configured",
			slog.Duration("retention", cfg.Memory.Retention),
			slog.Duration("cleanup_interval", cfg.Memory.CleanupInterval),
		)
		// Memory backend has no remote dependency; nothing to probe.
		return s, s.Close, nil, nil

	case config.BackendRedis:
		if cfg.Redis.URL == "" {
			return nil, nil, nil, fmt.Errorf("PERSISTENCE_BACKEND=redis requires REDIS_URL")
		}
		opts, err := redis.ParseURL(cfg.Redis.URL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parsing REDIS_URL: %w", err)
		}
		client := redis.NewClient(opts)

		// Fail fast on bad credentials / unreachable host so the pod
		// crashloops with a clear message instead of silently 500ing
		// every scan.
		pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Ping(pingCtx).Err(); err != nil {
			_ = client.Close()
			return nil, nil, nil, fmt.Errorf("redis ping at %s: %w", opts.Addr, err)
		}

		s := persistenceredis.NewStore(client, persistenceredis.WithTTL(cfg.Redis.TTL))

		// Live readiness probe — runs on every /probe/ready hit. A Redis
		// outage at runtime now takes the pod out of rotation instead of
		// leaving it Ready while every Create/Get fails (issue #25).
		checks := []v1.ReadinessCheck{
			{
				Name: "redis",
				Check: func() error {
					ctx, cancel := context.WithTimeout(context.Background(), readinessCheckTimeout)
					defer cancel()
					return s.Ping(ctx)
				},
			},
		}
		return s, func() { _ = client.Close() }, checks, nil

	default:
		return nil, nil, nil, fmt.Errorf("unknown PERSISTENCE_BACKEND %q (expected %q or %q)",
			cfg.Backend, config.BackendMemory, config.BackendRedis)
	}
}
