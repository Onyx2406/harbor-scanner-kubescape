package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/config"
	v1 "github.com/goharbor/harbor-scanner-kubescape/pkg/http/api/v1"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/k8s"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence/memory"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/scan"
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

	store := memory.NewStore()
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
		slog.Warn("Not running in Kubernetes cluster, VulnerabilityManifest CRD lookup disabled")
	}

	controller := scan.NewController(store, scanner, k8sClient, cfg.Kubevuln.Namespace)
	handler := v1.NewAPIHandler(buildInfo, cfg, store, controller)

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
