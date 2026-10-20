// Command sre-tool isolates workloads from each other's network traffic and
// hardens workloads that lack resource or securityContext settings.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/rustycom/sre-tool/internal/config"
	"github.com/rustycom/sre-tool/internal/httpapi"
	"github.com/rustycom/sre-tool/internal/isolation"
	"github.com/rustycom/sre-tool/internal/kube"
	"github.com/rustycom/sre-tool/internal/metrics"
)

// version is set at build time with -ldflags "-X main.version=<git sha>".
var version = "dev"

const (
	readinessInterval = 5 * time.Second
	shutdownGrace     = 25 * time.Second // SPEC §9: in-flight requests get up to 25s
	startupAttempts   = 5
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sre-tool:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Args[1:], os.Getenv)
	if err != nil {
		return err
	}
	if cfg.ShowVersion {
		fmt.Println(version)
		return nil
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))

	restCfg, err := kube.RESTConfig(cfg.Kubeconfig, cfg.KubeContext)
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Handler contexts derive from base, which is cancelled only after the
	// grace period, so a SIGTERM does not abort in-flight requests at once.
	base, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()

	recorder, stopEvents, err := kube.NewRecorder(base, client)
	if err != nil {
		return err
	}
	defer stopEvents()

	m := metrics.New()
	svc := isolation.NewService(client, recorder, cfg.PodCIDRs, cfg.ProtectedNamespaces, m.IsolationsActive)
	ready := httpapi.NewReadiness(func(ctx context.Context) error {
		return client.Discovery().RESTClient().Get().AbsPath("/version").Do(ctx).Error()
	}, time.Now)

	waitForAPIServer(ctx, ready, logger)
	if err := svc.RefreshActive(ctx); err != nil {
		logger.Warn("could not count active isolations at startup", "error", err)
	}
	go ready.Run(ctx, readinessInterval)

	apiSrv := httpapi.NewServer(base, cfg.APIAddr, httpapi.NewAPIHandler(svc, logger, m))
	opsSrv := httpapi.NewServer(base, cfg.OpsAddr, httpapi.NewOpsHandler(ready, m.Handler()))
	errc := make(chan error, 2)
	for _, srv := range []*http.Server{apiSrv, opsSrv} {
		go func() {
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("listen on %s: %w", srv.Addr, err)
			}
		}()
	}
	logger.Info("started", "version", version, "api_addr", cfg.APIAddr, "ops_addr", cfg.OpsAddr, "ready", ready.Ready())

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case runErr = <-errc:
	}

	// SPEC §9: readiness goes false, listeners stop, in-flight requests get
	// the grace period, then their contexts are cancelled.
	ready.ShutDown()
	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	for _, srv := range []*http.Server{apiSrv, opsSrv} {
		if err := srv.Shutdown(shutCtx); err != nil {
			logger.Warn("shutdown", "addr", srv.Addr, "error", err)
		}
	}
	cancelBase()
	return runErr
}

// waitForAPIServer probes the API server with exponential backoff. If it
// never answers, the tool still starts, but not ready: the readiness loop
// keeps probing, and the kubelet keeps traffic away until it succeeds.
func waitForAPIServer(ctx context.Context, ready *httpapi.Readiness, logger *slog.Logger) {
	delay := time.Second
	for attempt := 1; attempt <= startupAttempts; attempt++ {
		pctx, cancel := context.WithTimeout(ctx, readinessInterval)
		err := ready.Probe(pctx)
		cancel()
		if err == nil {
			return
		}
		logger.Warn("API server not reachable", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
	}
	logger.Error("API server still not reachable; starting not ready")
}
