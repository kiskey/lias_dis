// Binary lias implements the LAN Internet Access Scheduler.
// It consumes device data from DIS, evaluates policies and schedules,
// and manages an isolated nftables table to enforce network access.
//
// File:    apps/lias/cmd/lias/main.go
// Version: 1.0
package main

import (
    "context"
    "encoding/json"
    "errors"
    "log/slog"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/user/lias-dis/apps/lias/internal/config"
    "github.com/user/lias-dis/shared/api"
)

// version is injected at build time using -ldflags "-X main.version=..."
var version = "dev"

func main() {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    slog.SetDefault(logger)

    cfgPath := "/etc/lias/config.yaml"
    if envPath := os.Getenv("LIAS_CONFIG"); envPath != "" {
        cfgPath = envPath
    }

    cfg, err := config.Load(cfgPath)
    if err != nil {
        slog.Error("Failed to load configuration", "error", err)
        os.Exit(1)
    }

    mux := http.NewServeMux()

    // /health endpoint
    mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(api.HealthResponse{
            Status:  "ok",
            Version: version,
        })
    })

    srv := &http.Server{
        Addr:         cfg.HTTP.Listen,
        Handler:      mux,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    go func() {
        slog.Info("Starting LAN Internet Access Scheduler", "version", version, "listen_addr", cfg.HTTP.Listen)
        if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
            slog.Error("HTTP server failed", "error", err)
            os.Exit(1)
        }
    }()

    <-ctx.Done()
    slog.Info("Shutdown signal received, draining connections...")

    shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    if err := srv.Shutdown(shutdownCtx); err != nil {
        slog.Error("Graceful shutdown failed", "error", err)
        os.Exit(1)
    }

    // TODO: Execute nftables shutdown behavior (flush or persist) based on cfg.Nftables.ShutdownBehavior (Phase 5)

    slog.Info("LAN Internet Access Scheduler stopped gracefully")
}
