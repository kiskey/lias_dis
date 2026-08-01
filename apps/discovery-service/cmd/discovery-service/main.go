// Binary discovery-service implements the Discovery Intelligence Service (DIS).
// It observes network activity via netlink, Pi-hole, and DHCP, correlates
// devices, and exposes a REST + SSE API for LIAS to consume.
//
// File:    apps/discovery-service/cmd/discovery-service/main.go
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

    "github.com/user/lias-dis/shared/api"
)

// version is injected at build time using -ldflags "-X main.version=..."
var version = "dev"

func main() {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    slog.SetDefault(logger)

    // TODO: Load configuration from /etc/dis/config.yaml (Phase 2+)
    listenAddr := ":8080"

    mux := http.NewServeMux()

    // /health endpoint (using Go 1.22+ routing patterns)
    mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(api.HealthResponse{
            Status:  "ok",
            Version: version,
        })
    })

    srv := &http.Server{
        Addr:         listenAddr,
        Handler:      mux,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 30 * time.Second, // Longer for SSE
        IdleTimeout:  120 * time.Second,
    }

    // Graceful shutdown context
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    go func() {
        slog.Info("Starting Discovery Intelligence Service", "version", version, "listen_addr", listenAddr)
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

    slog.Info("Discovery Intelligence Service stopped gracefully")
}
