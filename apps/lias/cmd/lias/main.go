// Binary lias implements the LAN Internet Access Scheduler.
// It consumes device data from DIS, evaluates policies and schedules,
// and manages an isolated nftables table to enforce network access.
//
// File:    apps/lias/cmd/lias/main.go
// Version: 1.1
package main

import (
    "context"
    "embed"
    "encoding/json"
    "errors"
    "io/fs"
    "log/slog"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    liasAPI "github.com/user/lias-dis/apps/lias/internal/api"
    "github.com/user/lias-dis/apps/lias/internal/config"
    "github.com/user/lias-dis/apps/lias/internal/nftables"
    "github.com/user/lias-dis/apps/lias/internal/policy"
    "github.com/user/lias-dis/apps/lias/internal/schedule"
    liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
    "github.com/user/lias-dis/apps/lias/internal/tags"
    sharedAPI "github.com/user/lias-dis/shared/api"
)

// version is injected at build time using -ldflags "-X main.version=..."
var version = "dev"

//go:embed web/*
var webFS embed.FS

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

    // Core Components
    cache := liasSync.NewCache()
    disClient := liasSync.NewDISClient(cfg.DIS, cache)
    
    tagMgr := tags.NewManager()
    polEng := policy.NewEngine()
    schedEng := schedule.NewEngine(cache)

    // nftables Controller
    nftCtrl := nftables.NewController(cfg.Nftables)
    if err := nftCtrl.Init(); err != nil {
        slog.Error("Failed to initialize nftables", "error", err)
        os.Exit(1)
    }

    builder := nftables.NewBuilder(cache, nftCtrl)
    trigger := make(chan struct{}, 1) // Buffered to prevent blocking
    nftSync := nftables.NewSync(builder, polEng, schedEng, trigger)

    // Context for graceful shutdown
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    // Start background loops
    go disClient.Run(ctx)
    go schedEng.Run(ctx)
    go nftSync.Run(ctx)

    // API Server
    mux := http.NewServeMux()
    handlers := liasAPI.NewHandlers(cache, tagMgr, polEng, schedEng, nftCtrl, trigger)
    handlers.RegisterRoutes(mux)

    mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(sharedAPI.HealthResponse{
            Status:  "ok",
            Version: version,
        })
    })

    // Serve embedded Web UI
    webRoot, err := fs.Sub(webFS, "web")
    if err != nil {
        slog.Error("Failed to load embedded web UI", "error", err)
    } else {
        mux.Handle("/", http.FileServer(http.FS(webRoot)))
    }

    srv := &http.Server{
        Addr:         cfg.HTTP.Listen,
        Handler:      mux,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

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
    }

    // Execute nftables shutdown behavior
    if cfg.Nftables.ShutdownBehavior == "flush" {
        slog.Info("Flushing nftables table due to shutdown behavior config")
        if err := nftCtrl.FlushTable(); err != nil {
            slog.Error("Failed to flush nftables table on shutdown", "error", err)
        }
    }

    slog.Info("LAN Internet Access Scheduler stopped gracefully")
}
