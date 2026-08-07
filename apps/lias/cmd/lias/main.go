// Binary lias implements the LAN Internet Access Scheduler.
//
// File:    apps/lias/cmd/lias/main.go
// Version: 2.6 (Added 15s sweep loop for temporary policies)
package main

import (
    "context"
    "encoding/json"
    "errors"
    "log/slog"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    liasAPI "github.com/user/lias-dis/apps/lias/internal/api"
    "github.com/user/lias-dis/apps/lias/internal/config"
    "github.com/user/lias-dis/apps/lias/internal/metrics"
    "github.com/user/lias-dis/apps/lias/internal/nftables"
    "github.com/user/lias-dis/apps/lias/internal/policy"
    "github.com/user/lias-dis/apps/lias/internal/schedule"
    "github.com/user/lias-dis/apps/lias/internal/storage"
    liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
    "github.com/user/lias-dis/apps/lias/internal/tags"
    "github.com/user/lias-dis/apps/lias/web"
    sharedAPI "github.com/user/lias-dis/shared/api"
)

var version = "dev"

func main() {
    cfgPath := "/etc/lias/config.yaml"
    if envPath := os.Getenv("LIAS_CONFIG"); envPath != "" {
        cfgPath = envPath
    }

    cfg, err := config.Load(cfgPath)
    if err != nil {
        slog.Error("Failed to load configuration", "error", err)
        os.Exit(1)
    }

    var level slog.Level
    switch strings.ToLower(cfg.Logging.Level) {
    case "debug":
        level = slog.LevelDebug
    case "warn":
        level = slog.LevelWarn
    case "error":
        level = slog.LevelError
    default:
        level = slog.LevelInfo
    }

    opts := &slog.HandlerOptions{Level: level}
    var handler slog.Handler
    if strings.ToLower(cfg.Logging.Format) == "text" {
        handler = slog.NewTextHandler(os.Stdout, opts)
    } else {
        handler = slog.NewJSONHandler(os.Stdout, opts)
    }
    slog.SetDefault(slog.New(handler))

    cache := liasSync.NewCache()
    trigger := make(chan struct{}, 1)

    broker := liasAPI.NewBroker()
    defer broker.Stop()

    tagMgr := tags.NewManager()
    polEng := policy.NewEngine()
    schedEng := schedule.NewEngine(cache, polEng, trigger)

    var store *storage.Storage
    st, err := storage.NewStorage(cfg.Storage.Path)
    if err != nil {
        slog.Warn("Storage initialization failed, running in memory-only mode", "error", err)
    } else {
        defer st.Close()
        deviceTags, macTags, _ := st.LoadHydrate(tagMgr, polEng, schedEng)
        cache.LoadStickyTags(deviceTags, macTags)
        store = st
    }

    disClient := liasSync.NewDISClient(cfg.DIS, cache, trigger, broker, store)

    nftCtrl := nftables.NewController(cfg.Nftables)
    if err := nftCtrl.Init(); err != nil {
        slog.Error("Failed to initialize nftables controller", "error", err)
        os.Exit(1)
    }

    builder := nftables.NewBuilder(cache, nftCtrl)
    nftSync := nftables.NewSync(builder, polEng, schedEng, trigger)

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    go disClient.Run(ctx)
    go schedEng.Run(ctx)
    go nftSync.Run(ctx)

    // Temporary Policy Sweep Loop (Pause & Extend Access)
    // Checks every 15 seconds for expired temporary policies and cleans them up.
    go func() {
        ticker := time.NewTicker(15 * time.Second)
        defer ticker.Stop()
        for range ticker.C {
            expiredPolicies, ownedScheds := polEng.SweepExpired(time.Now())
            if len(expiredPolicies) == 0 {
                continue
            }
            for _, id := range expiredPolicies {
                if store != nil {
                    _ = store.DeletePolicy(id)
                }
                // Broadcast SSE update for the affected target
                if strings.HasPrefix(id, "pol_extend_device_") || strings.HasPrefix(id, "pol_pause_") {
                    pdid := strings.TrimPrefix(id, "pol_extend_device_")
                    pdid = strings.TrimPrefix(pdid, "pol_pause_")
                    broker.BroadcastEffectiveStatusChanged("device", pdid)
                } else if strings.HasPrefix(id, "pol_extend_tag_") {
                    tagID := strings.TrimPrefix(id, "pol_extend_tag_")
                    broker.BroadcastEffectiveStatusChanged("tag", tagID)
                }
            }
            for _, sid := range ownedScheds {
                schedEng.DeleteSchedule(sid)
                if store != nil {
                    _ = store.DeleteSchedule(sid)
                }
            }
            slog.Info("Swept expired temporary policies", "count", len(expiredPolicies))
            select {
            case trigger <- struct{}{}:
            default:
            }
        }
    }()

    if err := builder.Sync(polEng, schedEng); err != nil {
        slog.Warn("Initial nftables sync warning", "error", err)
    }

    mux := http.NewServeMux()
    handlers := liasAPI.NewHandlers(cache, tagMgr, polEng, schedEng, nftCtrl, store, trigger, broker)
    handlers.RegisterRoutes(mux, cfg.HTTP.AuthToken)

    metrics.RegisterHandler(mux, "/metrics")

    mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(sharedAPI.HealthResponse{
            Status:  "ok",
            Version: version,
        })
    })

    mux.Handle("/", http.FileServer(http.FS(web.FS())))

    srv := &http.Server{
        Addr:         cfg.HTTP.Listen,
        Handler:      mux,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 0,
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
        slog.Error("Graceful shutdown error", "error", err)
    }

    if cfg.Nftables.ShutdownBehavior == "flush" {
        slog.Info("Flushing nftables netdev table on shutdown")
        if err := nftCtrl.FlushTable(); err != nil {
            slog.Error("Failed to flush nftables on shutdown", "error", err)
        }
    }

    slog.Info("LAN Internet Access Scheduler stopped gracefully")
}
