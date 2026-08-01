// Binary discovery-service implements the Discovery Intelligence Service (DIS).
// It observes network activity via netlink, Pi-hole, and DHCP, correlates
// devices, and exposes a REST + SSE API for LIAS to consume.
//
// File:    apps/discovery-service/cmd/discovery-service/main.go
// Version: 1.3
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

    disAPI "github.com/user/lias-dis/apps/discovery-service/internal/api"
    "github.com/user/lias-dis/apps/discovery-service/internal/config"
    "github.com/user/lias-dis/apps/discovery-service/internal/correlation"
    "github.com/user/lias-dis/apps/discovery-service/internal/discovery"
    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    sharedAPI "github.com/user/lias-dis/shared/api"
)

// version is injected at build time using -ldflags "-X main.version=..."
var version = "dev"

func main() {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    slog.SetDefault(logger)

    cfgPath := "/etc/dis/config.yaml"
    if envPath := os.Getenv("DIS_CONFIG"); envPath != "" {
        cfgPath = envPath
    }

    cfg, err := config.Load(cfgPath)
    if err != nil {
        slog.Error("Failed to load configuration", "error", err)
        os.Exit(1)
    }

    // Core components
    cache := inventory.NewCache()
    defer cache.Stop()
    
    broker := disAPI.NewBroker()
    eng := correlation.NewEngine(cache, broker)

    // Context for graceful shutdown
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    // Initialize Providers
    var providers []discovery.DiscoveryProvider
    if cfg.Discovery.Netlink.Enabled {
        providers = append(providers, discovery.NewNetlinkProvider(cfg.Discovery.Interface))
    }
    if cfg.Discovery.Pihole.Enabled {
        providers = append(providers, discovery.NewPiholeProvider(cfg.Discovery.Pihole))
    }
    if cfg.Discovery.DHCP.Enabled {
        providers = append(providers, discovery.NewDHCPProvider(cfg.Discovery.DHCP))
    }

    // Start Providers
    for _, p := range providers {
        if err := p.Start(ctx); err != nil {
            slog.Error("Failed to start provider", "name", p.Name(), "error", err)
        } else {
            slog.Info("Started provider", "name", p.Name())
        }
    }
    
    // Initialize Primary Enrichers (Avahi, SSDP, NetBIOS)
    var primaries []discovery.Enricher
    if cfg.Discovery.Enrichment.AvahiEnabled {
        e := discovery.NewAvahiEnricher()
        _ = e.Start(ctx)
        primaries = append(primaries, e)
    }
    if cfg.Discovery.Enrichment.SSDPEnabled {
        e := discovery.NewSSDPEnricher()
        _ = e.Start(ctx)
        primaries = append(primaries, e)
    }
    if cfg.Discovery.Enrichment.NetbiosEnabled {
        e := discovery.NewNetBIOSEnricher()
        _ = e.Start(ctx)
        primaries = append(primaries, e)
    }

    // Initialize Fallback Enricher (Nmap)
    var fallback discovery.Enricher
    if cfg.Discovery.Enrichment.NmapEnabled {
        e := discovery.NewNmapEnricher()
        _ = e.Start(ctx)
        fallback = e
    }

    // Initialize Orchestrator and wire to Engine
    orch := discovery.NewOrchestrator(cache, broker, primaries, fallback)
    eng.SetOrchestrator(orch)

    // Start Correlation Engine
    eng.Run(ctx, providers)

    // API Server
    mux := http.NewServeMux()
    handlers := disAPI.NewHandlers(cache, broker, orch)
    handlers.RegisterRoutes(mux)

    mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(sharedAPI.HealthResponse{
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

    go func() {
        slog.Info("Starting Discovery Intelligence Service", "version", version, "listen_addr", cfg.HTTP.Listen)
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
