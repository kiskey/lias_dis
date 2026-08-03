// Binary discovery-service implements the Discovery Intelligence Service (DIS).
//
// File:    apps/discovery-service/cmd/discovery-service/main.go
// Version: 2.0
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

	disAPI "github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/config"
	"github.com/user/lias-dis/apps/discovery-service/internal/correlation"
	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/apps/discovery-service/internal/storage"
	"github.com/user/lias-dis/pkg/oui"
	sharedAPI "github.com/user/lias-dis/shared/api"
)

var version = "dev"

func main() {
	_ = oui.Get()

	cfgPath := "/etc/dis/config.yaml"
	if envPath := os.Getenv("DIS_CONFIG"); envPath != "" {
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

	cache := inventory.NewCache()
	defer cache.Stop()

	st, err := storage.NewStorage(cfg.Storage.Path)
	if err != nil {
		slog.Warn("DIS Storage initialization failed, running in memory-only mode", "error", err)
	} else {
		defer st.Close()
		if hydratedDevs, err := st.LoadHydrate(); err == nil {
			for _, dev := range hydratedDevs {
				dCopy := dev
				cache.Upsert(&dCopy)
			}
		}
	}

	// Step 5 Fix: Pass Cache handle to Broker for SSE reconnect rehydration filtering
	broker := disAPI.NewBroker(cache)
	eng := correlation.NewEngine(cache, broker)
	if st != nil {
		eng.SetStorage(st)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	for _, p := range providers {
		if err := p.Start(ctx); err != nil {
			slog.Error("Failed to start provider", "name", p.Name(), "error", err)
		} else {
			slog.Info("Started provider", "name", p.Name())
		}
	}

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

	var fallback discovery.Enricher
	if cfg.Discovery.Enrichment.NmapEnabled {
		e := discovery.NewNmapEnricher()
		_ = e.Start(ctx)
		fallback = e
	}

	orch := discovery.NewOrchestrator(cache, broker, primaries, fallback)
	eng.SetOrchestrator(orch)

	eng.Run(ctx, providers)

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
		WriteTimeout: 0,
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
		slog.Error("Graceful shutdown error", "error", err)
	}

	slog.Info("Discovery Intelligence Service stopped gracefully")
}
