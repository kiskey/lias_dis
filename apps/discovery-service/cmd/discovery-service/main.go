// Binary discovery-service implements the Discovery Intelligence Service (DIS).
//
// File:    apps/discovery-service/cmd/discovery-service/main.go
// Version: 1.5
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
	"github.com/user/lias-dis/pkg/oui"
	sharedAPI "github.com/user/lias-dis/shared/api"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

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

	cache := inventory.NewCache()
	defer cache.Stop()

	broker := disAPI.NewBroker()
	eng := correlation.NewEngine(cache, broker)

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
		WriteTimeout: 0, // Set WriteTimeout to 0 (unlimited) for long-lived SSE streams
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
