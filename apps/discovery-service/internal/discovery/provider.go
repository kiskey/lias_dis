// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/provider.go
// Version: 1.0
package discovery

import (
    "context"
    "net"
    "time"

    "github.com/user/lias-dis/shared/models"
)

// Provider is the base interface for all discovery and enrichment modules.
// It enforces strict lifecycle management via context propagation.
type Provider interface {
    Name() string
    Start(ctx context.Context) error
    Stop() error
}

// DiscoveryProvider extends Provider to emit real-time observations.
type DiscoveryProvider interface {
    Provider
    Events() <-chan Observation
}

// Enricher extends Provider to provide on-demand detail gathering for a device.
type Enricher interface {
    Provider
    Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error)
}

// Observation represents a single raw data point from a DiscoveryProvider.
// It is normalized into a models.Device by the correlation engine.
type Observation struct {
    Source     string
    MAC        net.HardwareAddr
    IP         net.IP
    Hostname   string
    Vendor     string
    Model      string
    Services   []string
    Confidence float64 // 0.0 - 1.0
    Timestamp  time.Time
}
