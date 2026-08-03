// Package discovery implements observation, enrichment, and correlation for DIS.
//
// File:    apps/discovery-service/internal/discovery/provider.go
// Version: 2.1
package discovery

import (
    "context"
    "net"
    "strconv"
    "strings"
    "time"

    "github.com/user/lias-dis/shared/models"
)

// ProviderGroup identifies the observation layer for provider-independence checks.
type ProviderGroup string

const (
    GroupA ProviderGroup = "L2_netlink"
    GroupB ProviderGroup = "L3_dhcp"
    GroupC ProviderGroup = "L3_pihole"
    GroupD ProviderGroup = "L7_name"
    GroupE ProviderGroup = "L7_active"
)

// Provider is the base interface for all discovery and enrichment modules.
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
type Observation struct {
    Source     string
    Group      ProviderGroup
    MAC        net.HardwareAddr
    IP         net.IP
    Hostname   string
    Vendor     string
    Model      string
    Services   []string
    Confidence float64
    Timestamp  time.Time
    Online     bool
    Raw        map[string]interface{} // NEW: Raw metadata for advanced validation (e.g., mdns_host)
}

// UnescapeHostname converts raw octal escape sequences (\058 -> :) and cleans mDNS hostnames.
func UnescapeHostname(raw string) string {
    if raw == "" {
        return ""
    }

    s := raw
    for {
        idx := strings.Index(s, "\\0")
        if idx == -1 || idx+4 > len(s) {
            break
        }
        octalCode := s[idx+2 : idx+4]
        if val, err := strconv.ParseInt(octalCode, 8, 64); err == nil {
            s = s[:idx] + string(rune(val)) + s[idx+4:]
        } else {
            break
        }
    }

    s = strings.ReplaceAll(s, "\\.", ".")
    s = strings.ReplaceAll(s, "\\", "")
    return strings.TrimSpace(s)
}
