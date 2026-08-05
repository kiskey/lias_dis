// Package discovery implements observation, enrichment, and correlation for DIS.
//
// File:    apps/discovery-service/internal/discovery/provider.go
// Version: 2.2 (Verified Interfaces)
package discovery

import (
    "context"
    "net"
    "strconv"
    "strings"
    "time"

    "github.com/user/lias-dis/shared/models"
)

type ProviderGroup string

const (
    GroupA ProviderGroup = "L2_netlink"
    GroupB ProviderGroup = "L3_dhcp"
    GroupC ProviderGroup = "L3_pihole"
    GroupD ProviderGroup = "L7_name"
    GroupE ProviderGroup = "L7_active"
)

type Provider interface {
    Name() string
    Start(ctx context.Context) error
    Stop() error
}

type DiscoveryProvider interface {
    Provider
    Events() <-chan Observation
}

type Enricher interface {
    Provider
    Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error)
}

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
    Raw        map[string]interface{}
}

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
