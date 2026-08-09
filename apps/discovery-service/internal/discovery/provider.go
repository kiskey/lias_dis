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
	var out strings.Builder
	out.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			out.WriteByte(raw[i])
			continue
        }
		if i+3 < len(raw) {
			if value, err := strconv.ParseUint(raw[i+1:i+4], 10, 8); err == nil {
				out.WriteByte(byte(value))
				i += 3
				continue
        }
    }
		if i+1 < len(raw) {
			i++
			out.WriteByte(raw[i])
		}
	}
	return strings.TrimSpace(out.String())
}
