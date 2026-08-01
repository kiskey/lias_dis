// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/netlink_provider.go
// Version: 1.0
package discovery

import (
    "context"
    "fmt"
    "log/slog"
    "net"
    "time"

    "github.com/vishvananda/netlink"
)

// NetlinkProvider subscribes to the Linux kernel neighbor table (ARP/NDP)
// to provide real-time, authoritative device presence data.
type NetlinkProvider struct {
    ctx     context.Context
    cancel  context.CancelFunc
    events  chan Observation
    done    chan struct{}
    iface   string
}

// NewNetlinkProvider initializes the netlink subscriber for a specific interface.
// If iface is empty, it subscribes to all interfaces.
func NewNetlinkProvider(iface string) *NetlinkProvider {
    return &NetlinkProvider{
        events: make(chan Observation, 256),
        done:   make(chan struct{}),
        iface:  iface,
    }
}

// Name returns the provider's identifier.
func (p *NetlinkProvider) Name() string { return "netlink" }

// Start begins listening for neighbor updates. It seeds the initial state
// with currently existing neighbors, then subscribes to live updates.
func (p *NetlinkProvider) Start(ctx context.Context) error {
    p.ctx, p.cancel = context.WithCancel(ctx)

    // 1. Seed existing neighbors
    neighs, err := netlink.NeighList(0, 0)
    if err != nil {
        return fmt.Errorf("failed to list existing neighbors: %w", err)
    }

    go func() {
        defer close(p.done)
        
        // Emit existing neighbors
        for _, n := range neighs {
            if p.iface != "" {
                link, err := netlink.LinkByIndex(n.LinkIndex)
                if err != nil || link.Attrs().Name != p.iface {
                    continue
                }
            }
            p.emitObservation(n, true)
        }

        // 2. Subscribe to live neighbor updates
        ch := make(chan netlink.NeighUpdate)
        done := make(chan struct{})
        
        if err := netlink.NeighSubscribe(ch, done); err != nil {
            slog.Error("Netlink subscription failed", "error", err)
            return
        }

        for {
            select {
            case <-p.ctx.Done():
                close(done)
                return
            case update, ok := <-ch:
                if !ok {
                    return
                }
                // Filter by interface if configured
                if p.iface != "" {
                    link, err := netlink.LinkByIndex(update.Neigh.LinkIndex)
                    if err != nil || link.Attrs().Name != p.iface {
                        continue
                    }
                }
                
                isAdd := update.Type == 0x01 // RTM_NEWNEIGH
                p.emitObservation(update.Neigh, isAdd)
            }
        }
    }()

    return nil
}

// emitObservation translates a netlink.Neigh into an Observation and sends it.
func (p *NetlinkProvider) emitObservation(n netlink.Neigh, online bool) {
    if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 {
        return // Skip incomplete entries (e.g., failed ARP resolutions)
    }

    obs := Observation{
        Source:     p.Name(),
        MAC:        n.HardwareAddr,
        IP:         n.IP,
        Confidence: 0.95, // High confidence for direct kernel observation
        Timestamp:  time.Now(),
    }

    if !online {
        obs.IP = nil // Clear IP on offline event, but keep MAC for identification
    }

    select {
    case p.events <- obs:
    default:
        slog.Warn("Netlink observation channel full, dropping event", "mac", n.HardwareAddr)
    }
}

// Stop terminates the netlink subscription and closes channels.
func (p *NetlinkProvider) Stop() error {
    if p.cancel != nil {
        p.cancel()
        <-p.done // Wait for goroutine to exit
    }
    return nil
}

// Events returns the read-only channel for observations.
func (p *NetlinkProvider) Events() <-chan Observation {
    return p.events
}
