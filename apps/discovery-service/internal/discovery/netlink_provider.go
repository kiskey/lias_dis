// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/netlink_provider.go
// Version: 1.3
package discovery

import (
    "context"
    "fmt"
    "log/slog"
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
func NewNetlinkProvider(iface string) *NetlinkProvider {
    return &NetlinkProvider{
        events: make(chan Observation, 256),
        done:   make(chan struct{}),
        iface:  iface,
    }
}

// Name returns the provider's identifier.
func (p *NetlinkProvider) Name() string { return "netlink" }

// Start begins listening for neighbor updates. It uses NeighSubscribeWithOptions
// with ListExisting: true to atomically seed the cache.
func (p *NetlinkProvider) Start(ctx context.Context) error {
    p.ctx, p.cancel = context.WithCancel(ctx)

    ch := make(chan netlink.NeighUpdate)
    done := make(chan struct{})
    
    // FIX: NeighSubscribeWithOptions expects a struct, not a functional option
    opt := netlink.NeighSubscribeOptions{
        ListExisting: true,
    }
    
    if err := netlink.NeighSubscribeWithOptions(ch, done, opt); err != nil {
        return fmt.Errorf("failed to subscribe to netlink: %w", err)
    }

    go func() {
        defer close(p.done)
        
        for {
            select {
            case <-p.ctx.Done():
                close(done)
                return
            case update, ok := <-ch:
                if !ok {
                    return
                }
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
        return
    }

    obs := Observation{
        Source:     p.Name(),
        MAC:        n.HardwareAddr,
        IP:         n.IP,
        Online:     online,
        Confidence: 0.95,
        Timestamp:  time.Now(),
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
        <-p.done
    }
    return nil
}

// Events returns the read-only channel for observations.
func (p *NetlinkProvider) Events() <-chan Observation {
    return p.events
}
