// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/netlink_provider.go
// Version: 1.4
package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/user/lias-dis/pkg/oui"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// NetlinkProvider subscribes to the Linux kernel neighbor table (ARP/NDP)
// to provide real-time, authoritative device presence data with minimal CPU impact.
type NetlinkProvider struct {
	ctx       context.Context
	cancel    context.CancelFunc
	events    chan Observation
	done      chan struct{}
	iface     string
	targetIdx int // Cached interface index to avoid per-event syscall churn
	mu        sync.RWMutex
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

// Start begins listening for neighbor updates. It resolves the interface index
// once at startup and uses ListExisting: true to seed the device inventory atomically.
func (p *NetlinkProvider) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)

	// Resolve and cache target interface index
	if p.iface != "" {
		link, err := netlink.LinkByName(p.iface)
		if err != nil {
			slog.Warn("Target interface not found immediately, will process all netlink events", "iface", p.iface, "error", err)
			p.targetIdx = 0
		} else {
			p.targetIdx = link.Attrs().Index
			slog.Info("Netlink provider bound to interface", "iface", p.iface, "index", p.targetIdx)
		}
	}

	ch := make(chan netlink.NeighUpdate)
	done := make(chan struct{})

	opt := netlink.NeighSubscribeOptions{
		ListExisting: true,
	}

	if err := netlink.NeighSubscribeWithOptions(ch, done, opt); err != nil {
		return fmt.Errorf("failed to subscribe to netlink neighbor updates: %w", err)
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
				p.handleNeighUpdate(update)
			}
		}
	}()

	return nil
}

// handleNeighUpdate inspects kernel neighbor states and dispatches observations.
func (p *NetlinkProvider) handleNeighUpdate(update netlink.NeighUpdate) {
	n := update.Neigh

	// 1. Interface index filtering using cached index (Zero syscall overhead)
	if p.targetIdx > 0 && n.LinkIndex != p.targetIdx {
		return
	}

	// 2. Hardware address sanity check
	if n.HardwareAddr == nil || len(n.HardwareAddr) != 6 {
		return
	}

	// 3. Filter by Netlink state and type
	// RTM_NEWNEIGH = 0x10 (28 in unix/netlink package) or update.Type check
	// Explicitly evaluate kernel NUD (Neighbor Unreachability Detection) flags
	isFailed := (n.State & (unix.NUD_FAILED | unix.NUD_INCOMPLETE)) != 0
	isOnline := !isFailed && (n.State&(unix.NUD_REACHABLE|unix.NUD_PERMANENT|unix.NUD_STALE|unix.NUD_DELAY|unix.NUD_NOARP)) != 0

	// Handle explicit deletion events (RTM_DELNEIGH = 29)
	if update.Type == unix.RTM_DELNEIGH {
		isOnline = false
	}

	// Perform fast OUI vendor lookup
	vendor := oui.Lookup(n.HardwareAddr.String())

	obs := Observation{
		Source:     p.Name(),
		MAC:        n.HardwareAddr,
		IP:         n.IP,
		Vendor:     vendor,
		Online:     isOnline,
		Confidence: 0.95, // High confidence for Netlink
		Timestamp:  time.Now(),
	}

	select {
	case p.events <- obs:
	default:
		slog.Warn("Netlink observation channel full, dropping event", "mac", n.HardwareAddr.String())
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
