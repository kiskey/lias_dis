// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/netlink_provider.go
// Version: 1.6
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

type NetlinkProvider struct {
	ctx       context.Context
	cancel    context.CancelFunc
	events    chan Observation
	done      chan struct{}
	iface     string
	targetIdx int
	mu        sync.RWMutex
}

func NewNetlinkProvider(iface string) *NetlinkProvider {
	return &NetlinkProvider{
		events: make(chan Observation, 256),
		done:   make(chan struct{}),
		iface:  iface,
	}
}

func (p *NetlinkProvider) Name() string { return "netlink" }

func (p *NetlinkProvider) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)

	if p.iface != "" {
		link, err := netlink.LinkByName(p.iface)
		if err != nil {
			slog.Warn("Target interface not found immediately", "iface", p.iface, "error", err)
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

func (p *NetlinkProvider) handleNeighUpdate(update netlink.NeighUpdate) {
	n := update.Neigh

	if p.targetIdx > 0 && n.LinkIndex != p.targetIdx {
		return
	}

	if n.HardwareAddr == nil || len(n.HardwareAddr) != 6 {
		return
	}

	// Filter out Broadcast and Multicast MAC/IP addresses
	if IsMulticastOrBroadcast(n.HardwareAddr, n.IP) {
		return
	}

	isFailed := (n.State & (unix.NUD_FAILED | unix.NUD_INCOMPLETE)) != 0
	isOnline := !isFailed && (n.State&(unix.NUD_REACHABLE|unix.NUD_PERMANENT|unix.NUD_STALE|unix.NUD_DELAY|unix.NUD_NOARP)) != 0

	if update.Type == unix.RTM_DELNEIGH {
		isOnline = false
	}

	vendor := oui.Lookup(n.HardwareAddr.String())

	obs := Observation{
		Source:     p.Name(),
		MAC:        n.HardwareAddr,
		IP:         n.IP,
		Vendor:     vendor,
		Online:     isOnline,
		Confidence: 0.95,
		Timestamp:  time.Now(),
	}

	select {
	case p.events <- obs:
	default:
		slog.Warn("Netlink observation channel full, dropping event", "mac", n.HardwareAddr.String())
	}
}

// IsMulticastOrBroadcast returns true if a MAC or IP address belongs to multicast/broadcast groups.
func IsMulticastOrBroadcast(mac net.HardwareAddr, ip net.IP) bool {
	if mac != nil && len(mac) == 6 {
		// IPv4 Multicast MAC prefix (01:00:5e)
		if mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5e {
			return true
		}
		// IPv6 Multicast MAC prefix (33:33)
		if mac[0] == 0x33 && mac[1] == 0x33 {
			return true
		}
		// Ethernet Broadcast MAC (ff:ff:ff:ff:ff:ff)
		if mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff {
			return true
		}
	}

	if ip != nil {
		// IPv4 Multicast (224.0.0.0/4) or Broadcast (255.255.255.255)
		if ip.IsMulticast() || ip.IsLoopback() || ip.IsUnspecified() || ip.Equal(net.IPv4bcast) {
			return true
		}
	}

	return false
}

func (p *NetlinkProvider) Stop() error {
	if p.cancel != nil {
		p.cancel()
		<-p.done
	}
	return nil
}

func (p *NetlinkProvider) Events() <-chan Observation {
	return p.events
}
