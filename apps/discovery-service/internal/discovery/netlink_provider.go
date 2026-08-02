// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/netlink_provider.go
// Version: 2.0
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

	// Start Active L2 Neighbor Reachability Monitor
	go p.monitorStaleNeighbors()

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

// monitorStaleNeighbors periodically audits kernel neighbor states and triggers active probes for STALE entries.
func (p *NetlinkProvider) monitorStaleNeighbors() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.auditKernelNeighbors()
		}
	}
}

func (p *NetlinkProvider) auditKernelNeighbors() {
	neighs, err := netlink.NeighList(p.targetIdx, netlink.FAMILY_V4)
	if err != nil {
		return
	}

	for _, n := range neighs {
		if n.HardwareAddr == nil || len(n.HardwareAddr) != 6 {
			continue
		}
		if IsMulticastOrBroadcast(n.HardwareAddr, n.IP) {
			continue
		}

		// If neighbor is in NUD_FAILED or NUD_INCOMPLETE, emit explicit offline observation with confidence 0.95
		if (n.State & (unix.NUD_FAILED | unix.NUD_INCOMPLETE)) != 0 {
			obs := Observation{
				Source:     p.Name(),
				MAC:        n.HardwareAddr,
				IP:         n.IP,
				Vendor:     oui.Lookup(n.HardwareAddr.String()),
				Online:     false,
				Confidence: 0.95,
				Timestamp:  time.Now(),
			}
			select {
			case p.events <- obs:
			default:
			}
			continue
		}

		// If neighbor is NUD_STALE or NUD_DELAY, transmit an active L2 probe to force kernel transition to REACHABLE or FAILED
		if (n.State & (unix.NUD_STALE | unix.NUD_DELAY)) != 0 && n.IP != nil {
			go p.probeNeighborIP(n.IP)
		}
	}
}

// probeNeighborIP transmits an active L2 probe packet to force kernel ARP state resolution.
func (p *NetlinkProvider) probeNeighborIP(ip net.IP) {
	addr := net.JoinHostPort(ip.String(), "64111")
	conn, err := net.DialTimeout("udp4", addr, 1*time.Second)
	if err == nil {
		_, _ = conn.Write([]byte{0x00})
		_ = conn.Close()
	}
}

func (p *NetlinkProvider) handleNeighUpdate(update netlink.NeighUpdate) {
	n := update.Neigh

	if p.targetIdx > 0 && n.LinkIndex != p.targetIdx {
		return
	}

	if n.HardwareAddr == nil || len(n.HardwareAddr) != 6 {
		return
	}

	if IsMulticastOrBroadcast(n.HardwareAddr, n.IP) {
		return
	}

	isFailed := (n.State & (unix.NUD_FAILED | unix.NUD_INCOMPLETE)) != 0
	isOnline := !isFailed && (n.State&(unix.NUD_REACHABLE|unix.NUD_PERMANENT|unix.NUD_STALE|unix.NUD_DELAY|unix.NUD_PROBE|unix.NUD_NOARP)) != 0

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

func IsMulticastOrBroadcast(mac net.HardwareAddr, ip net.IP) bool {
	if mac != nil && len(mac) == 6 {
		if mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5e {
			return true
		}
		if mac[0] == 0x33 && mac[1] == 0x33 {
			return true
		}
		if mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff {
			return true
		}
	}

	if ip != nil {
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
