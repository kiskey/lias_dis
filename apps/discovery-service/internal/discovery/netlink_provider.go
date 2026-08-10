// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/netlink_provider.go
// Version: 2.6 (Enhanced UDP Probe to Force L2 Resolution)
package discovery

import (
    "context"
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
        events:   make(chan Observation, 256),
        done:     make(chan struct{}),
        iface:    iface,
    }
}

func (p *NetlinkProvider) Name() string { return "netlink" }

func (p *NetlinkProvider) Start(ctx context.Context) error {
    p.ctx, p.cancel = context.WithCancel(ctx)

    p.resolveInterface()
    go p.runSubscriptionLoop()

    return nil
}

func (p *NetlinkProvider) resolveInterface() {
    if p.iface == "" {
        return
    }
    link, err := netlink.LinkByName(p.iface)
    if err != nil {
        slog.Warn("Target interface not found, will retry", "iface", p.iface, "error", err)
        p.mu.Lock()
        p.targetIdx = 0
        p.mu.Unlock()
        return
    }
    p.mu.Lock()
    p.targetIdx = link.Attrs().Index
    p.mu.Unlock()
    slog.Info("Netlink provider bound to interface", "iface", p.iface, "index", link.Attrs().Index)
}

func (p *NetlinkProvider) runSubscriptionLoop() {
    defer close(p.done)

    ifaceRetry := time.NewTicker(30 * time.Second)
    defer ifaceRetry.Stop()

    for {
        select {
        case <-p.ctx.Done():
            return
        case <-ifaceRetry.C:
            p.mu.RLock()
            idx := p.targetIdx
            p.mu.RUnlock()
            if idx == 0 {
                p.resolveInterface()
            }
        default:
        }

        p.mu.RLock()
        idx := p.targetIdx
        p.mu.RUnlock()
        if idx == 0 {
            select {
            case <-p.ctx.Done():
                return
            case <-time.After(5 * time.Second):
                continue
            }
        }

		ch := make(chan netlink.NeighUpdate, 256)
        innerDone := make(chan struct{})

        opt := netlink.NeighSubscribeOptions{
            ListExisting: true,
        }

        if err := netlink.NeighSubscribeWithOptions(ch, innerDone, opt); err != nil {
            slog.Error("Failed to subscribe to netlink neighbor updates, retrying in 5s", "error", err)
            select {
            case <-p.ctx.Done():
                return
            case <-time.After(5 * time.Second):
            }
            continue
        }

        for {
            select {
            case <-p.ctx.Done():
                close(innerDone)
                return
            case <-innerDone:
                slog.Warn("Netlink subscription closed by kernel, attempting reconnect...")
                select {
                case <-p.ctx.Done():
                    return
                case <-time.After(2 * time.Second):
                }
				goto ReconnectLoop
            case update, ok := <-ch:
                if !ok {
                    close(innerDone)
                    goto ReconnectLoop
                }
                p.handleNeighUpdate(update)
            }
        }

    ReconnectLoop:
        p.resolveInterface()
        select {
        case <-p.ctx.Done():
            return
        default:
        }
    }
}

func (p *NetlinkProvider) handleNeighUpdate(update netlink.NeighUpdate) {
    n := update.Neigh

    p.mu.RLock()
    idx := p.targetIdx
    p.mu.RUnlock()

    if idx > 0 && n.LinkIndex != idx {
        return
    }

    if n.HardwareAddr == nil || len(n.HardwareAddr) != 6 {
        return
    }

    if IsMulticastOrBroadcast(n.HardwareAddr, n.IP) {
        return
    }

	// A neighbour-cache mapping is not the same as current device presence.
	// STALE is explicitly "valid but suspicious"; PERMANENT and NOARP are
	// configuration states. Only a positive NUD_REACHABLE transition is used
	// as presence evidence. Deletion/failure is left to the correlation
	// staleness horizon and never treated as an immediate offline verdict.
	if update.Type == unix.RTM_DELNEIGH || n.State != unix.NUD_REACHABLE {
		return
    }

	vendor := ""
	if isGloballyAdministeredUnicast(n.HardwareAddr) {
		vendor = oui.Lookup(n.HardwareAddr.String())
	}

    obs := Observation{
        Source:     p.Name(),
        Group:      GroupA,
        MAC:        n.HardwareAddr,
        IP:         n.IP,
        Vendor:     vendor,
		Online:     true,
        Confidence: 0.95,
        Timestamp:  time.Now(),
		Raw: map[string]interface{}{
			"nud_state": "reachable",
		},
    }

    select {
    case p.events <- obs:
    default:
        slog.Warn("Netlink observation channel full, dropping event", "mac", n.HardwareAddr.String())
    }
}

func isGloballyAdministeredUnicast(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&0x01 == 0 && mac[0]&0x02 == 0
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
