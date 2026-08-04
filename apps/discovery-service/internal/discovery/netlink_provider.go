// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/netlink_provider.go
// Version: 2.5 (Fixed Goroutine Leak, Replaced Port 80, Dynamic Iface)
package discovery

import (
    "context"
    "fmt"
    "log/slog"
    "net"
    "os"
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
    probeSem  chan struct{}
}

func NewNetlinkProvider(iface string) *NetlinkProvider {
    return &NetlinkProvider{
        events:   make(chan Observation, 256),
        done:     make(chan struct{}),
        iface:    iface,
        probeSem: make(chan struct{}, 10),
    }
}

func (p *NetlinkProvider) Name() string { return "netlink" }

func (p *NetlinkProvider) Start(ctx context.Context) error {
    p.ctx, p.cancel = context.WithCancel(ctx)

    p.resolveInterface()
    p.checkGcStaleTime()

    go p.runSubscriptionLoop()
    go p.monitorStaleNeighbors()

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

func (p *NetlinkProvider) checkGcStaleTime() {
    if p.iface == "" {
        return
    }
    path := "/proc/sys/net/ipv4/neigh/" + p.iface + "/gc_stale_time"
    data, err := os.ReadFile(path)
    if err == nil {
        var val int
        _, err := fmt.Sscanf(string(data), "%d", &val)
        if err == nil && val < 180 {
            slog.Warn("Kernel neighbor gc_stale_time is lower than DIS staleThreshold (180s). Devices may flap between online/offline.",
                "iface", p.iface, "gc_stale_time", val, "path", path)
        }
    }
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

        ch := make(chan netlink.NeighUpdate)
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
            case update, ok := <-ch:
                if !ok {
                    // Critical 2 Fix: Close innerDone to stop the background goroutine before reconnecting
                    close(innerDone)
                    goto ReconnectLoop
                }
                p.handleNeighUpdate(update)
            }
        }

    ReconnectLoop:
        // Medium 5 Fix: Dynamically re-verify interface index on reconnect
        p.resolveInterface()
        select {
        case <-p.ctx.Done():
            return
        default:
        }
    }
}

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
    p.mu.RLock()
    idx := p.targetIdx
    p.mu.RUnlock()
    if idx == 0 {
        return
    }

    families := []int{netlink.FAMILY_V4, netlink.FAMILY_V6}

    for _, fam := range families {
        neighs, err := netlink.NeighList(idx, fam)
        if err != nil {
            continue
        }

        for _, n := range neighs {
            if n.HardwareAddr == nil || len(n.HardwareAddr) != 6 {
                continue
            }
            if IsMulticastOrBroadcast(n.HardwareAddr, n.IP) {
                continue
            }

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

            if (n.State & (unix.NUD_STALE | unix.NUD_DELAY)) != 0 && n.IP != nil {
                select {
                case p.probeSem <- struct{}{}:
                    go func(ip net.IP) {
                        defer func() { <-p.probeSem }()
                        p.probeNeighborIP(ip)
                    }(n.IP)
                default:
                }
            }
        }
    }
}

func (p *NetlinkProvider) probeNeighborIP(ip net.IP) {
    // High 1 Fix: Replace TCP port 80 probing with UDP port 9 (discard).
    // This triggers an ICMP Port Unreachable if the host is up, refreshing the neighbor cache.
    // It avoids sending TCP SYN to web servers and works for non-HTTP devices.
    var addr string
    if ip.To4() != nil {
        addr = net.JoinHostPort(ip.String(), "9")
    } else {
        // Medium 2 Fix: Append zone identifier for IPv6 link-local addresses
        if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
            addr = net.JoinHostPort(ip.String()+"%"+p.iface, "9")
        } else {
            addr = net.JoinHostPort(ip.String(), "9")
        }
    }

    conn, err := net.DialTimeout("udp", addr, 1*time.Second)
    if err == nil {
        _ = conn.Close()
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

    isFailed := (n.State & (unix.NUD_FAILED | unix.NUD_INCOMPLETE)) != 0
    isOnline := !isFailed && (n.State&(unix.NUD_REACHABLE|unix.NUD_PERMANENT|unix.NUD_STALE|unix.NUD_DELAY|unix.NUD_PROBE|unix.NUD_NOARP)) != 0

    if update.Type == unix.RTM_DELNEIGH {
        isOnline = false
    }

    vendor := oui.Lookup(n.HardwareAddr.String())

    obs := Observation{
        Source:     p.Name(),
        Group:      GroupA,
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
