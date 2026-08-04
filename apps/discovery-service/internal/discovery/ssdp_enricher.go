// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/ssdp_enricher.go
// Version: 1.5 (Fixed Build Error and SO_REUSEPORT Multicast)
package discovery

import (
    "context"
    "encoding/xml"
    "fmt"
    "log/slog"
    "net"
    "net/http"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/models"
    "golang.org/x/sys/unix"
)

type EnrichmentTriggerer interface {
    TriggerEnrichment(pdid string, force bool)
}

type SSDPEnricher struct {
    ctx       context.Context
    cancel    context.CancelFunc
    ifaceName string // NET-05 Fix: Store interface name
    cache     *inventory.Cache
    trigger   EnrichmentTriggerer
    bgQueue   chan string
    wg        sync.WaitGroup
}

func NewSSDPEnricher(ifaceName string) *SSDPEnricher {
    return &SSDPEnricher{
        ifaceName: ifaceName,
        bgQueue:   make(chan string, 64),
    }
}

func (e *SSDPEnricher) Name() string { return "ssdp" }

func (e *SSDPEnricher) Start(ctx context.Context) error {
    e.ctx, e.cancel = context.WithCancel(ctx)
    go e.runPassiveListener()
    go e.runBackgroundFetcher()
    return nil
}

func (e *SSDPEnricher) Stop() error {
    if e.cancel != nil {
        e.cancel()
    }
    close(e.bgQueue)
    e.wg.Wait()
    return nil
}

func (e *SSDPEnricher) SetCache(cache *inventory.Cache) {
    e.cache = cache
}

func (e *SSDPEnricher) SetEnrichmentTriggerer(t EnrichmentTriggerer) {
    e.trigger = t
}

func (e *SSDPEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    if d == nil || d.CurrentIP == "" {
        return nil, fmt.Errorf("cannot enrich without IP")
    }

    location, err := e.searchSSDP(ctx, d.CurrentIP)
    if err != nil || location == "" {
        return nil, nil
    }

    enr, err := e.fetchDescriptor(ctx, location)
    if err != nil {
        return nil, err
    }
    return enr, nil
}

func (e *SSDPEnricher) searchSSDP(ctx context.Context, targetIP string) (string, error) {
    searchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
    if err != nil {
        return "", err
    }

    conn, err := net.ListenPacket("udp4", ":0")
    if err != nil {
        return "", err
    }
    defer conn.Close()

    deadline, _ := searchCtx.Deadline()
    _ = conn.SetReadDeadline(deadline)

    msg := []byte("M-SEARCH * HTTP/1.1\r\n" +
        "HOST: 239.255.255.250:1900\r\n" +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 2\r\n" +
        "ST: ssdp:all\r\n\r\n")

    if _, err = conn.WriteTo(msg, addr); err != nil {
        return "", err
    }

    buf := make([]byte, 4096)
    for {
        n, src, err := conn.ReadFrom(buf)
        if err != nil {
            if searchCtx.Err() != nil {
                return "", nil
            }
            return "", err
        }

        if srcIP, ok := src.(*net.UDPAddr); ok && srcIP.IP.String() == targetIP {
            headers := string(buf[:n])
            return parseLocation(headers), nil
        }
    }
}

func (e *SSDPEnricher) runPassiveListener() {
    addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
    if err != nil {
        slog.Error("Failed to resolve SSDP multicast addr", "error", err)
        return
    }

    var iface *net.Interface
    if e.ifaceName != "" {
        iface, err = net.InterfaceByName(e.ifaceName)
        if err != nil {
            slog.Warn("Failed to find interface for SSDP multicast, binding to all", "iface", e.ifaceName, "error", err)
        }
    }

    // LNX-01 Fix: Use ListenConfig with SO_REUSEPORT
    lc := net.ListenConfig{
        Control: func(network, address string, c syscall.RawConn) error {
            var opErr error
            err := c.Control(func(fd uintptr) {
                opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
            })
            if err != nil {
                return err
            }
            return opErr
        },
    }

    pc, err := lc.ListenPacket(e.ctx, "udp4", "0.0.0.0:1900")
    if err != nil {
        slog.Error("Failed to listen on SSDP port 1900", "error", err)
        return
    }
    defer pc.Close()

    conn := pc.(*net.UDPConn)

    // NET-05 Fix: Join multicast group on specific interface
    if iface != nil {
        if err := conn.JoinGroup(iface, addr); err != nil {
            slog.Warn("Failed to join SSDP multicast group on specific interface", "iface", e.ifaceName, "error", err)
        }
    } else {
        if err := conn.JoinGroup(nil, addr); err != nil {
            slog.Warn("Failed to join SSDP multicast group", "error", err)
        }
    }

    buf := make([]byte, 4096)
    for {
        select {
        case <-e.ctx.Done():
            return
        default:
        }

        _ = conn.SetReadDeadline(time.Now().Add(1 * time.Minute))
        n, src, err := conn.ReadFromUDP(buf)
        if err != nil {
            if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                continue
            }
            if e.ctx.Err() != nil {
                return
            }
            slog.Debug("SSDP passive read error", "error", err)
            time.Sleep(1 * time.Second)
            continue
        }

        headers := string(buf[:n])
        if strings.HasPrefix(headers, "NOTIFY") {
            loc := parseLocation(headers)
            if loc != "" {
                select {
                case e.bgQueue <- loc:
                default:
                    slog.Debug("SSDP background queue full, dropping NOTIFY location", "src", src.IP)
                }
            }
        }
    }
}

func (e *SSDPEnricher) runBackgroundFetcher() {
    e.wg.Add(1)
    defer e.wg.Done()

    for loc := range e.bgQueue {
        if e.cache == nil || e.trigger == nil {
            continue
        }

        ip := extractIPFromURL(loc)
        if ip == "" {
            continue
        }

        dev := e.cache.GetByIP(ip)
        if dev == nil {
            slog.Debug("Passive SSDP: Device not in cache, skipping trigger", "ip", ip)
            continue
        }

        slog.Debug("Passive SSDP: Triggering enrichment for device", "ip", ip, "pdid", dev.PDID)
        e.trigger.TriggerEnrichment(dev.PDID, false)
    }
}

func extractIPFromURL(rawURL string) string {
    u := strings.TrimPrefix(rawURL, "http://")
    u = strings.TrimPrefix(u, "https://")
    parts := strings.Split(u, ":")
    if len(parts) > 0 {
        return parts[0]
    }
    return ""
}

func parseLocation(headers string) string {
    lines := strings.Split(headers, "\r\n")
    for _, line := range lines {
        if strings.HasPrefix(strings.ToLower(line), "location:") {
            return strings.TrimSpace(line[len("location:"):])
        }
    }
    return ""
}

func (e *SSDPEnricher) fetchDescriptor(ctx context.Context, url string) (*models.Enrichment, error) {
    client := &http.Client{Timeout: 5 * time.Second}
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, err
    }

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("ssdp descriptor returned non-200: %d", resp.StatusCode)
    }

    var dev struct {
        XMLName xml.Name `xml:"root"`
        Device  struct {
            FriendlyName string `xml:"friendlyName"`
            Manufacturer string `xml:"manufacturer"`
            ModelName    string `xml:"modelName"`
            ModelNumber  string `xml:"modelNumber"`
            DeviceType   string `xml:"deviceType"`
        } `xml:"device"`
    }

    if err := xml.NewDecoder(resp.Body).Decode(&dev); err != nil {
        slog.Debug("Failed to parse SSDP XML", "url", url, "error", err)
        return nil, nil
    }

    enr := &models.Enrichment{
        Source:       e.Name(),
        Confidence:   0.85,
        FriendlyName: dev.Device.FriendlyName,
        Manufacturer: dev.Device.Manufacturer,
        Model:        dev.Device.ModelName,
        Raw: map[string]interface{}{
            "device_type":  dev.Device.DeviceType,
            "model_number": dev.Device.ModelNumber,
        },
    }
    
    if strings.Contains(dev.Device.DeviceType, "MediaRenderer") {
        enr.DeviceType = "tv"
    } else if strings.Contains(dev.Device.DeviceType, "MediaServer") {
        enr.DeviceType = "server"
    }

    return enr, nil
}
