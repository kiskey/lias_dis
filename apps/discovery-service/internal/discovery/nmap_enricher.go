// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/nmap_enricher.go
// Version: 1.0
package discovery

import (
    "context"
    "encoding/xml"
    "fmt"
    "log/slog"
    "os/exec"
    "strings"
    "time"

    "github.com/user/lias-dis/shared/models"
)

// NmapEnricher uses the system `nmap` binary to perform on-demand
// OS and service detection. It executes a fast basic scan first, and falls
// back to a more intense scan if the device remains unidentified.
// See §3.5 for details.
type NmapEnricher struct {
    ctx    context.Context
    cancel context.CancelFunc
}

// NewNmapEnricher initializes the enricher.
func NewNmapEnricher() *NmapEnricher {
    return &NmapEnricher{}
}

// Name returns the provider's identifier.
func (e *NmapEnricher) Name() string { return "nmap" }

// Start satisfies the Provider interface (no-op for enrichers).
func (e *NmapEnricher) Start(ctx context.Context) error {
    e.ctx, e.cancel = context.WithCancel(ctx)
    return nil
}

// Stop satisfies the Provider interface.
func (e *NmapEnricher) Stop() error {
    if e.cancel != nil {
        e.cancel()
    }
    return nil
}

// Enrich executes nmap against the device's current IP and parses the XML output.
func (e *NmapEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    if d == nil || d.CurrentIP == "" {
        return nil, fmt.Errorf("cannot enrich without IP")
    }

    // 1. Basic scan first (-sn -PR -PE)
    enr := e.runNmap(ctx, d.CurrentIP, false)
    if enr != nil && (enr.Vendor != "" || enr.DeviceType != "") {
        return enr, nil
    }

    // 2. If basic scan didn't yield vendor/OS, try intense scan (-O -sV)
    // Note: Intense scan requires root/cap_net_raw. We ignore errors gracefully.
    return e.runNmap(ctx, d.CurrentIP, true), nil
}

// runNmap executes the nmap command and parses the XML output.
func (e *NmapEnricher) runNmap(ctx context.Context, ip string, intense bool) *models.Enrichment {
    timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
    defer cancel()

    args := []string{"-sn", "-PR", "-PE", "-oX", "-", ip}
    if intense {
        args = []string{"-O", "-sV", "--version-light", "-oX", "-", ip}
    }

    cmd := exec.CommandContext(timeoutCtx, "nmap", args...)
    output, err := cmd.Output()
    if err != nil {
        if ctx.Err() == context.DeadlineExceeded {
            slog.Debug("Nmap scan timed out", "ip", ip)
        } else {
            slog.Debug("Nmap execution failed (is nmap installed and privileged?)", "ip", ip, "error", err)
        }
        return nil
    }

    return parseNmapXML(output)
}

// nmapRun represents the relevant parts of the nmap XML output.
type nmapRun struct {
    Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
    Status    nmapStatus    `xml:"status"`
    Addresses []nmapAddress `xml:"address"`
    Hostnames []nmapHostname `xml:"hostnames>hostname"`
    OS        nmapOS        `xml:"os"`
    Ports     []nmapPort    `xml:"ports>port"`
}

type nmapStatus struct {
    State string `xml:"state,attr"`
}

type nmapAddress struct {
    Addr     string `xml:"addr,attr"`
    AddrType string `xml:"addrtype,attr"`
    Vendor   string `xml:"vendor,attr"`
}

type nmapHostname struct {
    Name string `xml:"name,attr"`
    Type string `xml:"type,attr"`
}

type nmapOS struct {
    OSMatches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
    Name     string `xml:"name,attr"`
    Accuracy string `xml:"accuracy,attr"`
}

type nmapPort struct {
    PortID  string      `xml:"portid,attr"`
    Service nmapService `xml:"service"`
}

type nmapService struct {
    Name    string `xml:"name,attr"`
    Product string `xml:"product,attr"`
    Version string `xml:"version,attr"`
}

// parseNmapXML unmarshals nmap XML output into an Enrichment struct.
func parseNmapXML(data []byte) *models.Enrichment {
    var run nmapRun
    if err := xml.Unmarshal(data, &run); err != nil {
        return nil
    }
    if len(run.Hosts) == 0 || run.Hosts[0].Status.State != "up" {
        return nil
    }

    host := run.Hosts[0]
    enr := &models.Enrichment{
        Source:     "nmap",
        Confidence: 0.8, // High confidence for Nmap enrichment
        Raw:        make(map[string]interface{}),
    }

    for _, addr := range host.Addresses {
        if addr.AddrType == "mac" && addr.Vendor != "" {
            enr.Vendor = addr.Vendor
        }
    }

    if len(host.Hostnames) > 0 {
        enr.Hostname = host.Hostnames[0].Name
    }

    if len(host.OS.OSMatches) > 0 {
        osName := host.OS.OSMatches[0].Name
        enr.DeviceType = guessDeviceTypeFromOS(osName)
        enr.Model = osName // Use OS as model fallback
    }

    var services []string
    for _, p := range host.Ports {
        services = append(services, p.Service.Name)
    }
    if len(services) > 0 {
        enr.Services = services
    }

    return enr
}

// guessDeviceTypeFromOS infers a generic device type from an Nmap OS string.
func guessDeviceTypeFromOS(os string) string {
    osLower := strings.ToLower(os)
    if strings.Contains(osLower, "ios") || strings.Contains(osLower, "android") {
        return "phone"
    }
    if strings.Contains(osLower, "windows") {
        return "pc"
    }
    if strings.Contains(osLower, "mac os") {
        return "mac"
    }
    if strings.Contains(osLower, "linux") {
        return "server" // Could be server, iot, or router
    }
    return ""
}
