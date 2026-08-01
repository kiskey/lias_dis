// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/dhcp_provider.go
// Version: 1.2
package discovery

import (
    "bufio"
    "context"
    "fmt"
    "io"
    "log/slog"
    "net"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/config"
)

// DHCPProvider reads DHCP lease files to map hostnames and MACs to IPs.
// It supports reading from a local file or fetching from a remote HTTP URL.
type DHCPProvider struct {
    cfg    config.DHCPConfig
    ctx    context.Context
    cancel context.CancelFunc
    events chan Observation
    done   chan struct{}
    client *http.Client
}

// NewDHCPProvider initializes the DHCP lease file parser.
func NewDHCPProvider(cfg config.DHCPConfig) *DHCPProvider {
    return &DHCPProvider{
        cfg:    cfg,
        events: make(chan Observation, 128),
        done:   make(chan struct{}),
        client: &http.Client{Timeout: 10 * time.Second},
    }
}

// Name returns the provider's identifier.
func (p *DHCPProvider) Name() string { return "dhcp" }

// Start begins the polling loop.
func (p *DHCPProvider) Start(ctx context.Context) error {
    p.ctx, p.cancel = context.WithCancel(ctx)
    go p.run()
    return nil
}

// Stop terminates the polling loop.
func (p *DHCPProvider) Stop() error {
    if p.cancel != nil {
        p.cancel()
        <-p.done
    }
    return nil
}

// Events returns the read-only channel for observations.
func (p *DHCPProvider) Events() <-chan Observation {
    return p.events
}

func (p *DHCPProvider) run() {
    defer close(p.done)
    
    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()
    
    p.poll()
    
    for {
        select {
        case <-p.ctx.Done():
            return
        case <-ticker.C:
            p.poll()
        }
    }
}

func (p *DHCPProvider) poll() {
    var reader io.Reader
    var err error

    // Determine if we are fetching remotely or reading locally
    if p.cfg.LeaseURL != "" {
        req, reqErr := http.NewRequestWithContext(p.ctx, "GET", p.cfg.LeaseURL, nil)
        if reqErr != nil {
            slog.Debug("Failed to create DHCP lease request", "url", p.cfg.LeaseURL, "error", reqErr)
            return
        }
        
        resp, httpErr := p.client.Do(req)
        if httpErr != nil {
            slog.Debug("Failed to fetch DHCP leases via HTTP", "url", p.cfg.LeaseURL, "error", httpErr)
            return
        }
        defer resp.Body.Close()
        
        if resp.StatusCode != http.StatusOK {
            slog.Debug("DHCP lease URL returned non-200", "url", p.cfg.LeaseURL, "status", resp.StatusCode)
            return
        }
        
        reader = resp.Body
    } else if p.cfg.LeaseFile != "" {
        file, fileErr := os.Open(p.cfg.LeaseFile)
        if fileErr != nil {
            slog.Debug("Failed to open local DHCP lease file", "file", p.cfg.LeaseFile, "error", fileErr)
            return
        }
        defer file.Close()
        reader = file
    } else {
        return // No source configured
    }

    scanner := bufio.NewScanner(reader)
    for scanner.Scan() {
        line := scanner.Text()
        // Standard dnsmasq/OpenWrt format: <expiry_timestamp> <mac> <ip> <hostname> <client_id>
        parts := strings.Fields(line)
        if len(parts) < 4 {
            continue
        }
        
        mac, err := net.ParseMAC(parts[1])
        if err != nil {
            continue
        }
        
        ip := net.ParseIP(parts[2])
        if ip == nil {
            continue
        }
        
        hostname := parts[3]
        if hostname == "*" {
            hostname = ""
        }
        
        obs := Observation{
            Source:     p.Name(),
            MAC:        mac,
            IP:         ip,
            Hostname:   hostname,
            Online:     true, // Explicitly mark as online
            Confidence: 0.5,  // MEDIUM confidence per §3.2
            Timestamp:  time.Now(),
        }
        
        select {
        case p.events <- obs:
        default:
            slog.Warn("DHCP observation channel full, dropping event")
        }
    }
    
    if err := scanner.Err(); err != nil {
        slog.Error("Error reading DHCP leases", "error", err)
    }
}

// Unused but required to satisfy fmt import in some lint environments
var _ = fmt.Sprintf
