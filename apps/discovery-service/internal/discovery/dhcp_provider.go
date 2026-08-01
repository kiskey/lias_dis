// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/dhcp_provider.go
// Version: 1.0
package discovery

import (
    "bufio"
    "context"
    "log/slog"
    "net"
    "os"
    "strings"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/config"
)

// DHCPProvider reads DHCP lease files to map hostnames and MACs to IPs.
// It provides medium-confidence hostname/MAC bindings.
type DHCPProvider struct {
    cfg    config.DHCPConfig
    ctx    context.Context
    cancel context.CancelFunc
    events chan Observation
    done   chan struct{}
}

// NewDHCPProvider initializes the DHCP lease file parser.
func NewDHCPProvider(cfg config.DHCPConfig) *DHCPProvider {
    return &DHCPProvider{
        cfg:    cfg,
        events: make(chan Observation, 128),
        done:   make(chan struct{}),
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
    file, err := os.Open(p.cfg.LeaseFile)
    if err != nil {
        // Don't log as error every 60s if file just doesn't exist
        slog.Debug("Failed to open DHCP lease file", "file", p.cfg.LeaseFile, "error", err)
        return
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        // Standard dnsmasq/OpenWrt format: <mac> <ip> <hostname> <client_id>
        parts := strings.Fields(line)
        if len(parts) < 3 {
            continue
        }
        
        mac, err := net.ParseMAC(parts[0])
        if err != nil {
            continue
        }
        
        ip := net.ParseIP(parts[1])
        if ip == nil {
            continue
        }
        
        hostname := parts[2]
        if hostname == "*" {
            hostname = ""
        }
        
        obs := Observation{
            Source:     p.Name(),
            MAC:        mac,
            IP:         ip,
            Hostname:   hostname,
            Confidence: 0.5, // MEDIUM confidence per §3.2
            Timestamp:  time.Now(),
        }
        
        select {
        case p.events <- obs:
        default:
            slog.Warn("DHCP observation channel full, dropping event")
        }
    }
    
    if err := scanner.Err(); err != nil {
        slog.Error("Error reading DHCP lease file", "error", err)
    }
}
