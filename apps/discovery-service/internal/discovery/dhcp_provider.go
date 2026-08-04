// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/dhcp_provider.go
// Version: 1.4
package discovery

import (
    "bufio"
    "bytes"
    "context"
    "fmt"
    "io"
    "log/slog"
    "net"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/config"
)

// DHCPProvider reads DHCP lease files to map hostnames and MACs to IPs.
type DHCPProvider struct {
    cfg    config.DHCPConfig
    ctx    context.Context
    cancel context.CancelFunc
    events chan Observation
    done   chan struct{}
    client *http.Client
}

func NewDHCPProvider(cfg config.DHCPConfig) *DHCPProvider {
    return &DHCPProvider{
        cfg:    cfg,
        events: make(chan Observation, 128),
        done:   make(chan struct{}),
        client: &http.Client{Timeout: 10 * time.Second},
    }
}

func (p *DHCPProvider) Name() string { return "dhcp" }

func (p *DHCPProvider) Start(ctx context.Context) error {
    p.ctx, p.cancel = context.WithCancel(ctx)
    go p.run()
    return nil
}

func (p *DHCPProvider) Stop() error {
    if p.cancel != nil {
        p.cancel()
        <-p.done
    }
    return nil
}

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

    if p.cfg.SSHHost != "" {
        user := p.cfg.SSHUser
        if user == "" {
            user = "root"
        }
        
        target := fmt.Sprintf("%s@%s", user, p.cfg.SSHHost)
        cmd := exec.CommandContext(p.ctx, "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5", target, "cat /tmp/dhcp.leases")
        
        var stdout bytes.Buffer
        cmd.Stdout = &stdout
        err = cmd.Run()
        if err != nil {
            slog.Debug("Failed to fetch DHCP leases via SSH", "host", p.cfg.SSHHost, "error", err)
            return
        }
        reader = &stdout
        
    } else if p.cfg.LeaseURL != "" {
        req, reqErr := http.NewRequestWithContext(p.ctx, "GET", p.cfg.LeaseURL, nil)
        if reqErr != nil {
            return
        }
        
        resp, httpErr := p.client.Do(req)
        if httpErr != nil {
            return
        }
        defer resp.Body.Close()
        
        if resp.StatusCode != http.StatusOK {
            return
        }
        
        reader = resp.Body
        
    } else if p.cfg.LeaseFile != "" {
        file, fileErr := os.Open(p.cfg.LeaseFile)
        if fileErr != nil {
            return
        }
        defer file.Close()
        reader = file
    } else {
        return
    }

    scanner := bufio.NewScanner(reader)
    for scanner.Scan() {
        line := scanner.Text()
        // Format: <expiry> <mac> <ip> <hostname> <client_id> [<option_55_hex>]
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
            Group:      GroupB,
            MAC:        mac,
            IP:         ip,
            Hostname:   hostname,
            Online:     true,
            Confidence: 0.50,
            Timestamp:  time.Now(),
            Raw:        make(map[string]interface{}),
        }

        // DIS-PROV-11 Fix: DHCP Option 55 Fingerprinting
        if len(parts) > 5 {
            opt55 := parts[5]
            obs.Raw["dhcp_option_55"] = opt55
            osGuess := fingerprintOSFromDHCP(opt55)
            if osGuess != "" {
                obs.Model = osGuess
                obs.Confidence = 0.70
            }
        } else if len(parts) > 4 {
            // Some routers store client_id instead of option 55
            obs.Raw["client_id"] = parts[4]
        }
        
        select {
        case p.events <- obs:
        default:
            slog.Warn("DHCP observation channel full, dropping event")
        }
    }
}

// fingerprintOSFromDHCP provides passive OS identification based on DHCP Parameter Request List (Option 55).
// Reference: https://docs.microsoft.com/en-us/windows-server/troubleshoot/dynamic-host-configuration-protocol-basics
func fingerprintOSFromDHCP(opt55 string) string {
    opt55Lower := strings.ToLower(opt55)
    
    // Typical Windows request: 1,15,3,6,44,46,47,31,33,121,249
    if strings.Contains(opt55Lower, "1f") && strings.Contains(opt55Lower, "21") && strings.Contains(opt55Lower, "2c") {
        return "Windows"
    }
    // Typical macOS / iOS request: 1,121,3,6,15,119,252,95,44
    if strings.Contains(opt55Lower, "77") && strings.Contains(opt55Lower, "fc") && strings.Contains(opt55Lower, "5f") {
        return "Apple macOS/iOS"
    }
    // Typical Android request: 1,33,3,6,15,28,51,58,59
    if strings.Contains(opt55Lower, "21") && strings.Contains(opt55Lower, "1c") && !strings.Contains(opt55Lower, "2c") {
        return "Android"
    }
    // Typical Linux (dhclient): 1,28,2,5,3,6,12,15,119
    if strings.Contains(opt55Lower, "01") && strings.Contains(opt55Lower, "1c") && strings.Contains(opt55Lower, "06") && !strings.Contains(opt55Lower, "77") {
        return "Linux"
    }

    return ""
}
