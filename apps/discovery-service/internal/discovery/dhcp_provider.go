// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/dhcp_provider.go
// Version: 1.6 (Hardened Option 55 Parsing)
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
    "strconv"
    "strings"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/config"
)

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
        cmd := exec.CommandContext(p.ctx, "ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=5", target, "cat /tmp/dhcp.leases")
        
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

        if len(parts) > 5 {
            opt55 := parts[5]
            obs.Raw["dhcp_option_55"] = opt55
            osGuess := fingerprintOSFromDHCP(opt55)
            if osGuess != "" {
                obs.Model = osGuess
                obs.Confidence = 0.70
            }
        } else if len(parts) > 4 {
            obs.Raw["client_id"] = parts[4]
        }
        
        select {
        case p.events <- obs:
        default:
            slog.Warn("DHCP observation channel full, dropping event")
        }
    }
}

// ENR-07 Fix: Parse DHCP Option 55 robustly (handles both comma-separated decimal and raw hex)
func fingerprintOSFromDHCP(opt55 string) string {
    set := make(map[byte]bool)
    
    if strings.Contains(opt55, ",") {
        // Comma-separated decimal (e.g., "1,15,3,6,44,46,47,31,33,121,249")
        bytesStr := strings.Split(opt55, ",")
        for _, b := range bytesStr {
            n, err := strconv.Atoi(strings.TrimSpace(b))
            if err == nil {
                set[byte(n)] = true
            }
        }
    } else {
        // Raw hex string (e.g., "0103060f1f21" or "01:03:06:0f:1f:21")
        cleanHex := strings.ReplaceAll(opt55, ":", "")
        cleanHex = strings.ReplaceAll(cleanHex, " ", "")
        if len(cleanHex)%2 == 0 {
            for i := 0; i < len(cleanHex); i += 2 {
                n, err := strconv.ParseUint(cleanHex[i:i+2], 16, 8)
                if err == nil {
                    set[byte(n)] = true
                }
            }
        }
    }

    // Typical Windows request: 1,15,3,6,44,46,47,31,33,121,249
    if set[31] && set[33] && set[44] {
        return "Windows"
    }
    // Typical macOS / iOS request: 1,121,3,6,15,119,252,95,44
    if set[119] && set[252] && set[95] {
        return "Apple macOS/iOS"
    }
    // Typical Android request: 1,33,3,6,15,28,51,58,59
    if set[28] && set[51] && !set[44] {
        return "Android"
    }
    // Typical Linux (dhclient): 1,28,2,5,3,6,12,15,119
    if set[1] && set[28] && set[2] && set[5] && !set[119] {
        return "Linux"
    }

    return ""
}
