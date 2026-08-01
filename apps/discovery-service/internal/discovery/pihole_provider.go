// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/pihole_provider.go
// Version: 1.0
package discovery

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "net"
    "net/http"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/config"
)

// PiholeProvider polls the Pi-hole v6 API for active client activity.
// It provides low-confidence presence data.
type PiholeProvider struct {
    cfg      config.PiholeConfig
    ctx      context.Context
    cancel   context.CancelFunc
    events   chan Observation
    done     chan struct{}
    client   *http.Client
    sid      string
    sidValid bool
}

// NewPiholeProvider initializes the Pi-hole polling provider.
func NewPiholeProvider(cfg config.PiholeConfig) *PiholeProvider {
    return &PiholeProvider{
        cfg:    cfg,
        events: make(chan Observation, 128),
        done:   make(chan struct{}),
        client: &http.Client{Timeout: 10 * time.Second},
    }
}

// Name returns the provider's identifier.
func (p *PiholeProvider) Name() string { return "pihole" }

// Start begins the polling loop.
func (p *PiholeProvider) Start(ctx context.Context) error {
    p.ctx, p.cancel = context.WithCancel(ctx)
    go p.run()
    return nil
}

// Stop terminates the polling loop.
func (p *PiholeProvider) Stop() error {
    if p.cancel != nil {
        p.cancel()
        <-p.done
    }
    return nil
}

// Events returns the read-only channel for observations.
func (p *PiholeProvider) Events() <-chan Observation {
    return p.events
}

func (p *PiholeProvider) run() {
    defer close(p.done)
    
    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()
    
    // Initial run immediately
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

func (p *PiholeProvider) poll() {
    if !p.sidValid {
        if err := p.authenticate(); err != nil {
            slog.Error("Pi-hole authentication failed", "error", err)
            return
        }
    }
    
    req, err := http.NewRequestWithContext(p.ctx, "GET", p.cfg.URL+"/api/stats/clients", nil)
    if err != nil {
        return
    }
    req.Header.Set("X-FTL-SID", p.sid)
    
    resp, err := p.client.Do(req)
    if err != nil {
        slog.Error("Failed to fetch Pi-hole clients", "error", err)
        return
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == http.StatusUnauthorized {
        p.sidValid = false
        slog.Warn("Pi-hole SID expired, will re-authenticate")
        return
    }
    if resp.StatusCode != http.StatusOK {
        slog.Error("Pi-hole API returned non-200", "status", resp.StatusCode)
        return
    }
    
    // Pi-hole v6 response structure varies, but typically includes a list of clients.
    // We use a generic struct to parse the active clients.
    var stats struct {
        Clients []struct {
            IP   string `json:"ip"`
            Name string `json:"name"`
            Mac  string `json:"hwaddr"`
        } `json:"clients"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
        slog.Error("Failed to decode Pi-hole response", "error", err)
        return
    }
    
    for _, c := range stats.Clients {
        obs := Observation{
            Source:     p.Name(),
            IP:         net.ParseIP(c.IP),
            Hostname:   c.Name,
            Confidence: 0.3, // LOW confidence per §3.2
            Timestamp:  time.Now(),
        }
        if c.Mac != "" && c.Mac != "00:00:00:00:00:00" {
            if hw, err := net.ParseMAC(c.Mac); err == nil {
                obs.MAC = hw
            }
        }
        
        select {
        case p.events <- obs:
        default:
            slog.Warn("Pi-hole observation channel full, dropping event")
        }
    }
}

func (p *PiholeProvider) authenticate() error {
    payload, _ := json.Marshal(map[string]string{"password": p.cfg.Password})
    req, err := http.NewRequestWithContext(p.ctx, "POST", p.cfg.URL+"/api/auth", bytes.NewBuffer(payload))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")
    
    resp, err := p.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("pihole auth failed with status %d", resp.StatusCode)
    }
    
    var authResp struct {
        Session struct {
            SID   string `json:"sid"`
            Valid bool   `json:"valid"`
        } `json:"session"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
        return err
    }
    
    if !authResp.Session.Valid || authResp.Session.SID == "" {
        return fmt.Errorf("pihole auth returned invalid session")
    }
    
    p.sid = authResp.Session.SID
    p.sidValid = true
    slog.Info("Successfully authenticated with Pi-hole")
    return nil
}
