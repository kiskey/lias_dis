// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/pihole_provider.go
// Version: 2.0 (Removed Redundant Auth Check)
package discovery

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log/slog"
    "net"
    "net/http"
    "strings"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/config"
)

var errUnauthorized = fmt.Errorf("unauthorized")

type PiholeProvider struct {
    cfg      config.PiholeConfig
    ctx      context.Context
    cancel   context.CancelFunc
    events   chan Observation
    done     chan struct{}
    client   *http.Client
    sid      string
    sidValid bool
    noAuth   bool
}

func NewPiholeProvider(cfg config.PiholeConfig) *PiholeProvider {
    return &PiholeProvider{
        cfg:    cfg,
        events: make(chan Observation, 128),
        done:   make(chan struct{}),
        client: &http.Client{Timeout: 10 * time.Second},
    }
}

func (p *PiholeProvider) Name() string { return "pihole" }

func (p *PiholeProvider) Start(ctx context.Context) error {
    p.ctx, p.cancel = context.WithCancel(ctx)
    go p.run()
    return nil
}

func (p *PiholeProvider) Stop() error {
    if p.cancel != nil {
        p.cancel()
        <-p.done
    }
    return nil
}

func (p *PiholeProvider) Events() <-chan Observation {
    return p.events
}

func (p *PiholeProvider) run() {
    defer close(p.done)

    backoff := 10 * time.Second
    maxBackoff := 5 * time.Minute

    // Initial poll and auth
    if err := p.poll(); err == errUnauthorized {
        if authErr := p.authenticate(); authErr != nil {
            slog.Error("Initial Pi-hole auth failed", "error", authErr)
        } else {
            _ = p.poll()
        }
    }

    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-p.ctx.Done():
            return
        case <-ticker.C:
            // Low 2 Fix: Removed redundant isSessionValid() check.
            // Rely on HTTP 401 from poll() to trigger re-authentication.
            err := p.poll()
            if err == errUnauthorized {
                if authErr := p.authenticate(); authErr != nil {
                    slog.Error("Pi-hole v6 authentication failed, applying exponential backoff",
                        "error", authErr, "next_retry_in", backoff)

                    select {
                    case <-p.ctx.Done():
                        return
                    case <-time.After(backoff):
                        backoff *= 2
                        if backoff > maxBackoff {
                            backoff = maxBackoff
                        }
                    }
                    continue
                }
                backoff = 10 * time.Second
                // Retry poll immediately after successful auth
                _ = p.poll()
            }
        }
    }
}

func normalizePiholeURL(raw string) string {
    u := strings.TrimSpace(raw)
    if u == "" {
        return ""
    }
    if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
        u = "http://" + u
    }
    return strings.TrimRight(u, "/")
}

func (p *PiholeProvider) poll() error {
    baseURL := normalizePiholeURL(p.cfg.URL)
    if baseURL == "" {
        return nil
    }

    targetEndpoints := []string{
        "/api/stats/top_clients?count=100",
        "/api/network/devices",
        "/api/stats/clients",
    }

    var resp *http.Response
    var fetchErr error

    for _, ep := range targetEndpoints {
        req, err := http.NewRequestWithContext(p.ctx, "GET", baseURL+ep, nil)
        if err != nil {
            continue
        }

        if !p.noAuth && p.sid != "" {
            req.Header.Set("sid", p.sid)
            req.Header.Set("X-FTL-SID", p.sid)
            req.Header.Set("Cookie", "sid="+p.sid)
        }

        res, err := p.client.Do(req)
        if err == nil && res.StatusCode == http.StatusOK {
            resp = res
            break
        }
        if res != nil {
            // Low 2 Fix: If 401, return errUnauthorized to trigger re-auth
            if res.StatusCode == http.StatusUnauthorized {
                p.sidValid = false
                res.Body.Close()
                return errUnauthorized
            }
            res.Body.Close()
        }
        fetchErr = err
    }

    if resp == nil {
        if fetchErr != nil {
            slog.Debug("Failed to fetch Pi-hole v6 clients", "error", fetchErr)
        }
        return nil
    }
    defer resp.Body.Close()

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        slog.Error("Failed to read Pi-hole response body", "error", err)
        return nil
    }

    type clientItem struct {
        IP   string `json:"ip"`
        Name string `json:"name"`
        Mac  string `json:"hwaddr"`
    }

    var clientList []clientItem

    var topClientsWrapper struct {
        TopClients []struct {
            IP   string `json:"ip"`
            Name string `json:"name"`
            Mac  string `json:"hwaddr"`
        } `json:"top_clients"`
    }

    if err := json.Unmarshal(bodyBytes, &topClientsWrapper); err == nil && len(topClientsWrapper.TopClients) > 0 {
        for _, tc := range topClientsWrapper.TopClients {
            clientList = append(clientList, clientItem{
                IP:   tc.IP,
                Name: tc.Name,
                Mac:  tc.Mac,
            })
        }
    } else {
        var devWrapper struct {
            Devices []clientItem `json:"devices"`
        }
        if err := json.Unmarshal(bodyBytes, &devWrapper); err == nil && len(devWrapper.Devices) > 0 {
            clientList = devWrapper.Devices
        } else {
            var rawWrapper struct {
                Clients json.RawMessage `json:"clients"`
            }
            if err := json.Unmarshal(bodyBytes, &rawWrapper); err == nil {
                _ = json.Unmarshal(rawWrapper.Clients, &clientList)
            }
        }
    }

    for _, c := range clientList {
        if c.IP == "" {
            continue
        }

        ipObj := net.ParseIP(c.IP)
        var macObj net.HardwareAddr
        if c.Mac != "" && c.Mac != "00:00:00:00:00:00" {
            macObj, _ = net.ParseMAC(c.Mac)
        }

        if IsMulticastOrBroadcast(macObj, ipObj) {
            continue
        }

        obs := Observation{
            Source:     p.Name(),
            Group:      GroupC,
            IP:         ipObj,
            MAC:        macObj,
            Hostname:   UnescapeHostname(c.Name),
            Online:     true,
            Confidence: 0.30,
            Timestamp:  time.Now(),
        }

        select {
        case p.events <- obs:
        default:
            slog.Warn("Pi-hole observation channel full, dropping event")
        }
    }

    return nil
}

func (p *PiholeProvider) authenticate() error {
    baseURL := normalizePiholeURL(p.cfg.URL)
    if baseURL == "" {
        return fmt.Errorf("pihole URL not configured")
    }

    payload, _ := json.Marshal(map[string]string{"password": p.cfg.Password})

    req, err := http.NewRequestWithContext(p.ctx, "POST", baseURL+"/api/auth", bytes.NewBuffer(payload))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := p.client.Do(req)
    if err != nil {
        return fmt.Errorf("http POST /api/auth failed: %w", err)
    }
    defer resp.Body.Close()

    bodyBytes, _ := io.ReadAll(resp.Body)

    var authResp struct {
        Session struct {
            SID      string `json:"sid"`
            Valid    bool   `json:"valid"`
            Message  string `json:"message"`
            Validity int    `json:"validity"`
        } `json:"session"`
        Error struct {
            Key     string `json:"key"`
            Message string `json:"message"`
        } `json:"error"`
    }

    _ = json.Unmarshal(bodyBytes, &authResp)

    if resp.StatusCode != http.StatusOK {
        reason := authResp.Error.Message
        if reason == "" {
            reason = authResp.Error.Key
        }
        if reason == "" {
            reason = string(bodyBytes)
        }
        return fmt.Errorf("pihole auth endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(reason))
    }

    if authResp.Session.Message == "no password set" || (authResp.Session.Valid && authResp.Session.SID == "" && authResp.Session.Validity == -1) {
        p.noAuth = true
        p.sidValid = true
        p.sid = ""
        slog.Info("Pi-hole v6 has no password configured. Operating in unauthenticated open LAN mode")
        return nil
    }

    if !authResp.Session.Valid || authResp.Session.SID == "" || authResp.Session.SID == "null" {
        p.noAuth = false
        p.sidValid = false

        reason := authResp.Session.Message
        if reason == "" {
            reason = authResp.Error.Message
        }
        if reason == "" {
            reason = authResp.Error.Key
        }
        if reason == "" {
            reason = "password incorrect or session rejected"
        }
        return fmt.Errorf("pihole auth returned invalid session state: %s", reason)
    }

    p.noAuth = false
    p.sid = authResp.Session.SID
    p.sidValid = true
    slog.Info("Successfully authenticated with Pi-hole v6 REST API")
    return nil
}
