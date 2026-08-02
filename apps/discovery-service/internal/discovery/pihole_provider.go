// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/pihole_provider.go
// Version: 1.5
package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/config"
)

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

	p.poll()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if !p.isSessionValid() {
				if err := p.authenticate(); err != nil {
					slog.Error("Pi-hole v6 authentication failed, applying exponential backoff",
						"error", err, "next_retry_in", backoff)

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
				backoff = 10 * time.Second // Reset backoff on success
			}
			p.poll()
		}
	}
}

func (p *PiholeProvider) isSessionValid() bool {
	if !p.sidValid || p.sid == "" {
		return false
	}

	baseURL := strings.TrimRight(p.cfg.URL, "/")
	req, err := http.NewRequestWithContext(p.ctx, "GET", baseURL+"/api/auth?sid="+p.sid, nil)
	if err != nil {
		return false
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var checkResp struct {
		Session struct {
			Valid bool `json:"valid"`
		} `json:"session"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&checkResp); err == nil {
		return checkResp.Session.Valid
	}

	return false
}

func (p *PiholeProvider) poll() {
	if !p.isSessionValid() {
		if err := p.authenticate(); err != nil {
			slog.Error("Pi-hole v6 authentication failed", "error", err)
			return
		}
	}

	baseURL := strings.TrimRight(p.cfg.URL, "/")
	req, err := http.NewRequestWithContext(p.ctx, "GET", baseURL+"/api/stats/clients", nil)
	if err != nil {
		return
	}

	req.Header.Set("sid", p.sid)
	req.Header.Set("X-FTL-SID", p.sid)
	req.Header.Set("Cookie", "SID="+p.sid)

	resp, err := p.client.Do(req)
	if err != nil {
		slog.Error("Failed to fetch Pi-hole clients", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		p.sidValid = false
		slog.Warn("Pi-hole SID token rejected, will re-authenticate on next cycle")
		return
	}
	if resp.StatusCode != http.StatusOK {
		slog.Error("Pi-hole API returned non-200 status", "status", resp.StatusCode)
		return
	}

	var raw struct {
		Clients json.RawMessage `json:"clients"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		slog.Error("Failed to decode Pi-hole response wrapper", "error", err)
		return
	}

	type clientItem struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
		Mac  string `json:"hwaddr"`
	}

	var clientList []clientItem

	if err := json.Unmarshal(raw.Clients, &clientList); err != nil {
		var clientMap map[string]clientItem
		if mapErr := json.Unmarshal(raw.Clients, &clientMap); mapErr == nil {
			for ipKey, item := range clientMap {
				if item.IP == "" {
					item.IP = ipKey
				}
				clientList = append(clientList, item)
			}
		} else {
			slog.Error("Failed to decode Pi-hole clients payload", "error", err)
			return
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
			IP:         ipObj,
			MAC:        macObj,
			Hostname:   UnescapeHostname(c.Name),
			Online:     true,
			Confidence: 0.3,
			Timestamp:  time.Now(),
		}

		select {
		case p.events <- obs:
		default:
			slog.Warn("Pi-hole observation channel full, dropping event")
		}
	}
}

func (p *PiholeProvider) authenticate() error {
	baseURL := strings.TrimRight(p.cfg.URL, "/")
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

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pihole auth endpoint returned HTTP %d", resp.StatusCode)
	}

	var authResp struct {
		Session struct {
			SID   string `json:"sid"`
			Valid bool   `json:"valid"`
		} `json:"session"`
		Error struct {
			Key     string `json:"key"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode pihole auth response: %w", err)
	}

	if !authResp.Session.Valid || authResp.Session.SID == "" {
		return fmt.Errorf("pihole auth returned invalid session state: key=%q message=%q",
			authResp.Error.Key, authResp.Error.Message)
	}

	p.sid = authResp.Session.SID
	p.sidValid = true
	slog.Info("Successfully authenticated with Pi-hole v6 REST API")
	return nil
}
