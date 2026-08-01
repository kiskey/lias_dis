// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/avahi_enricher.go
// Version: 1.0
package discovery

import (
    "bufio"
    "context"
    "fmt"
    "log/slog"
    "os/exec"
    "strings"
    "time"

    "github.com/user/lias-dis/shared/models"
)

// AvahiEnricher uses the system `avahi-browse` utility to discover mDNS
// services and friendly names. It relies on the Avahi daemon for completeness.
// See §3.5 for details.
type AvahiEnricher struct {
    ctx    context.Context
    cancel context.CancelFunc
}

// NewAvahiEnricher initializes the enricher.
func NewAvahiEnricher() *AvahiEnricher {
    return &AvahiEnricher{}
}

// Name returns the provider's identifier.
func (e *AvahiEnricher) Name() string { return "avahi" }

// Start satisfies the Provider interface.
func (e *AvahiEnricher) Start(ctx context.Context) error {
    e.ctx, e.cancel = context.WithCancel(ctx)
    return nil
}

// Stop satisfies the Provider interface.
func (e *AvahiEnricher) Stop() error {
    if e.cancel != nil {
        e.cancel()
    }
    return nil
}

// Enrich executes avahi-browse and parses the output for the target device.
func (e *AvahiEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    if d == nil || (d.CurrentIP == "" && d.Hostname == "") {
        return nil, fmt.Errorf("cannot enrich without IP or Hostname")
    }

    timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    // -a: all services, -r: resolve (include IP/hostname), -p: parse-friendly, -t: terminate
    cmd := exec.CommandContext(timeoutCtx, "avahi-browse", "-a", "-r", "-p", "-t")
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return nil, fmt.Errorf("failed to create pipe: %w", err)
    }

    if err := cmd.Start(); err != nil {
        slog.Debug("Avahi execution failed (is avahi-tools installed?)", "error", err)
        return nil, nil // Not a fatal error, just means no mDNS data available
    }

    enr := &models.Enrichment{
        Source:     "avahi",
        Confidence: 0.7, // High confidence for mDNS
        Raw:        make(map[string]interface{}),
    }

    var foundServices []string

    scanner := bufio.NewScanner(stdout)
    for scanner.Scan() {
        line := scanner.Text()
        // Format: =;<interface>;<protocol>;<name>;<type>;<domain>;<hostname>;<address>;<port>;[txt]
        // e.g., =;eth0;IPv4;MyPrinter;_ipp._tcp;local;myprinter.local;192.168.1.50;631;
        parts := strings.Split(line, ";")
        if len(parts) < 9 {
            continue
        }

        ip := parts[7]
        hostname := parts[6]

        // Match by IP or hostname
        if (d.CurrentIP != "" && ip == d.CurrentIP) || (d.Hostname != "" && hostname == d.Hostname) {
            if enr.FriendlyName == "" {
                enr.FriendlyName = parts[3]
            }
            if enr.Hostname == "" {
                enr.Hostname = hostname
            }
            foundServices = append(foundServices, parts[4])
        }
    }

    if err := cmd.Wait(); err != nil {
        slog.Debug("Avahi command wait error", "error", err)
    }

    if len(foundServices) == 0 && enr.FriendlyName == "" {
        return nil, nil
    }

    enr.Services = foundServices
    return enr, nil
}
