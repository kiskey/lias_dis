// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/avahi_enricher.go
// Version: 1.4 (Verified Persistent Listener)
package discovery

import (
    "bufio"
    "context"
    "fmt"
    "log/slog"
    "os/exec"
    "strings"
    "sync"
    "time"

    "github.com/user/lias-dis/shared/models"
)

type AvahiEnricher struct {
    ctx     context.Context
    cancel  context.CancelFunc
    mu      sync.RWMutex
    records map[string][]avahiRecord
}

type avahiRecord struct {
    FriendlyName string
    Hostname     string
    ServiceType  string
    IP           string
}

func NewAvahiEnricher() *AvahiEnricher {
    return &AvahiEnricher{
        records: make(map[string][]avahiRecord),
    }
}

func (e *AvahiEnricher) Name() string { return "avahi" }

func (e *AvahiEnricher) Start(ctx context.Context) error {
    e.ctx, e.cancel = context.WithCancel(ctx)
    go e.runPersistentListener()
    return nil
}

func (e *AvahiEnricher) Stop() error {
    if e.cancel != nil {
        e.cancel()
    }
    return nil
}

// ENR-05 Fix: Run a persistent avahi-browse in the background.
func (e *AvahiEnricher) runPersistentListener() {
    for {
        select {
        case <-e.ctx.Done():
            return
        default:
        }

        // -a: all services, -r: resolve, -p: parse-friendly, -k: keep alive
        cmd := exec.CommandContext(e.ctx, "avahi-browse", "-a", "-r", "-p", "-k")
        stdout, err := cmd.StdoutPipe()
        if err != nil {
            slog.Debug("Failed to create pipe for avahi-browse", "error", err)
            time.Sleep(30 * time.Second)
            continue
        }

        if err := cmd.Start(); err != nil {
            slog.Debug("Avahi-browse execution skipped (avahi-tools not installed?)", "error", err)
            time.Sleep(30 * time.Second)
            continue
        }

        scanner := bufio.NewScanner(stdout)
        for scanner.Scan() {
            line := scanner.Text()
            parts := strings.Split(line, ";")
            if len(parts) < 9 || parts[0] != "=" {
                continue
            }

            rec := avahiRecord{
                FriendlyName: parts[3],
                ServiceType:  parts[4],
                Hostname:     normalizeDomain(parts[6]),
                IP:           parts[7],
            }

            e.mu.Lock()
            if rec.IP != "" {
                e.records[rec.IP] = append(e.records[rec.IP], rec)
            }
            if rec.Hostname != "" {
                e.records[rec.Hostname] = append(e.records[rec.Hostname], rec)
            }
            e.mu.Unlock()
        }

        _ = cmd.Wait()
        
        select {
        case <-e.ctx.Done():
            return
        case <-time.After(5 * time.Second):
        }
    }
}

func (e *AvahiEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    if d == nil || (d.CurrentIP == "" && d.Hostname == "") {
        return nil, fmt.Errorf("cannot enrich without IP or Hostname")
    }

    targetHostNormalized := normalizeDomain(d.Hostname)
    targetIPStr := d.CurrentIP

    var foundRecords []avahiRecord

    e.mu.RLock()
    if targetIPStr != "" {
        if recs, ok := e.records[targetIPStr]; ok {
            foundRecords = append(foundRecords, recs...)
        }
    }
    if targetHostNormalized != "" {
        if recs, ok := e.records[targetHostNormalized]; ok {
            foundRecords = append(foundRecords, recs...)
        }
    }
    e.mu.RUnlock()

    if len(foundRecords) == 0 {
        return nil, nil
    }

    enr := &models.Enrichment{
        Source:     e.Name(),
        Confidence: 0.75,
        Raw:        make(map[string]interface{}),
    }

    var foundServices []string
    for _, rec := range foundRecords {
        if enr.FriendlyName == "" && rec.FriendlyName != "" {
            enr.FriendlyName = rec.FriendlyName
        }
        if enr.Hostname == "" && rec.Hostname != "" {
            enr.Hostname = rec.Hostname
        }
        foundServices = append(foundServices, rec.ServiceType)
    }

    enr.Services = foundServices
    enr.DeviceType = ClassifyDeviceFromMDNSServices(foundServices)

    return enr, nil
}

func normalizeDomain(domain string) string {
    d := strings.ToLower(strings.TrimSpace(domain))
    d = strings.TrimSuffix(d, ".")
    d = strings.TrimSuffix(d, ".local")
    return d
}

func ClassifyDeviceFromMDNSServices(services []string) string {
    for _, s := range services {
        svc := strings.ToLower(s)

        if strings.Contains(svc, "_ipp") || strings.Contains(svc, "_printer") || strings.Contains(svc, "_pdl-datastream") {
            return "printer"
        }
        if strings.Contains(svc, "_airplay") || strings.Contains(svc, "_googlecast") || strings.Contains(svc, "_raop") {
            return "tv"
        }
        if strings.Contains(svc, "_hap") || strings.Contains(svc, "_homekit") || strings.Contains(svc, "_matter") {
            return "iot"
        }
        if strings.Contains(svc, "_sonos") || strings.Contains(svc, "_spotify-connect") || strings.Contains(svc, "_soundtouch") {
            return "audio"
        }
        if strings.Contains(svc, "_smb") || strings.Contains(svc, "_afpovertcp") || strings.Contains(svc, "_nfs") {
            return "server"
        }
    }
    return ""
}
