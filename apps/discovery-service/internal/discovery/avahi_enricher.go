// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/avahi_enricher.go
// Version: 1.1
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

// AvahiEnricher uses system `avahi-browse` to discover mDNS services
// and resolve friendly device names.
type AvahiEnricher struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewAvahiEnricher initializes the Avahi enricher.
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

// Enrich executes avahi-browse and parses mDNS records matching the target device.
func (e *AvahiEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
	if d == nil || (d.CurrentIP == "" && d.Hostname == "") {
		return nil, fmt.Errorf("cannot enrich without IP or Hostname")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	// -a: all services, -r: resolve, -p: parse-friendly, -t: terminate
	cmd := exec.CommandContext(timeoutCtx, "avahi-browse", "-a", "-r", "-p", "-t")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		slog.Debug("Avahi-browse execution skipped (avahi-tools not installed?)", "error", err)
		return nil, nil
	}

	enr := &models.Enrichment{
		Source:     "avahi",
		Confidence: 0.75,
		Raw:        make(map[string]interface{}),
	}

	var foundServices []string
	targetHostNormalized := normalizeDomain(d.Hostname)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: =;<interface>;<protocol>;<name>;<type>;<domain>;<hostname>;<address>;<port>;[txt]
		parts := strings.Split(line, ";")
		if len(parts) < 9 || parts[0] != "=" {
			continue
		}

		friendlyName := parts[3]
		serviceType := parts[4]
		mDnsHost := normalizeDomain(parts[6])
		ipAddress := parts[7]

		// Match by IP or normalized hostname (handling .local suffixes cleanly)
		ipMatch := d.CurrentIP != "" && ipAddress == d.CurrentIP
		hostMatch := targetHostNormalized != "" && mDnsHost != "" && targetHostNormalized == mDnsHost

		if ipMatch || hostMatch {
			if enr.FriendlyName == "" && friendlyName != "" {
				enr.FriendlyName = friendlyName
			}
			if enr.Hostname == "" && parts[6] != "" {
				enr.Hostname = parts[6]
			}

			foundServices = append(foundServices, serviceType)
		}
	}

	_ = cmd.Wait()

	if len(foundServices) == 0 && enr.FriendlyName == "" {
		return nil, nil
	}

	enr.Services = foundServices
	enr.DeviceType = ClassifyDeviceFromMDNSServices(foundServices)

	return enr, nil
}

// normalizeDomain strips .local suffixes and converts domains to lowercase for reliable comparisons.
func normalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimSuffix(d, ".local")
	return d
}

// ClassifyDeviceFromMDNSServices infers device types based on mDNS service signatures.
func ClassifyDeviceFromMDNSServices(services []string) string {
	for _, s := range services {
		svc := strings.ToLower(s)

		// Printers & Scanners
		if strings.Contains(svc, "_ipp") || strings.Contains(svc, "_printer") || strings.Contains(svc, "_pdl-datastream") {
			return "printer"
		}

		// Smart TVs & Media Streamers
		if strings.Contains(svc, "_airplay") || strings.Contains(svc, "_googlecast") || strings.Contains(svc, "_raop") {
			return "tv"
		}

		// Smart Home & IoT Protocols
		if strings.Contains(svc, "_hap") || strings.Contains(svc, "_homekit") || strings.Contains(svc, "_matter") {
			return "iot"
		}

		// Audio Hardware
		if strings.Contains(svc, "_sonos") || strings.Contains(svc, "_spotify-connect") || strings.Contains(svc, "_soundtouch") {
			return "audio"
		}

		// Network Storage / Servers
		if strings.Contains(svc, "_smb") || strings.Contains(svc, "_afpovertcp") || strings.Contains(svc, "_nfs") {
			return "server"
		}
	}

	return ""
}
