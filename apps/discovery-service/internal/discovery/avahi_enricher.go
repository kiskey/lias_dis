package discovery

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/user/lias-dis/shared/models"
)

type AvahiEnricher struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.RWMutex
	records map[string]avahiRecord
}

const maxAvahiRecords = 4096

type avahiRecord struct {
	Interface    string
	Protocol     string
	FriendlyName string
	Hostname     string
	ServiceType  string
	Domain       string
	IP           string
	Port         uint16
	TXT          map[string]string
	Timestamp    time.Time
}

func NewAvahiEnricher() *AvahiEnricher {
	return &AvahiEnricher{done: make(chan struct{}), records: make(map[string]avahiRecord)}
}

func (e *AvahiEnricher) Name() string { return "avahi" }

func (e *AvahiEnricher) Start(ctx context.Context) error {
	if _, err := exec.LookPath("avahi-browse"); err != nil {
		return fmt.Errorf("avahi-browse unavailable: %w", err)
	}
	e.ctx, e.cancel = context.WithCancel(ctx)
	go e.runPersistentListener()
	return nil
}

func (e *AvahiEnricher) Stop() error {
	if e.cancel != nil {
		e.cancel()
		<-e.done
	}
	return nil
}

func (e *AvahiEnricher) runPersistentListener() {
	defer close(e.done)
	for {
		if e.ctx.Err() != nil {
			return
		}
		// Avahi owns RR TTL/cache-flush/goodbye processing and emits '-'
		// lifecycle events. --no-fail keeps the watch attached across daemon
		// restarts without spawning a polling process per device.
		cmd := exec.CommandContext(e.ctx, "avahi-browse", "-a", "-r", "-p", "-k", "-f")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			slog.Warn("Failed to create avahi-browse pipe", "error", err)
			if !waitForContext(e.ctx, 30*time.Second) {
				return
			}
			continue
		}
		if err := cmd.Start(); err != nil {
			slog.Warn("Failed to start avahi-browse", "error", err)
			if !waitForContext(e.ctx, 30*time.Second) {
				return
			}
			continue
		}

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), 256<<10)
		for scanner.Scan() {
			event, key, rec, ok := parseAvahiBrowseLine(scanner.Text(), time.Now())
			if !ok {
				continue
			}
			e.mu.Lock()
			switch event {
			case "resolved":
				e.upsertRecordLocked(key, rec)
			case "removed":
				delete(e.records, key)
			}
			e.mu.Unlock()
		}
		if err := scanner.Err(); err != nil && e.ctx.Err() == nil {
			slog.Warn("avahi-browse output error", "error", err)
		}
		_ = cmd.Wait()
		// Once the watch is lost, its cache can no longer receive mDNS goodbye
		// or removal events. Clear it and let the restarted browser replay the
		// daemon's current cache instead of retaining unbounded stale records.
		e.mu.Lock()
		e.records = make(map[string]avahiRecord)
		e.mu.Unlock()
		if !waitForContext(e.ctx, 5*time.Second) {
			return
		}
	}
}

func (e *AvahiEnricher) upsertRecordLocked(key string, rec avahiRecord) {
	if _, exists := e.records[key]; !exists && len(e.records) >= maxAvahiRecords {
		oldestKey := ""
		var oldest time.Time
		for candidateKey, candidate := range e.records {
			if oldestKey == "" || candidate.Timestamp.Before(oldest) {
				oldestKey, oldest = candidateKey, candidate.Timestamp
			}
		}
		delete(e.records, oldestKey)
	}
	e.records[key] = rec
}

func waitForContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func parseAvahiBrowseLine(line string, now time.Time) (string, string, avahiRecord, bool) {
	if len(line) > 4096 {
		return "", "", avahiRecord{}, false
	}
	parts := strings.Split(line, ";")
	if len(parts) < 6 {
		return "", "", avahiRecord{}, false
	}
	action := parts[0]
	if action != "=" && action != "-" {
		return "", "", avahiRecord{}, false
	}
	iface := unescapeAvahiField(parts[1])
	protocol := unescapeAvahiField(parts[2])
	name := unescapeAvahiField(parts[3])
	serviceType := strings.ToLower(unescapeAvahiField(parts[4]))
	domain := normalizeDomain(unescapeAvahiField(parts[5]))
	if iface == "" || name == "" || serviceType == "" {
		return "", "", avahiRecord{}, false
	}
	key := strings.Join([]string{iface, protocol, name, serviceType, domain}, "\x00")
	if action == "-" {
		return "removed", key, avahiRecord{}, true
	}
	if len(parts) < 9 {
		return "", "", avahiRecord{}, false
	}
	hostname := normalizeDomain(unescapeAvahiField(parts[6]))
	ip := normalizeScopedIP(unescapeAvahiField(parts[7]))
	if ip == "" {
		return "", "", avahiRecord{}, false
	}
	portValue, err := strconv.ParseUint(parts[8], 10, 16)
	if err != nil {
		return "", "", avahiRecord{}, false
	}
	txt := map[string]string(nil)
	if len(parts) > 9 {
		txt = parseAvahiTXT(strings.Join(parts[9:], ";"))
	}
	return "resolved", key, avahiRecord{Interface: iface, Protocol: protocol, FriendlyName: name,
		Hostname: hostname, ServiceType: serviceType, Domain: domain, IP: ip,
		Port: uint16(portValue), TXT: txt, Timestamp: now}, true
}

func unescapeAvahiField(value string) string {
	value = strings.TrimSpace(value)
	var out strings.Builder
	out.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		if i+3 < len(value) {
			if decoded, err := strconv.ParseUint(value[i+1:i+4], 10, 8); err == nil {
				out.WriteByte(byte(decoded))
				i += 3
				continue
			}
		}
		if i+1 < len(value) {
			i++
			out.WriteByte(value[i])
		}
	}
	return strings.TrimSpace(out.String())
}

func parseAvahiTXT(value string) map[string]string {
	if len(value) == 0 || len(value) > 1300 {
		return nil
	}
	result := make(map[string]string)
	for _, token := range strings.Fields(value) {
		if len(result) >= 16 {
			break
		}
		token = strings.Trim(token, "\"")
		token = unescapeAvahiField(token)
		key, val, found := strings.Cut(token, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" || len(key) > 64 {
			continue
		}
		if !found {
			val = ""
		}
		if len(val) > 256 {
			val = val[:256]
		}
		result[key] = val
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func normalizeScopedIP(value string) string {
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if zone := strings.LastIndexByte(value, '%'); zone >= 0 {
		value = value[:zone]
	}
	ip := net.ParseIP(strings.Trim(value, "[]"))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (e *AvahiEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
	if d == nil || (d.CurrentIP == "" && d.Hostname == "") {
		return nil, fmt.Errorf("cannot enrich without IP or hostname")
	}
	targetHost := normalizeDomain(d.Hostname)
	targetIPs := make(map[string]struct{}, len(d.IPs)+1)
	for _, value := range append(append([]string(nil), d.IPs...), d.CurrentIP) {
		if ip := normalizeScopedIP(value); ip != "" {
			targetIPs[ip] = struct{}{}
		}
	}

	e.mu.RLock()
	found := make([]avahiRecord, 0)
	for _, rec := range e.records {
		_, ipMatch := targetIPs[rec.IP]
		if ipMatch || (targetHost != "" && rec.Hostname == targetHost) {
			found = append(found, rec)
		}
	}
	e.mu.RUnlock()
	if len(found) == 0 {
		return nil, nil
	}
	sort.Slice(found, func(i, j int) bool { return found[i].ServiceType < found[j].ServiceType })
	enr := &models.Enrichment{Source: e.Name(), Confidence: 0.75, Raw: make(map[string]interface{})}
	services := make(map[string]struct{})
	interfaces := make(map[string]struct{})
	mergedTXT := make(map[string]string)
	for _, rec := range found {
		if enr.FriendlyName == "" {
			enr.FriendlyName = rec.FriendlyName
		}
		if enr.Hostname == "" {
			enr.Hostname = rec.Hostname
		}
		services[rec.ServiceType] = struct{}{}
		interfaces[rec.Interface] = struct{}{}
		for key, value := range rec.TXT {
			if _, exists := mergedTXT[key]; !exists {
				mergedTXT[key] = value
			}
		}
	}
	for service := range services {
		enr.Services = append(enr.Services, service)
	}
	sort.Strings(enr.Services)
	var interfaceList []string
	for iface := range interfaces {
		interfaceList = append(interfaceList, iface)
	}
	sort.Strings(interfaceList)
	enr.Raw["mdns_interfaces"] = interfaceList
	if len(mergedTXT) > 0 {
		enr.Raw["mdns_txt"] = mergedTXT
	}
	enr.DeviceType = ClassifyDeviceFromMDNSServices(enr.Services)
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
