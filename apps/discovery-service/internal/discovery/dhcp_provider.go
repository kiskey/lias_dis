// Package discovery implements DHCP lease and OpenWrt observation providers.
package discovery

import (
    "bufio"
    "bytes"
    "context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
    "fmt"
    "io"
    "log/slog"
    "net"
    "net/http"
    "os"
    "os/exec"
	"sort"
    "strconv"
    "strings"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/config"
)

const (
	maxDHCPPayloadBytes = 4 << 20
	maxDHCPRecords      = 4096
)

type DHCPProvider struct {
    cfg    config.DHCPConfig
    ctx    context.Context
    cancel context.CancelFunc
    events chan Observation
    done   chan struct{}
    client *http.Client
	seenLeases map[string]string
}

func NewDHCPProvider(cfg config.DHCPConfig) *DHCPProvider {
    return &DHCPProvider{
		cfg: cfg, events: make(chan Observation, 256), done: make(chan struct{}),
		client: &http.Client{Timeout: 10 * time.Second}, seenLeases: make(map[string]string),
    }
}

func (p *DHCPProvider) Name() string { return "dhcp" }

func (p *DHCPProvider) Start(ctx context.Context) error {
	if _, err := normalizeLeaseType(p.cfg.Type); err != nil {
		return err
	}
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

func (p *DHCPProvider) Events() <-chan Observation { return p.events }

func (p *DHCPProvider) run() {
    defer close(p.done)
	interval := p.cfg.PollInterval
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	ticker := time.NewTicker(interval)
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
	payload, err := p.fetchPayload()
	if err != nil {
		slog.Debug("DHCP/OpenWrt poll failed", "error", err)
		return
	}
	leaseData, apLines, neighLines, err := splitDHCPPayload(payload)
	if err != nil {
		slog.Warn("Rejected malformed DHCP/OpenWrt payload", "error", err)
		return
	}
	leaseType, _ := normalizeLeaseType(p.cfg.Type)
	leases, err := parseLeasePayload(leaseType, leaseData, time.Now())
	if err != nil {
		slog.Warn("Rejected malformed DHCP lease payload", "type", leaseType, "error", err)
		return
	}
	p.emitChangedLeases(leases)
	for _, line := range apLines {
		if obs, ok := parseOpenWrtStationLine(line); ok {
			p.emit(obs)
		}
	}
	for _, line := range neighLines {
		if obs, ok := parseOpenWrtNeighborLine(line); ok {
			p.emit(obs)
		}
	}
}

func (p *DHCPProvider) fetchPayload() ([]byte, error) {
    if p.cfg.SSHHost != "" {
        user := p.cfg.SSHUser
        if user == "" {
            user = "root"
        }
        leaseFile := p.cfg.LeaseFile
        if leaseFile == "" {
            leaseFile = "/tmp/dhcp.leases"
        }
		var script strings.Builder
		script.WriteString("cat -- ")
		script.WriteString(shellQuote(leaseFile))
        if p.cfg.OpenWrtAPEnabled {
			script.WriteString(`; printf '\n===AP_ASSOC===\n'; for iface in $(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}'); do iw dev "$iface" station dump 2>/dev/null | awk -v iface="$iface" '$1=="Station"{print iface, $2}'; done`)
        }
		if p.cfg.NeighborTableEnabled || p.cfg.ArpTableEnabled {
			script.WriteString(`; printf '\n===NEIGH_REACHABLE===\n'; ip -o neigh show nud reachable 2>/dev/null | awk '$0 ~ /lladdr/ {for(i=1;i<=NF;i++) if($i=="lladdr") {print $1, $(i+1), "REACHABLE"}}'`)
        }
		target := fmt.Sprintf("%s@%s", user, p.cfg.SSHHost)
		sshArgs := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
			"-o", "UserKnownHostsFile=/etc/dis/known_hosts", "-o", "ConnectTimeout=5"}
		if err := os.MkdirAll("/run/dis", 0o700); err == nil {
			sshArgs = append(sshArgs, "-o", "ControlMaster=auto", "-o", "ControlPersist=5m", "-o", "ControlPath=/run/dis/ssh-%C")
		}
		sshArgs = append(sshArgs, target, "sh", "-c", shellQuote(script.String()))
		cmd := exec.CommandContext(p.ctx, "ssh", sshArgs...)
		output, err := cmd.Output()
        if err != nil {
			return nil, fmt.Errorf("SSH collection: %w", err)
        }
		if len(output) > maxDHCPPayloadBytes {
			return nil, fmt.Errorf("SSH payload exceeds %d bytes", maxDHCPPayloadBytes)
		}
		return output, nil
        }
        
	if p.cfg.LeaseURL != "" {
		req, err := http.NewRequestWithContext(p.ctx, http.MethodGet, p.cfg.LeaseURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := p.client.Do(req)
		if err != nil {
			return nil, err
        }
        defer resp.Body.Close()
        if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("lease endpoint status %d", resp.StatusCode)
		}
		return readBounded(resp.Body, maxDHCPPayloadBytes)
        }
        
	if p.cfg.LeaseFile == "" {
		return nil, fmt.Errorf("no DHCP lease source configured")
	}
	file, err := os.Open(p.cfg.LeaseFile)
	if err != nil {
		return nil, err
        }
        defer file.Close()
	return readBounded(file, maxDHCPPayloadBytes)
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(reader, limit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("payload exceeds %d bytes", limit)
	}
	return data, nil
    }

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
    
func splitDHCPPayload(payload []byte) ([]byte, []string, []string, error) {
	var lease bytes.Buffer
	var apLines, neighLines []string
	section := "lease"
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 4096), 256<<10)
    for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch line {
		case "===AP_ASSOC===":
			section = "ap"
            continue
		case "===NEIGH_REACHABLE===", "===ARP_TABLE===":
			section = "neigh"
            continue
        }
		switch section {
		case "lease":
			lease.WriteString(scanner.Text())
			lease.WriteByte('\n')
		case "ap":
			if line != "" {
				if len(apLines) >= maxDHCPRecords {
					return nil, nil, nil, fmt.Errorf("AP station count exceeds limit")
				}
				apLines = append(apLines, line)
			}
		case "neigh":
			if line != "" {
				if len(neighLines) >= maxDHCPRecords {
					return nil, nil, nil, fmt.Errorf("neighbour count exceeds limit")
				}
				neighLines = append(neighLines, line)
        }
    }
}
	if err := scanner.Err(); err != nil {
		return nil, nil, nil, err
	}
	return lease.Bytes(), apLines, neighLines, nil
}

func normalizeLeaseType(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "router", "openwrt", "pihole", "dnsmasq":
		return "dnsmasq", nil
	case "kea":
		return "kea", nil
	default:
		return "", fmt.Errorf("unsupported DHCP lease type %q", value)
	}
    }
    
func parseLeasePayload(leaseType string, data []byte, now time.Time) ([]Observation, error) {
	switch leaseType {
	case "dnsmasq":
		return parseDNSMasqLeases(data, now)
	case "kea":
		return parseKeaLeases(data, now)
	default:
		return nil, fmt.Errorf("unsupported DHCP lease type %q", leaseType)
	}
    }
    
func parseDNSMasqLeases(data []byte, now time.Time) ([]Observation, error) {
	var result []Observation
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "duid ") {
			continue
		}
		parts := strings.Fields(line)
		// dnsmasq IPv4 lease format is exactly:
		// expiry, hardware address, IPv4 address, hostname, client-id.
		if len(parts) != 5 {
			continue
		}
		expires, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || (expires != 0 && expires <= now.Unix()) {
			continue
		}
		mac, err := net.ParseMAC(parts[1])
    ip := net.ParseIP(parts[2])
		if err != nil || len(mac) != 6 || ip == nil || ip.To4() == nil {
			continue
    }
    hostname := parts[3]
    if hostname == "*" {
        hostname = ""
    }
		raw := map[string]interface{}{"lease_format": "dnsmasq"}
		if expires != 0 {
			raw["lease_expires_at"] = time.Unix(expires, 0).UTC().Format(time.RFC3339)
    }
		if parts[4] != "*" {
			raw["dhcp_client_id_hash"] = hashCredential(parts[4])
        }
		result = append(result, Observation{Source: "dhcp", Group: GroupB, MAC: mac, IP: ip,
			Hostname: hostname, Online: false, Confidence: 0.60, Timestamp: now, Raw: raw})
		if len(result) > maxDHCPRecords {
			return nil, fmt.Errorf("dnsmasq active lease count exceeds limit")
    }
    }
	return result, scanner.Err()
}

func parseKeaLeases(data []byte, now time.Time) ([]Observation, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err == io.EOF {
		return nil, nil
    }
    if err != nil {
		return nil, err
    }
	columns := make(map[string]int, len(header))
	for i, name := range header {
		columns[strings.ToLower(strings.TrimSpace(name))] = i
    }
	for _, required := range []string{"address", "hwaddr", "expire"} {
		if _, ok := columns[required]; !ok {
			return nil, fmt.Errorf("Kea CSV missing %q column", required)
    }
}
	latest := make(map[string]Observation)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
    }
    if err != nil {
			return nil, err
    }
		field := func(name string) string {
			idx, ok := columns[name]
			if !ok || idx >= len(record) {
				return ""
    }
			return strings.TrimSpace(record[idx])
		}
		mac, err := net.ParseMAC(field("hwaddr"))
		ip := net.ParseIP(field("address"))
		if err != nil || len(mac) != 6 || ip == nil || ip.To4() == nil {
			continue
		}
		// Kea memfile is append-only between lease-file cleanups. The last
		// row for an address is authoritative, including a reclaimed/expired
		// tombstone, so never resurrect an older active row.
		key := ip.String()
		expires, err := strconv.ParseInt(field("expire"), 10, 64)
		if state := field("state"); err != nil || expires <= now.Unix() || (state != "" && state != "0") {
			delete(latest, key)
			continue
		}
		hostname := field("hostname")
		raw := map[string]interface{}{"lease_format": "kea", "lease_expires_at": time.Unix(expires, 0).UTC().Format(time.RFC3339)}
		if clientID := field("client_id"); clientID != "" {
			raw["dhcp_client_id_hash"] = hashCredential(clientID)
		}
		obs := Observation{Source: "dhcp", Group: GroupB, MAC: mac, IP: ip, Hostname: hostname,
			Online: false, Confidence: 0.60, Timestamp: now, Raw: raw}
		if _, exists := latest[key]; !exists && len(latest) >= maxDHCPRecords {
			return nil, fmt.Errorf("Kea active lease count exceeds limit")
    }
		latest[key] = obs
	}
	keys := make([]string, 0, len(latest))
	for key := range latest {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Observation, 0, len(keys))
	for _, key := range keys {
		result = append(result, latest[key])
	}
	return result, nil
}

func hashCredential(value string) string {
	sum := sha256.Sum256([]byte("dhcp-client-id\x00" + strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}
    
func (p *DHCPProvider) emitChangedLeases(leases []Observation) {
	current := make(map[string]string, len(leases))
	for _, obs := range leases {
		key := obs.MAC.String() + "|" + obs.IP.String()
		signature := obs.Hostname + "|" + fmt.Sprint(obs.Raw["lease_expires_at"]) + "|" + fmt.Sprint(obs.Raw["dhcp_client_id_hash"])
		current[key] = signature
		if p.seenLeases[key] != signature {
			p.emit(obs)
            }
        }
	p.seenLeases = current
                }

func parseOpenWrtStationLine(line string) (Observation, bool) {
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return Observation{}, false
            }
	mac, err := net.ParseMAC(parts[1])
	if err != nil || len(mac) != 6 {
		return Observation{}, false
        }
	return Observation{Source: "openwrt_ap", Group: GroupA, MAC: mac, Online: true,
		Confidence: 0.99, Timestamp: time.Now(), Raw: map[string]interface{}{"wifi_interface": parts[0]}}, true
    }

func parseOpenWrtNeighborLine(line string) (Observation, bool) {
	parts := strings.Fields(line)
	if len(parts) != 3 || !strings.EqualFold(parts[2], "REACHABLE") {
		return Observation{}, false
    }
	ip := net.ParseIP(parts[0])
	mac, err := net.ParseMAC(parts[1])
	if ip == nil || err != nil || len(mac) != 6 {
		return Observation{}, false
    }
	return Observation{Source: "openwrt_neigh", Group: GroupA, MAC: mac, IP: ip, Online: true,
		Confidence: 0.95, Timestamp: time.Now(), Raw: map[string]interface{}{"nud_state": "reachable"}}, true
    }

func (p *DHCPProvider) emit(obs Observation) {
	select {
	case p.events <- obs:
	default:
		slog.Warn("DHCP/OpenWrt observation channel full, dropping event", "source", obs.Source)
	}
}
