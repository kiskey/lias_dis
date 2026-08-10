// Package discovery implements the SSDP control-point subset used by DIS.
//
// File:    apps/discovery-service/internal/discovery/ssdp_enricher.go
// Version: 2.0 (Bounded Parser, Lifecycle, Interface Scope, and SSRF Guard)
package discovery

import (
	"bytes"
    "context"
    "encoding/xml"
	"errors"
    "fmt"
	"io"
    "log/slog"
    "net"
    "net/http"
    "net/url"
	"strconv"
    "strings"
    "sync"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/models"
)

const (
	ssdpMulticastAddress = "239.255.255.250:1900"
	maxSSDPDatagram      = 8192
	maxSSDPHeaders       = 64
	maxSSDPHeaderLine    = 1024
	maxSSDPRecords       = 2048
	maxDescriptorBytes   = 1 << 20
	ssdpTriggerCooldown  = 5 * time.Minute
)

type EnrichmentTriggerer interface {
    TriggerEnrichment(pdid string, force bool)
}

type ssdpNotice struct {
	sourceIP string
}

type ssdpMessage struct {
	startLine string
	headers   map[string]string
}

type ssdpRecord struct {
	location  string
	sourceIP  string
	expiresAt time.Time
}

type SSDPEnricher struct {
    ctx       context.Context
    cancel    context.CancelFunc
    ifaceName string
	iface     *net.Interface
	listener  *net.UDPConn
    cache     *inventory.Cache
    trigger   EnrichmentTriggerer
	bgQueue   chan ssdpNotice
	recordMu  sync.Mutex
	records   map[string]ssdpRecord
    wg        sync.WaitGroup
	stopOnce  sync.Once
}

func NewSSDPEnricher(ifaceName string) *SSDPEnricher {
    return &SSDPEnricher{
        ifaceName: ifaceName,
		bgQueue:   make(chan ssdpNotice, 64),
		records:   make(map[string]ssdpRecord),
    }
}

func (e *SSDPEnricher) Name() string { return "ssdp" }

func (e *SSDPEnricher) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("ssdp requires a non-nil context")
	}
	var err error
	if e.ifaceName != "" {
		e.iface, err = net.InterfaceByName(e.ifaceName)
		if err != nil {
			return fmt.Errorf("resolve SSDP interface %q: %w", e.ifaceName, err)
		}
	}
	addr, err := net.ResolveUDPAddr("udp4", ssdpMulticastAddress)
	if err != nil {
		return fmt.Errorf("resolve SSDP multicast address: %w", err)
	}
	listener, err := net.ListenMulticastUDP("udp4", e.iface, addr)
	if err != nil {
		return fmt.Errorf("listen SSDP multicast on %q: %w", e.ifaceName, err)
	}
	_ = listener.SetReadBuffer(maxSSDPDatagram * 8)
	e.listener = listener
    e.ctx, e.cancel = context.WithCancel(ctx)
	e.wg.Add(2)
    go e.runPassiveListener()
    go e.runBackgroundFetcher()
    return nil
}

func (e *SSDPEnricher) Stop() error {
	e.stopOnce.Do(func() {
    if e.cancel != nil {
        e.cancel()
    }
		if e.listener != nil {
			_ = e.listener.Close()
		}
	})
    e.wg.Wait()
    return nil
}

func (e *SSDPEnricher) SetCache(cache *inventory.Cache) { e.cache = cache }

func (e *SSDPEnricher) SetEnrichmentTriggerer(t EnrichmentTriggerer) { e.trigger = t }

func (e *SSDPEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    if d == nil || d.CurrentIP == "" {
        return nil, fmt.Errorf("cannot enrich without IP")
    }
	target := net.ParseIP(strings.TrimSpace(d.CurrentIP))
	if !isLANAddress(target) {
		return nil, fmt.Errorf("refusing SSDP enrichment for non-LAN IP %q", d.CurrentIP)
    }

	location, err := e.searchSSDP(ctx, target)
	if err != nil || location == "" {
        return nil, err
    }
	return e.fetchDescriptor(ctx, location, target)
}

func (e *SSDPEnricher) searchSSDP(ctx context.Context, targetIP net.IP) (string, error) {
	searchCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
    defer cancel()

	localAddr := &net.UDPAddr{IP: net.IPv4zero}
	if e.iface != nil {
		ip, err := interfaceIPv4(e.iface)
    if err != nil {
        return "", err
    }
		localAddr.IP = ip
	}
	conn, err := net.ListenUDP("udp4", localAddr)
    if err != nil {
        return "", err
    }
    defer conn.Close()

    deadline, _ := searchCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	addr, err := net.ResolveUDPAddr("udp4", ssdpMulticastAddress)
	if err != nil {
		return "", err
	}
    msg := []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: " + ssdpMulticastAddress + "\r\n" +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 2\r\n" +
        "ST: ssdp:all\r\n\r\n")
	if _, err := conn.WriteToUDP(msg, addr); err != nil {
        return "", err
    }

	buf := make([]byte, maxSSDPDatagram+1)
    for {
		n, src, err := conn.ReadFromUDP(buf)
        if err != nil {
            if searchCtx.Err() != nil {
                return "", nil
            }
            return "", err
        }
		if n > maxSSDPDatagram || src == nil || !src.IP.Equal(targetIP) {
			continue
		}
		parsed, err := parseSSDPMessage(buf[:n])
		if err != nil || parsed.startLine != "HTTP/1.1 200 OK" {
			continue
		}
		location := parsed.headers["location"]
		if _, err := validateDescriptorURL(location, targetIP); err == nil {
			return location, nil
        }
    }
}

func (e *SSDPEnricher) runPassiveListener() {
	defer e.wg.Done()
	buf := make([]byte, maxSSDPDatagram+1)
	for {
		_ = e.listener.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := e.listener.ReadFromUDP(buf)
    if err != nil {
			if e.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
        return
    }
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
        }
			slog.Debug("SSDP passive read error", "error", err)
			continue
    }
		if n > maxSSDPDatagram || src == nil || !isLANAddress(src.IP) {
			continue
		}
		msg, err := parseSSDPMessage(buf[:n])
		if err != nil || msg.startLine != "NOTIFY * HTTP/1.1" {
			continue
		}
		e.handleNotify(msg, src.IP)
    }
    }

func (e *SSDPEnricher) handleNotify(msg *ssdpMessage, sourceIP net.IP) {
	nts := strings.ToLower(msg.headers["nts"])
	usn := strings.TrimSpace(msg.headers["usn"])
	if usn == "" {
            return
        }
	if nts == "ssdp:byebye" {
		e.recordMu.Lock()
		delete(e.records, usn)
		e.recordMu.Unlock()
		return
            }
	if nts != "ssdp:alive" && nts != "ssdp:update" {
                return
            }
	location := msg.headers["location"]
	if _, err := validateDescriptorURL(location, sourceIP); err != nil {
		return
	}
	ttl := parseSSDPCacheTTL(msg.headers["cache-control"])
	if ttl == 0 {
		return
        }

	e.recordMu.Lock()
	if len(e.records) >= maxSSDPRecords {
		e.evictExpiredLocked(time.Now())
                }
	accepted := false
	if len(e.records) < maxSSDPRecords {
		e.records[usn] = ssdpRecord{location: location, sourceIP: sourceIP.String(), expiresAt: time.Now().Add(ttl)}
		accepted = true
            }
	e.recordMu.Unlock()
	if !accepted {
		return
        }

	select {
	case e.bgQueue <- ssdpNotice{sourceIP: sourceIP.String()}:
	case <-e.ctx.Done():
	default:
		slog.Debug("SSDP background queue full; notification dropped", "src", sourceIP)
    }
}

func (e *SSDPEnricher) runBackgroundFetcher() {
    defer e.wg.Done()
	lastTrigger := make(map[string]time.Time)
	cleanup := time.NewTicker(time.Minute)
	defer cleanup.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-cleanup.C:
			now := time.Now()
			e.recordMu.Lock()
			e.evictExpiredLocked(now)
			e.recordMu.Unlock()
			for ip, last := range lastTrigger {
				if now.Sub(last) >= 2*ssdpTriggerCooldown {
					delete(lastTrigger, ip)
				}
			}
		case notice := <-e.bgQueue:
			if e.cache == nil || e.trigger == nil || time.Since(lastTrigger[notice.sourceIP]) < ssdpTriggerCooldown {
            continue
        }
			dev := e.cache.GetByIP(notice.sourceIP)
			if dev == nil || dev.IsFullyIdentified || (dev.Vendor != "" && dev.DeviceType != "" && (dev.FriendlyName != "" || dev.Hostname != "")) {
            continue
        }
			lastTrigger[notice.sourceIP] = time.Now()
			e.trigger.TriggerEnrichment(dev.PDID, false)
		}
	}
}

func (e *SSDPEnricher) evictExpiredLocked(now time.Time) {
	for usn, record := range e.records {
		if !record.expiresAt.After(now) {
			delete(e.records, usn)
		}
            }
        }

func parseSSDPMessage(data []byte) (*ssdpMessage, error) {
	if len(data) == 0 || len(data) > maxSSDPDatagram || bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("invalid SSDP datagram size or content")
	}
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 || len(bytes.TrimSpace(data[headerEnd+4:])) != 0 {
		return nil, errors.New("invalid SSDP header termination")
	}
	lines := strings.Split(string(data[:headerEnd]), "\r\n")
	if len(lines) < 2 {
		return nil, errors.New("invalid SSDP line framing")
	}
	start := strings.TrimSpace(lines[0])
	if start != "HTTP/1.1 200 OK" && start != "NOTIFY * HTTP/1.1" {
		return nil, fmt.Errorf("unsupported SSDP start line %q", start)
	}
	headers := make(map[string]string)
	count := 0
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		count++
		if count > maxSSDPHeaders || len(line) > maxSSDPHeaderLine {
			return nil, errors.New("SSDP header limits exceeded")
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, errors.New("malformed SSDP header")
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if _, duplicate := headers[name]; duplicate {
			return nil, fmt.Errorf("duplicate SSDP header %q", name)
		}
		headers[name] = strings.TrimSpace(value)
	}
	return &ssdpMessage{startLine: start, headers: headers}, nil
        }

func parseSSDPCacheTTL(value string) time.Duration {
	for _, part := range strings.Split(value, ",") {
		name, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "max-age") {
            continue
        }
		seconds, err := strconv.Atoi(strings.Trim(strings.TrimSpace(raw), "\""))
		if err != nil || seconds <= 0 {
			return 0
    }
		if seconds < 30 {
			seconds = 30
}
		if seconds > 86400 {
			seconds = 86400
    }
		return time.Duration(seconds) * time.Second
	}
	return 0
}

func validateDescriptorURL(rawURL string, expectedIP net.IP) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil || u.IsAbs() == false {
		return nil, errors.New("invalid absolute SSDP descriptor URL")
        }
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("SSDP descriptor URL must use HTTP or HTTPS")
	}
	if u.User != nil || u.Hostname() == "" || u.Fragment != "" {
		return nil, errors.New("SSDP descriptor URL contains forbidden components")
	}
	hostIP := net.ParseIP(u.Hostname())
	if hostIP == nil || expectedIP == nil || !hostIP.Equal(expectedIP) || !isLANAddress(hostIP) {
		return nil, errors.New("SSDP descriptor host must be the advertising LAN IP")
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return nil, errors.New("invalid SSDP descriptor port")
    }
	}
	return u, nil
}

func (e *SSDPEnricher) fetchDescriptor(ctx context.Context, rawURL string, expectedIP net.IP) (*models.Enrichment, error) {
	u, err := validateDescriptorURL(rawURL, expectedIP)
    if err != nil {
        return nil, err
    }
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			port := u.Port()
			if port == "" {
				if u.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(expectedIP.String(), port))
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   4 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/xml, application/xml")
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SSDP descriptor returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDescriptorBytes+1))
	if err != nil {
		return nil, err
	}
	return parseSSDPDescriptor(body)
    }

func parseSSDPDescriptor(body []byte) (*models.Enrichment, error) {
	if len(body) > maxDescriptorBytes {
		return nil, errors.New("SSDP descriptor exceeds 1 MiB limit")
	}
	upperBody := bytes.ToUpper(body)
	if bytes.Contains(upperBody, []byte("<!DOCTYPE")) || bytes.Contains(upperBody, []byte("<!ENTITY")) {
		return nil, errors.New("SSDP descriptor contains a forbidden XML declaration")
	}
	var descriptor struct {
        XMLName xml.Name `xml:"root"`
        Device  struct {
            FriendlyName string `xml:"friendlyName"`
            Manufacturer string `xml:"manufacturer"`
            ModelName    string `xml:"modelName"`
            ModelNumber  string `xml:"modelNumber"`
            DeviceType   string `xml:"deviceType"`
        } `xml:"device"`
    }
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	if err := decoder.Decode(&descriptor); err != nil {
		return nil, fmt.Errorf("parse SSDP descriptor: %w", err)
    }

	deviceType := boundedText(descriptor.Device.DeviceType, 512)
    enr := &models.Enrichment{
		Source:       "ssdp",
        Confidence:   0.85,
		FriendlyName: boundedText(descriptor.Device.FriendlyName, 256),
		Manufacturer: boundedText(descriptor.Device.Manufacturer, 256),
		Model:        boundedText(descriptor.Device.ModelName, 256),
        Raw: map[string]interface{}{
			"device_type":       deviceType,
			"model_number":      boundedText(descriptor.Device.ModelNumber, 256),
			"identity_evidence": false,
        },
    }
	if strings.Contains(deviceType, "MediaRenderer") {
        enr.DeviceType = "tv"
	} else if strings.Contains(deviceType, "MediaServer") {
        enr.DeviceType = "server"
    }
    return enr, nil
}

func interfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list addresses for interface %q: %w", iface.Name, err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.To4(), nil
		}
	}
	return nil, fmt.Errorf("interface %q has no usable IPv4 address", iface.Name)
}

func isLANAddress(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && (ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func boundedText(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		value = value[:max]
	}
	return value
}

// Compatibility helpers retained for callers and older tests.
func extractIPFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func parseLocation(headers string) string {
	msg, err := parseSSDPMessage([]byte(headers))
	if err != nil {
		return ""
	}
	return msg.headers["location"]
}
