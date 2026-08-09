// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/nmap_enricher.go
// Version: 2.0 (Bounded Process, Output, Rate, Target, and Scan Profile)
package discovery

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/user/lias-dis/shared/models"
)

// ErrNmapNoResults is returned when nmap fails to identify OS, vendor, or services.
// This allows the orchestrator to distinguish between execution errors and negative results.
var ErrNmapNoResults = fmt.Errorf("nmap scan produced no identifiable results")

var ErrNmapOutputLimit = fmt.Errorf("nmap output exceeded configured limit")

type NmapOptions struct {
	HostTimeout       time.Duration
	ProcessTimeout    time.Duration
	MaxRate           int
	MaxOutputBytes    int64
	EnableOSDetection bool
}

// NmapEnricher uses the system `nmap` utility to perform on-demand
// OS and service detection with fast XML parsing.
type NmapEnricher struct {
	ctx    context.Context
	cancel context.CancelFunc
	sem    chan struct{}
	binary string
	opts   NmapOptions
}

// NewNmapEnricher initializes the Nmap enricher.
func NewNmapEnricher(options ...NmapOptions) *NmapEnricher {
	opts := NmapOptions{}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.HostTimeout <= 0 {
		opts.HostTimeout = 10 * time.Second
	}
	if opts.ProcessTimeout <= 0 {
		opts.ProcessTimeout = 15 * time.Second
	}
	if opts.MaxRate <= 0 {
		opts.MaxRate = 50
	}
	if opts.MaxRate > 1000 {
		opts.MaxRate = 1000
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = 1 << 20
	}
	if opts.MaxOutputBytes > 16<<20 {
		opts.MaxOutputBytes = 16 << 20
	}
	return &NmapEnricher{
		sem:  make(chan struct{}, 1),
		opts: opts,
	}
}

// Name returns the provider's identifier.
func (e *NmapEnricher) Name() string { return "nmap" }

// Start satisfies the Provider interface.
func (e *NmapEnricher) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nmap enricher requires a non-nil context")
	}
	binary, err := exec.LookPath("nmap")
	if err != nil {
		return fmt.Errorf("nmap executable not found: %w", err)
	}
	e.binary = binary
	e.ctx, e.cancel = context.WithCancel(ctx)
	return nil
}

// Stop satisfies the Provider interface.
func (e *NmapEnricher) Stop() error {
	if e.cancel != nil {
		e.cancel()
	}
	return nil
}

// Enrich executes a single optimized nmap scan against the device's current IP.
func (e *NmapEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
	if d == nil || d.CurrentIP == "" {
		return nil, fmt.Errorf("cannot enrich without IP")
	}

	ip := net.ParseIP(strings.TrimSpace(d.CurrentIP))
	if !isLANAddress(ip) {
		return nil, fmt.Errorf("refusing nmap scan of non-LAN IP %q", d.CurrentIP)
	}
	if e.binary == "" {
		return nil, errors.New("nmap enricher was not started")
	}

	enr, err := e.runNmap(ctx, ip.String())
	if err != nil {
		return nil, err
	}
	if enr != nil && (enr.Vendor != "" || enr.DeviceType != "" || enr.Hostname != "" || len(enr.Services) > 0) {
		return enr, nil
	}

	// P0-FIX: Return error instead of nil so orchestrator tracks failure for negative caching
	return nil, ErrNmapNoResults
}

func (e *NmapEnricher) runNmap(ctx context.Context, ip string) (*models.Enrichment, error) {
	// P2-FIX: Acquire concurrency semaphore to prevent CPU spikes from parallel scans
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, e.opts.ProcessTimeout)
	defer cancel()

	args := e.commandArgs(ip)
	cmd := exec.CommandContext(timeoutCtx, e.binary, args...)
	stdout := &limitedBuffer{limit: e.opts.MaxOutputBytes}
	stderr := &limitedBuffer{limit: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		if stdout.exceeded {
			return nil, ErrNmapOutputLimit
		}
		if timeoutCtx.Err() != nil {
			return nil, timeoutCtx.Err()
		}
		slog.Debug("Nmap execution failed", "ip", ip, "error", err, "stderr", boundedText(stderr.String(), 512))
		return nil, fmt.Errorf("nmap execution failed: %w", err)
	}
	if stdout.exceeded {
		return nil, ErrNmapOutputLimit
	}
	enr := parseNmapXML(stdout.Bytes())
	if enr != nil {
		enr.Raw["scan_profile"] = "tcp_connect_service_light"
		enr.Raw["max_rate_packets_per_second"] = e.opts.MaxRate
		enr.Raw["host_timeout"] = e.opts.HostTimeout.String()
		enr.Raw["os_detection_enabled"] = e.opts.EnableOSDetection
		enr.Raw["identity_evidence"] = false
	}
	return enr, nil
}

func (e *NmapEnricher) commandArgs(ip string) []string {
	args := []string{
		"-Pn", "-n", "-sT", "-sV", "--version-light",
		"--max-retries", "1",
		"--host-timeout", nmapDuration(e.opts.HostTimeout),
		"--max-rate", strconv.Itoa(e.opts.MaxRate),
		"-F", "-oX", "-",
	}
	if e.opts.EnableOSDetection {
		args = append(args, "-O", "--osscan-limit")
	}
	return append(args, ip)
}

func nmapDuration(value time.Duration) string {
	seconds := int64(value.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10) + "s"
}

type limitedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	limit    int64
	exceeded bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := w.limit - int64(w.buf.Len())
	if remaining <= 0 {
		w.exceeded = true
		return 0, ErrNmapOutputLimit
	}
	if int64(len(p)) > remaining {
		_, _ = w.buf.Write(p[:remaining])
		w.exceeded = true
		return int(remaining), ErrNmapOutputLimit
	}
	return w.buf.Write(p)
}

func (w *limitedBuffer) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf.Bytes())
}

func (w *limitedBuffer) String() string {
	return string(w.Bytes())
}

// nmapRun represents the relevant XML structures from Nmap.
type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus     `xml:"status"`
	Addresses []nmapAddress  `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	OS        nmapOS         `xml:"os"`
	Ports     []nmapPort     `xml:"ports>port"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapOS struct {
	OSMatches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

type nmapPort struct {
	PortID  string        `xml:"portid,attr"`
	State   nmapPortState `xml:"state"`
	Service nmapService   `xml:"service"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func parseNmapXML(data []byte) *models.Enrichment {
	if len(data) > 1<<20 {
		return nil
	}
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil
	}
	if len(run.Hosts) == 0 || run.Hosts[0].Status.State != "up" {
		return nil
	}

	host := run.Hosts[0]
	enr := &models.Enrichment{
		Source:     "nmap",
		Confidence: 0.8,
		Raw:        make(map[string]interface{}),
	}

	for _, addr := range host.Addresses {
		if addr.AddrType == "mac" && addr.Vendor != "" {
			enr.Vendor = addr.Vendor
		}
	}

	if len(host.Hostnames) > 0 {
		enr.Hostname = host.Hostnames[0].Name
	}

	var openPorts []string
	var serviceNames []string
	for _, p := range host.Ports {
		if p.State.State == "open" && p.Service.Name != "" {
			serviceNames = append(serviceNames, p.Service.Name)
			openPorts = append(openPorts, p.PortID)
		}
	}
	if len(serviceNames) > 0 {
		enr.Services = serviceNames
	}

	if len(host.OS.OSMatches) > 0 {
		osName := host.OS.OSMatches[0].Name
		enr.Model = osName
		enr.DeviceType = ClassifyDeviceFromOSAndPorts(osName, openPorts, serviceNames)
	} else if len(serviceNames) > 0 {
		enr.DeviceType = ClassifyDeviceFromOSAndPorts("", openPorts, serviceNames)
	}

	return enr
}

// ClassifyDeviceFromOSAndPorts performs rule-based classification across OS strings,
// open ports, and running service names to accurately categorize hardware.
func ClassifyDeviceFromOSAndPorts(osName string, ports []string, services []string) string {
	osLower := strings.ToLower(osName)
	svcJoined := strings.ToLower(strings.Join(services, " "))
	portsJoined := " " + strings.Join(ports, " ") + " "

	// 1. Mobile & Wearable Devices
	if strings.Contains(osLower, "ios") || strings.Contains(osLower, "iphone") || strings.Contains(osLower, "ipod") {
		return "phone"
	}
	if strings.Contains(osLower, "ipad") {
		return "tablet"
	}
	if strings.Contains(osLower, "android") {
		if strings.Contains(osLower, "tv") || strings.Contains(osLower, "shield") {
			return "tv"
		}
		if strings.Contains(osLower, "tablet") {
			return "tablet"
		}
		return "phone"
	}

	// 2. Gaming Consoles
	if strings.Contains(osLower, "playstation") || strings.Contains(osLower, "xbox") ||
		strings.Contains(osLower, "nintendo") || strings.Contains(svcJoined, "playstation") {
		return "console"
	}

	// 3. Smart TVs & Streaming Devices
	if strings.Contains(osLower, "webos") || strings.Contains(osLower, "tizen") ||
		strings.Contains(osLower, "bravia") || strings.Contains(osLower, "apple tv") ||
		strings.Contains(osLower, "roku") || strings.Contains(osLower, "chromecast") {
		return "tv"
	}

	// 4. Printers
	if strings.Contains(osLower, "printer") || strings.Contains(osLower, "jetdirect") ||
		strings.Contains(portsJoined, " 631 ") || strings.Contains(portsJoined, " 9100 ") ||
		strings.Contains(svcJoined, "ipp") || strings.Contains(svcJoined, "printer") {
		return "printer"
	}

	// 5. Network Infrastructure (Routers, Switches, Access Points)
	if strings.Contains(osLower, "routeros") || strings.Contains(osLower, "openwrt") ||
		strings.Contains(osLower, "cisco") || strings.Contains(osLower, "juniper") ||
		strings.Contains(osLower, "access point") || strings.Contains(osLower, "edgeos") ||
		strings.Contains(osLower, "pfsense") || strings.Contains(osLower, "opnsense") {
		return "infrastructure"
	}

	// 6. Desktop / Laptop Workstations
	if strings.Contains(osLower, "windows 10") || strings.Contains(osLower, "windows 11") ||
		strings.Contains(osLower, "windows 8") || strings.Contains(osLower, "windows 7") {
		return "pc"
	}
	if strings.Contains(osLower, "mac os x") || strings.Contains(osLower, "macos") {
		return "mac"
	}

	// 7. IoT & Smart Home Devices
	if strings.Contains(osLower, "espressif") || strings.Contains(osLower, "freertos") ||
		strings.Contains(osLower, "embedded") || strings.Contains(osLower, "tuya") ||
		strings.Contains(svcJoined, "mqtt") || strings.Contains(portsJoined, " 1883 ") {
		return "iot"
	}

	// 8. Servers & NAS
	if strings.Contains(osLower, "synology") || strings.Contains(osLower, "qnap") ||
		strings.Contains(svcJoined, "nfs") || strings.Contains(svcJoined, "iscsi") {
		return "server"
	}
	if strings.Contains(osLower, "linux") || strings.Contains(osLower, "bsd") {
		// Differentiate generic Linux OS from IoT or Server based on SSH/Web services
		if strings.Contains(portsJoined, " 22 ") || strings.Contains(portsJoined, " 443 ") {
			return "server"
		}
		return "iot" // Lightweight embedded Linux
	}

	return ""
}
