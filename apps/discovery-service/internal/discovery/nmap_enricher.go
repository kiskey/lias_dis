// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/nmap_enricher.go
// Version: 1.1
package discovery

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/user/lias-dis/shared/models"
)

// NmapEnricher uses the system `nmap` utility to perform on-demand
// OS and service detection with fast XML parsing.
type NmapEnricher struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewNmapEnricher initializes the Nmap enricher.
func NewNmapEnricher() *NmapEnricher {
	return &NmapEnricher{}
}

// Name returns the provider's identifier.
func (e *NmapEnricher) Name() string { return "nmap" }

// Start satisfies the Provider interface.
func (e *NmapEnricher) Start(ctx context.Context) error {
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

// Enrich executes nmap against the device's current IP and parses XML output.
func (e *NmapEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
	if d == nil || d.CurrentIP == "" {
		return nil, fmt.Errorf("cannot enrich without IP")
	}

	// 1. Fast reachability & port scan (-sn -PR -PE)
	enr := e.runNmap(ctx, d.CurrentIP, false)
	if enr != nil && (enr.Vendor != "" || enr.DeviceType != "") {
		return enr, nil
	}

	// 2. Fallback OS & Service scan (-O -sV --version-light)
	return e.runNmap(ctx, d.CurrentIP, true), nil
}

func (e *NmapEnricher) runNmap(ctx context.Context, ip string, intense bool) *models.Enrichment {
	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	args := []string{"-sn", "-PR", "-PE", "-oX", "-", ip}
	if intense {
		args = []string{"-O", "-sV", "--version-light", "--max-retries", "1", "-oX", "-", ip}
	}

	cmd := exec.CommandContext(timeoutCtx, "nmap", args...)
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			slog.Debug("Nmap scan timed out", "ip", ip)
		} else {
			slog.Debug("Nmap execution skipped or unprivileged", "ip", ip, "intense", intense)
		}
		return nil
	}

	return parseNmapXML(output)
}

// nmapRun represents the relevant XML structures from Nmap.
type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	OS        nmapOS        `xml:"os"`
	Ports     []nmapPort    `xml:"ports>port"`
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
	PortID  string      `xml:"portid,attr"`
	Service nmapService `xml:"service"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func parseNmapXML(data []byte) *models.Enrichment {
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
		if p.Service.Name != "" {
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
	if strings.Contains(osLower, "mac os x") || strings.Contains(osLower, "macOS") {
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
