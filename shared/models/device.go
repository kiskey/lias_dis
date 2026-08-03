// Package models defines canonical data structures shared between the
// Discovery Intelligence Service (DIS) and the LAN Internet Access Scheduler (LIAS).
//
// File:    shared/models/device.go
// Version: 1.4 (Added strict DisplayName hierarchy helper)
package models

import (
	"net"
	"strings"
	"time"
)

const maxHistoricalMACs = 32

// Device is the canonical network device record exchanged between DIS and LIAS.
type Device struct {
	PDID         string                `json:"pdid"`
	MACs         []string              `json:"macs"`
	CurrentMAC   string                `json:"current_mac"`
	IPs          []string              `json:"ips"`
	CurrentIP    string                `json:"current_ip"`
	Hostname     string                `json:"hostname"`
	FriendlyName string                `json:"friendly_name"`
	Manufacturer string                `json:"manufacturer"`
	Vendor       string                `json:"vendor"`
	Model        string                `json:"model"`
	DeviceType   string                `json:"device_type"`
	Services     []string              `json:"services"`
	Online       bool                  `json:"online"`
	IsTentative  bool                  `json:"is_tentative,omitempty"` // Explicitly tracks if PDID was generated without a MAC
	FirstSeen    time.Time             `json:"first_seen"`
	LastSeen     time.Time             `json:"last_seen"`
	Confidence   float64               `json:"confidence"`
	Tags         []string              `json:"tags"`
	SourceInfo   map[string]SourceMeta `json:"source_info,omitempty"`
}

// SourceMeta records per-source provenance for an observed field on a Device.
type SourceMeta struct {
	Source     string                 `json:"source"`
	Confidence float64                `json:"confidence"`
	Timestamp  time.Time              `json:"timestamp"`
	Raw        map[string]interface{} `json:"raw,omitempty"`
}

// PDIDRecord aggregates all known identity observations for a Persistent Device Identity.
type PDIDRecord struct {
	ID         string       `json:"id"`
	PrimaryMAC string       `json:"primary_mac"`
	KnownMACs  []string     `json:"known_macs"`
	KnownIPs   []string     `json:"known_ips"`
	Hostnames  []string     `json:"hostnames"`
	MergeLog   []MergeEvent `json:"merge_log,omitempty"`
	Confidence float64      `json:"confidence"`
}

// MergeEvent records a single correlation merge decision in the PDID history.
type MergeEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Reason     string    `json:"reason"`
	FromMAC    string    `json:"from_mac"`
	ToPDID     string    `json:"to_pdid"`
	Confidence float64   `json:"confidence"`
}

// Enrichment represents the structured output of an Enricher invocation.
type Enrichment struct {
	Hostname     string                 `json:"hostname,omitempty"`
	FriendlyName string                 `json:"friendly_name,omitempty"`
	Manufacturer string                 `json:"manufacturer,omitempty"`
	Vendor       string                 `json:"vendor,omitempty"`
	Model        string                 `json:"model,omitempty"`
	DeviceType   string                 `json:"device_type,omitempty"`
	Services     []string               `json:"services,omitempty"`
	Confidence   float64                `json:"confidence"`
	Source       string                 `json:"source"`
	Raw          map[string]interface{} `json:"raw,omitempty"`
}

// DisplayName returns the canonical display name enforcing strict precedence:
// Hostname -> Friendly Name -> Vendor + Model -> Current MAC -> PDID.
func (d *Device) DisplayName() string {
	if d == nil {
		return "Unknown Device"
	}
	if h := strings.TrimSpace(d.Hostname); h != "" {
		return h
	}
	if f := strings.TrimSpace(d.FriendlyName); f != "" {
		return f
	}
	v := strings.TrimSpace(d.Vendor)
	m := strings.TrimSpace(d.Model)
	if v != "" && m != "" {
		return v + " " + m
	}
	if v != "" {
		return v
	}
	if m != "" {
		return m
	}
	if d.CurrentMAC != "" {
		return d.CurrentMAC
	}
	if d.PDID != "" {
		return d.PDID
	}
	return "Unknown Device"
}

// FormatMAC normalizes a HardwareAddr to colon-separated lowercase form.
func FormatMAC(mac net.HardwareAddr) string {
	if mac == nil {
		return ""
	}
	return strings.ToLower(mac.String())
}

// AddMAC appends a MAC address to the device's known list if not present, keeping CurrentMAC updated.
// Bounded to retain at most maxHistoricalMACs (32) to prevent unbounded memory growth on rotating MAC devices.
func (d *Device) AddMAC(mac string) {
	if d == nil || mac == "" {
		return
	}

	cleanMAC := strings.ToLower(strings.TrimSpace(mac))
	if hw, err := net.ParseMAC(cleanMAC); err == nil {
		cleanMAC = hw.String()
	}

	for _, existing := range d.MACs {
		if existing == cleanMAC {
			d.CurrentMAC = cleanMAC
			return
		}
	}

	d.MACs = append(d.MACs, cleanMAC)
	d.CurrentMAC = cleanMAC

	// Bound history to prevent unbounded growth
	if len(d.MACs) > maxHistoricalMACs {
		d.MACs = d.MACs[len(d.MACs)-maxHistoricalMACs:]
	}
}

// AddIP appends an IP address to the device's known list if not present, keeping CurrentIP updated.
func (d *Device) AddIP(ip string) {
	if d == nil || ip == "" {
		return
	}

	cleanIP := strings.TrimSpace(ip)
	if parsed := net.ParseIP(cleanIP); parsed != nil {
		cleanIP = parsed.String()
	}

	for _, existing := range d.IPs {
		if existing == cleanIP {
			d.CurrentIP = cleanIP
			return
		}
	}
	d.IPs = append(d.IPs, cleanIP)
	d.CurrentIP = cleanIP
}

// HasMAC checks whether a given MAC address exists in the device's MAC history.
func (d *Device) HasMAC(macStr string) bool {
	if d == nil || macStr == "" {
		return false
	}
	clean := strings.ToLower(strings.TrimSpace(macStr))
	for _, m := range d.MACs {
		if strings.ToLower(strings.TrimSpace(m)) == clean {
			return true
		}
	}
	return false
}

// AddService appends a service identifier, deduplicating against existing entries.
func (d *Device) AddService(svc string) {
	if d == nil || svc == "" {
		return
	}
	cleanSvc := strings.TrimSpace(svc)
	for _, existing := range d.Services {
		if existing == cleanSvc {
			return
		}
	}
	d.Services = append(d.Services, cleanSvc)
}

// Touch updates LastSeen timestamp and sets FirstSeen if uninitialized.
func (d *Device) Touch(ts time.Time) {
	if d == nil {
		return
	}
	d.LastSeen = ts
	if d.FirstSeen.IsZero() {
		d.FirstSeen = ts
	}
}

// HasTag reports whether the device currently carries the specified tag.
func (d *Device) HasTag(tag string) bool {
	if d == nil || tag == "" {
		return false
	}
	for _, t := range d.Tags {
		if t == tag {
			return true
		}
	}
	return false
}
