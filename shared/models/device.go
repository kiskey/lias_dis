// Package models defines canonical data structures shared between the
// Discovery Intelligence Service (DIS) and the LAN Internet Access Scheduler
// (LIAS). Keeping these in a shared module prevents wire-format drift between
// the two binaries that communicate solely via REST + SSE.
//
// File:    shared/models/device.go
// Version: 1.0
package models

import (
    "net"
    "time"
)

// Device is the canonical network device record exchanged between DIS and LIAS.
// All byte-oriented fields (HardwareAddr, IP) are normalized to strings so the
// struct is safe to serialize across SSE boundaries and into JSON stores.
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

// PDIDRecord aggregates all known identity observations for a Persistent
// Device Identity. Used by DIS to survive MAC randomization across reboots
// and to provide an auditable merge history to the LIAS dashboard.
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
// Empty fields are omitted from the wire format so partial enrichments do not
// overwrite higher-confidence data already stored on the Device.
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

// FormatMAC normalizes a HardwareAddr to colon-separated lowercase form and
// returns an empty string when the input is nil. This keeps consumers free of
// nil-check boilerplate when persisting netlink observations.
func FormatMAC(mac net.HardwareAddr) string {
    if mac == nil {
        return ""
    }
    return mac.String()
}

// AddMAC appends a MAC to the device's known MAC list if not already present
// and updates CurrentMAC to the supplied value. Safe to call on a nil receiver.
func (d *Device) AddMAC(mac string) {
    if d == nil || mac == "" {
        return
    }
    for _, existing := range d.MACs {
        if existing == mac {
            d.CurrentMAC = mac
            return
        }
    }
    d.MACs = append(d.MACs, mac)
    d.CurrentMAC = mac
}

// AddIP appends an IP to the device's known IP list if not already present
// and updates CurrentIP to the supplied value. Safe to call on a nil receiver.
func (d *Device) AddIP(ip string) {
    if d == nil || ip == "" {
        return
    }
    for _, existing := range d.IPs {
        if existing == ip {
            d.CurrentIP = ip
            return
        }
    }
    d.IPs = append(d.IPs, ip)
    d.CurrentIP = ip
}

// AddService appends a service identifier (e.g. "_airplay._tcp") to the
// device's service list, deduplicating against existing entries.
func (d *Device) AddService(svc string) {
    if d == nil || svc == "" {
        return
    }
    for _, existing := range d.Services {
        if existing == svc {
            return
        }
    }
    d.Services = append(d.Services, svc)
}

// Touch updates LastSeen to the supplied timestamp and, when FirstSeen is
// zero, sets FirstSeen to the same value. The caller is responsible for
// setting Online appropriately.
func (d *Device) Touch(ts time.Time) {
    if d == nil {
        return
    }
    d.LastSeen = ts
    if d.FirstSeen.IsZero() {
        d.FirstSeen = ts
    }
}

// HasTag reports whether the device currently carries the supplied tag.
// Used by LIAS policy evaluation to short-circuit infrastructure lookups.
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
