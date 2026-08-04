// Package models defines canonical data structures shared between DIS and LIAS.
//
// File:    shared/models/device.go
// Version: 2.1
package models

import (
    "net"
    "strings"
    "time"
)

const maxHistoricalMACs = 32

// IdentityTier enumerates the immutability tier of a Device identity.
type IdentityTier string

const (
    TierTentative IdentityTier = "tentative"
    TierL7        IdentityTier = "l7"
    TierBIA       IdentityTier = "bia"
)

// Device is the canonical network device record exchanged between DIS and LIAS.
type Device struct {
    PDID              string                `json:"pdid"`
    IdentityTier      IdentityTier          `json:"identity_tier"`
    IdentityAnchor    string                `json:"identity_anchor"`
    CanonicalHostname string                `json:"canonical_hostname,omitempty"`
    CurrentMAC        string                `json:"current_mac"`
    MACs              []string              `json:"macs"`
    CurrentIP         string                `json:"current_ip"`
    IPs               []string              `json:"ips"`
    Hostname          string                `json:"hostname"`
    FriendlyName      string                `json:"friendly_name"`
    Manufacturer      string                `json:"manufacturer"`
    Vendor            string                `json:"vendor"`
    Model             string                `json:"model"`
    DeviceType        string                `json:"device_type"`
    Services          []string              `json:"services"`
    Online            bool                  `json:"online"`
    PendingOnlineObs  []string              `json:"pending_online_obs,omitempty"`
    IsTentative       bool                  `json:"is_tentative,omitempty"`
    FirstSeen         time.Time             `json:"first_seen"`
    LastSeen          time.Time             `json:"last_seen"`
    Confidence        float64               `json:"confidence"`
    Tags              []string              `json:"tags"`
    UserID            string                `json:"user_id,omitempty"` // SYS-FEAT-03 Fix: Per-user mapping
    SourceInfo        map[string]SourceMeta `json:"source_info,omitempty"`
}

// SourceMeta records per-source provenance for an observed field on a Device.
type SourceMeta struct {
    Source     string                 `json:"source"`
    Confidence float64                `json:"confidence"`
    Timestamp  time.Time              `json:"timestamp"`
    Raw        map[string]interface{} `json:"raw,omitempty"`
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

// User represents a human user profile for aggregate policy enforcement (SYS-FEAT-03)
type User struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}

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

    if len(d.MACs) > maxHistoricalMACs {
        d.MACs = d.MACs[len(d.MACs)-maxHistoricalMACs:]
    }
}

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

func (d *Device) Touch(ts time.Time) {
    if d == nil {
        return
    }
    d.LastSeen = ts
    if d.FirstSeen.IsZero() {
        d.FirstSeen = ts
    }
}

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
