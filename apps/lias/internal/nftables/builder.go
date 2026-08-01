// Package nftables implements the isolated firewall controller for LIAS.
//
// File:    apps/lias/internal/nftables/builder.go
// Version: 1.2
package nftables

import (
    "net"
    "sync"

    "github.com/user/lias-dis/apps/lias/internal/policy"
    liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
    "github.com/user/lias-dis/shared/models"
)

// Builder evaluates the LIAS cache and computes the desired nftables state.
type Builder struct {
    mu         sync.Mutex
    cache      *liasSync.Cache
    controller *Controller
}

// NewBuilder initializes the builder.
func NewBuilder(cache *liasSync.Cache, controller *Controller) *Builder {
    return &Builder{
        cache:      cache,
        controller: controller,
    }
}

// Sync evaluates all devices in the cache and applies the resulting
// allow/block sets to nftables.
func (b *Builder) Sync(policyEngine policy.PolicyEvaluator, schedEngine policy.ScheduleEvaluator) error {
    b.mu.Lock()
    defer b.mu.Unlock()

    devs := b.cache.List()
    var allowedIPs, blockedIPs []net.IP
    var allowedMACs, blockedMACs []net.HardwareAddr

    for _, d := range devs {
        if !d.Online {
            continue // Only apply rules to online devices
        }

        localDev := d 
        action := policyEngine.EvaluateAction(&localDev, schedEngine)

        switch action {
        case models.ActionAllow:
            if d.CurrentIP != "" {
                if ip := net.ParseIP(d.CurrentIP); ip != nil {
                    allowedIPs = append(allowedIPs, ip.To4())
                }
            }
            if d.CurrentMAC != "" {
                if mac, err := net.ParseMAC(d.CurrentMAC); err == nil {
                    allowedMACs = append(allowedMACs, mac)
                }
            }
        case models.ActionBlock:
            if d.CurrentIP != "" {
                if ip := net.ParseIP(d.CurrentIP); ip != nil {
                    blockedIPs = append(blockedIPs, ip.To4())
                }
            }
            if d.CurrentMAC != "" {
                if mac, err := net.ParseMAC(d.CurrentMAC); err == nil {
                    blockedMACs = append(blockedMACs, mac)
                }
            }
        }
    }

    return b.controller.Apply(
        SetElements{IPs: allowedIPs, MACs: allowedMACs},
        SetElements{IPs: blockedIPs, MACs: blockedMACs},
    )
}
