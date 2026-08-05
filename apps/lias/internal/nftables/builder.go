// Package nftables implements the isolated firewall controller for LIAS.
//
// File:    apps/lias/internal/nftables/builder.go
// Version: 2.2 (Fixed Infrastructure Immunity Bypass on Offline Status)
package nftables

import (
    "log/slog"
    "net"
    "sync"

    "github.com/user/lias-dis/apps/lias/internal/policy"
    liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
    "github.com/user/lias-dis/shared/models"
)

type Builder struct {
    mu         sync.Mutex
    cache      *liasSync.Cache
    controller *Controller

    currentAllowedIPs  map[string]net.IP
    currentBlockedIPs  map[string]net.IP
    currentAllowedMACs map[string]net.HardwareAddr
    currentBlockedMACs map[string]net.HardwareAddr
    currentAllowedIP6s map[string]net.IP
    currentBlockedIP6s map[string]net.IP
}

func NewBuilder(cache *liasSync.Cache, controller *Controller) *Builder {
    return &Builder{
        cache:      cache,
        controller: controller,
        
        currentAllowedIPs:  make(map[string]net.IP),
        currentBlockedIPs:  make(map[string]net.IP),
        currentAllowedMACs: make(map[string]net.HardwareAddr),
        currentBlockedMACs: make(map[string]net.HardwareAddr),
        currentAllowedIP6s: make(map[string]net.IP),
        currentBlockedIP6s: make(map[string]net.IP),
    }
}

// NET-03 Fix: Reset internal state when the kernel connection is lost/reinitialized.
func (b *Builder) ResetState() {
    b.mu.Lock()
    defer b.mu.Unlock()
    
    b.currentAllowedIPs = make(map[string]net.IP)
    b.currentBlockedIPs = make(map[string]net.IP)
    b.currentAllowedMACs = make(map[string]net.HardwareAddr)
    b.currentBlockedMACs = make(map[string]net.HardwareAddr)
    b.currentAllowedIP6s = make(map[string]net.IP)
    b.currentBlockedIP6s = make(map[string]net.IP)
    
    slog.Info("Builder state reset. Next sync will be a full repopulation.")
}

func (b *Builder) Sync(policyEngine policy.PolicyEvaluator, schedEngine policy.ScheduleEvaluator) error {
    b.mu.Lock()
    defer b.mu.Unlock()

    devs := b.cache.List()

    desiredAllowedIPs := make(map[string]net.IP)
    desiredBlockedIPs := make(map[string]net.IP)
    desiredAllowedMACs := make(map[string]net.HardwareAddr)
    desiredBlockedMACs := make(map[string]net.HardwareAddr)
    desiredAllowedIP6s := make(map[string]net.IP)
    desiredBlockedIP6s := make(map[string]net.IP)

    for i := range devs {
        d := &devs[i]
        action := policyEngine.EvaluateAction(d, schedEngine)

        // V2.2 FIX: Infrastructure devices must ALWAYS be in the allowed sets, 
        // even if offline, to prevent network lockouts.
        isInfra := d.HasTag("infrastructure")
        if isInfra {
            action = models.ActionAllow
        }

        switch action {
        case models.ActionAllow:
            // Skip offline devices ONLY if they are not infrastructure
            if !d.Online && !isInfra {
                continue
            }
            for _, ipStr := range d.IPs {
                if ip := net.ParseIP(ipStr); ip != nil {
                    if ip4 := ip.To4(); ip4 != nil {
                        desiredAllowedIPs[ip4.String()] = ip4
                    } else if ip6 := ip.To16(); ip6 != nil {
                        desiredAllowedIP6s[ip6.String()] = ip6
                    }
                }
            }
            for _, macStr := range d.MACs {
                if mac, err := net.ParseMAC(macStr); err == nil && len(mac) == 6 {
                    desiredAllowedMACs[mac.String()] = mac
                }
            }

        case models.ActionBlock:
            for _, ipStr := range d.IPs {
                if ip := net.ParseIP(ipStr); ip != nil {
                    if ip4 := ip.To4(); ip4 != nil {
                        desiredBlockedIPs[ip4.String()] = ip4
                    } else if ip6 := ip.To16(); ip6 != nil {
                        desiredBlockedIP6s[ip6.String()] = ip6
                    }
                }
            }
            for _, macStr := range d.MACs {
                if mac, err := net.ParseMAC(macStr); err == nil && len(mac) == 6 {
                    desiredBlockedMACs[mac.String()] = mac
                }
            }
        }
    }

    diff := SetDiff{
        AllowedIPsToAdd:   make([]net.IP, 0),
        AllowedIPsToRem:   make([]net.IP, 0),
        BlockedIPsToAdd:   make([]net.IP, 0),
        BlockedIPsToRem:   make([]net.IP, 0),
        AllowedMACsToAdd:  make([]net.HardwareAddr, 0),
        AllowedMACsToRem:  make([]net.HardwareAddr, 0),
        BlockedMACsToAdd:  make([]net.HardwareAddr, 0),
        BlockedMACsToRem:  make([]net.HardwareAddr, 0),
        AllowedIP6sToAdd:  make([]net.IP, 0),
        AllowedIP6sToRem:  make([]net.IP, 0),
        BlockedIP6sToAdd:  make([]net.IP, 0),
        BlockedIP6sToRem:  make([]net.IP, 0),
    }

    diffIPs(desiredAllowedIPs, b.currentAllowedIPs, &diff.AllowedIPsToAdd, &diff.AllowedIPsToRem)
    diffIPs(desiredBlockedIPs, b.currentBlockedIPs, &diff.BlockedIPsToAdd, &diff.BlockedIPsToRem)
    diffMACs(desiredAllowedMACs, b.currentAllowedMACs, &diff.AllowedMACsToAdd, &diff.AllowedMACsToRem)
    diffMACs(desiredBlockedMACs, b.currentBlockedMACs, &diff.BlockedMACsToAdd, &diff.BlockedMACsToRem)
    diffIPs(desiredAllowedIP6s, b.currentAllowedIP6s, &diff.AllowedIP6sToAdd, &diff.AllowedIP6sToRem)
    diffIPs(desiredBlockedIP6s, b.currentBlockedIP6s, &diff.BlockedIP6sToAdd, &diff.BlockedIP6sToRem)

    if len(diff.AllowedIPsToAdd) == 0 && len(diff.AllowedIPsToRem) == 0 &&
        len(diff.BlockedIPsToAdd) == 0 && len(diff.BlockedIPsToRem) == 0 &&
        len(diff.AllowedMACsToAdd) == 0 && len(diff.AllowedMACsToRem) == 0 &&
        len(diff.BlockedMACsToAdd) == 0 && len(diff.BlockedMACsToRem) == 0 &&
        len(diff.AllowedIP6sToAdd) == 0 && len(diff.AllowedIP6sToRem) == 0 &&
        len(diff.BlockedIP6sToAdd) == 0 && len(diff.BlockedIP6sToRem) == 0 {
        return nil
    }

    err := b.controller.Apply(diff)

    if err == nil {
        b.currentAllowedIPs = desiredAllowedIPs
        b.currentBlockedIPs = desiredBlockedIPs
        b.currentAllowedMACs = desiredAllowedMACs
        b.currentBlockedMACs = desiredBlockedMACs
        b.currentAllowedIP6s = desiredAllowedIP6s
        b.currentBlockedIP6s = desiredBlockedIP6s
    } else {
        b.currentAllowedIPs = make(map[string]net.IP)
        b.currentBlockedIPs = make(map[string]net.IP)
        b.currentAllowedMACs = make(map[string]net.HardwareAddr)
        b.currentBlockedMACs = make(map[string]net.HardwareAddr)
        b.currentAllowedIP6s = make(map[string]net.IP)
        b.currentBlockedIP6s = make(map[string]net.IP)
        slog.Info("Builder state reset due to Apply failure. Next sync will be a full repopulation.")
    }

    return err
}

func diffIPs(desired, current map[string]net.IP, toAdd, toRem *[]net.IP) {
    for k, v := range desired {
        if _, exists := current[k]; !exists {
            *toAdd = append(*toAdd, v)
        }
    }
    for k, v := range current {
        if _, exists := desired[k]; !exists {
            *toRem = append(*toRem, v)
        }
    }
}

func diffMACs(desired, current map[string]net.HardwareAddr, toAdd, toRem *[]net.HardwareAddr) {
    for k, v := range desired {
        if _, exists := current[k]; !exists {
            *toAdd = append(*toAdd, v)
        }
    }
    for k, v := range current {
        if _, exists := desired[k]; !exists {
            *toRem = append(*toRem, v)
        }
    }
}
