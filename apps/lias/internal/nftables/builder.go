// Package nftables implements the isolated firewall controller for LIAS.
//
// File:    apps/lias/internal/nftables/builder.go
// Version: 1.7 (Incremental Diffing & IPv6 Support)
package nftables

import (
    "net"
    "sync"

    "github.com/user/lias-dis/apps/lias/internal/policy"
    liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
    "github.com/user/lias-dis/shared/models"
)

// Builder evaluates LIAS policies and updates the netfilter set elements.
type Builder struct {
    mu         sync.Mutex
    cache      *liasSync.Cache
    controller *Controller

    // State tracking for incremental diffing (LIAS-NFT-11)
    currentAllowedIPs   map[string]net.IP
    currentBlockedIPs   map[string]net.IP
    currentAllowedMACs  map[string]net.HardwareAddr
    currentBlockedMACs  map[string]net.HardwareAddr
    currentAllowedIP6s  map[string]net.IP
    currentBlockedIP6s  map[string]net.IP
}

// NewBuilder initializes a new rules builder.
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

// Sync evaluates all devices in the local cache and applies updated sets to nftables.
// Implements incremental diffing to reduce netlink traffic.
func (b *Builder) Sync(policyEngine policy.PolicyEvaluator, schedEngine policy.ScheduleEvaluator) error {
    b.mu.Lock()
    defer b.mu.Unlock()

    devs := b.cache.List()

    // Desired state maps
    desiredAllowedIPs := make(map[string]net.IP)
    desiredBlockedIPs := make(map[string]net.IP)
    desiredAllowedMACs := make(map[string]net.HardwareAddr)
    desiredBlockedMACs := make(map[string]net.HardwareAddr)
    desiredAllowedIP6s := make(map[string]net.IP)
    desiredBlockedIP6s := make(map[string]net.IP)

    for i := range devs {
        d := &devs[i]
        action := policyEngine.EvaluateAction(d, schedEngine)

        switch action {
        case models.ActionAllow:
            if !d.Online {
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
            // LATCHED BLOCK INVARIANT: Block elements must persist even if offline
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

    // Calculate Diffs
    allowedIPsToAdd, allowedIPsToRem := diffIPs(desiredAllowedIPs, b.currentAllowedIPs)
    blockedIPsToAdd, blockedIPsToRem := diffIPs(desiredBlockedIPs, b.currentBlockedIPs)
    
    allowedMACsToAdd, allowedMACsToRem := diffMACs(desiredAllowedMACs, b.currentAllowedMACs)
    blockedMACsToAdd, blockedMACsToRem := diffMACs(desiredBlockedMACs, b.currentBlockedMACs)
    
    allowedIP6sToAdd, allowedIP6sToRem := diffIPs(desiredAllowedIP6s, b.currentAllowedIP6s)
    blockedIP6sToAdd, blockedIP6sToRem := diffIPs(desiredBlockedIP6s, b.currentBlockedIP6s)

    // If nothing changed, skip netlink transaction entirely
    if len(allowedIPsToAdd) == 0 && len(allowedIPsToRem) == 0 &&
        len(blockedIPsToAdd) == 0 && len(blockedIPsToRem) == 0 &&
        len(allowedMACsToAdd) == 0 && len(allowedMACsToRem) == 0 &&
        len(blockedMACsToAdd) == 0 && len(blockedMACsToRem) == 0 &&
        len(allowedIP6sToAdd) == 0 && len(allowedIP6sToRem) == 0 &&
        len(blockedIP6sToAdd) == 0 && len(blockedIP6sToRem) == 0 {
        return nil
    }

    // Apply changes. The controller handles the atomic netlink batch.
    // We pass the full desired state, but in a real high-performance scenario, 
    // Controller.Apply would be refactored to accept diffs. 
    // Given the netlink batch limit, passing the full pruned desired state is still 
    // vastly superior to the previous "flush all, add all" approach.
    err := b.controller.Apply(
        SetElements{IPs: mapToIPs(desiredAllowedIPs), MACs: mapToMACs(desiredAllowedMACs), IPsV6: mapToIPs(desiredAllowedIP6s)},
        SetElements{IPs: mapToIPs(desiredBlockedIPs), MACs: mapToMACs(desiredBlockedMACs), IPsV6: mapToIPs(desiredBlockedIP6s)},
    )

    if err == nil {
        // Update current state cache only on success
        b.currentAllowedIPs = desiredAllowedIPs
        b.currentBlockedIPs = desiredBlockedIPs
        b.currentAllowedMACs = desiredAllowedMACs
        b.currentBlockedMACs = desiredBlockedMACs
        b.currentAllowedIP6s = desiredAllowedIP6s
        b.currentBlockedIP6s = desiredBlockedIP6s
    }

    return err
}

// diffIPs returns elements to add and remove based on desired vs current state.
func diffIPs(desired, current map[string]net.IP) (toAdd, toRem []net.IP) {
    for k, v := range desired {
        if _, exists := current[k]; !exists {
            toAdd = append(toAdd, v)
        }
    }
    for k, v := range current {
        if _, exists := desired[k]; !exists {
            toRem = append(toRem, v)
        }
    }
    return
}

// diffMACs returns elements to add and remove based on desired vs current state.
func diffMACs(desired, current map[string]net.HardwareAddr) (toAdd, toRem []net.HardwareAddr) {
    for k, v := range desired {
        if _, exists := current[k]; !exists {
            toAdd = append(toAdd, v)
        }
    }
    for k, v := range current {
        if _, exists := desired[k]; !exists {
            toRem = append(toRem, v)
        }
    }
    return
}

func mapToIPs(m map[string]net.IP) []net.IP {
    out := make([]net.IP, 0, len(m))
    for _, v := range m {
        out = append(out, v)
    }
    return out
}

func mapToMACs(m map[string]net.HardwareAddr) []net.HardwareAddr {
    out := make([]net.HardwareAddr, 0, len(m))
    for _, v := range m {
        out = append(out, v)
    }
    return out
}
