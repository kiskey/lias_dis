// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/ipclaim.go
// Version: 1.3 (Removed Unused Import)
package correlation

import (
    "strings"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/discovery"
    "github.com/user/lias-dis/pkg/oui"
    "github.com/user/lias-dis/shared/models"
)

type IPClaimResult int

const (
    ClaimAttach IPClaimResult = iota
    ClaimCreateNew
    ClaimCreateNewSilent
)

func ValidateIPClaim(obs discovery.Observation, existing *models.Device) IPClaimResult {
    if existing == nil || obs.MAC == nil {
        return ClaimCreateNewSilent
    }

    if !existing.Online && time.Since(existing.LastSeen) > 5*time.Minute {
        return ClaimCreateNewSilent
    }

    macStr := obs.MAC.String()

    if !oui.IsRandomizedMAC(macStr) {
        return ClaimCreateNew
    }

    obsVendor := oui.Lookup(macStr)
    existingVendor := oui.Lookup(existing.CurrentMAC)
    if obsVendor != "" && existingVendor != "" && !strings.EqualFold(obsVendor, existingVendor) {
        return ClaimCreateNew
    }

    hasL7Confirmation := false

    if obs.Hostname != "" && existing.Hostname != "" {
        if HostnamesAreEquivalent(obs.Hostname, existing.Hostname) {
            hasL7Confirmation = true
        }
    }

    if !hasL7Confirmation && existing.Hostname == "" && len(obs.Services) > 0 && len(existing.Services) > 0 {
        for _, s1 := range obs.Services {
            for _, s2 := range existing.Services {
                if strings.EqualFold(s1, s2) {
                    hasL7Confirmation = true
                    break
                }
            }
            if hasL7Confirmation {
                break
            }
        }
    }

    if hasL7Confirmation && time.Since(existing.LastSeen) < 60*time.Second {
        return ClaimAttach
    }

    return ClaimCreateNew
}
