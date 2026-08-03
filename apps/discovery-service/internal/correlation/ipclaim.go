// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/ipclaim.go
// Version: 1.0
package correlation

import (
	"strings"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	"github.com/user/lias-dis/pkg/oui"
	"github.com/user/lias-dis/shared/models"
)

// IPClaimResult represents the outcome of validating a new MAC observation against an existing IP binding.
type IPClaimResult int

const (
	// ClaimAttach attaches the new MAC to the existing device record (MAC rotation).
	ClaimAttach IPClaimResult = iota
	// ClaimCreateNew treats the observation as a DHCP reassignment and creates a new device.
	ClaimCreateNew
)

// ValidateIPClaim determines whether an incoming observation with MAC M_new at IP I
// belongs to an existing device record P_existing (which has not yet recorded M_new).
func ValidateIPClaim(obs discovery.Observation, existing *models.Device) IPClaimResult {
	if existing == nil || obs.MAC == nil {
		return ClaimCreateNew
	}

	macStr := obs.MAC.String()

	// CASE 1: M_new is a BIA (Burned-In Address / non-randomized OUI)
	// Physical hardware addresses do not rotate. A new BIA on an existing IP represents DHCP reassignment.
	if !oui.IsRandomizedMAC(macStr) {
		return ClaimCreateNew
	}

	// CASE 2: M_new is a Randomized / Private MAC (LAA bit set)

	// Vendor Mismatch Guard:
	// If both MACs resolve to known, differing OUI vendors, they cannot belong to the same physical NIC.
	obsVendor := oui.Lookup(macStr)
	existingVendor := oui.Lookup(existing.CurrentMAC)
	if obsVendor != "" && existingVendor != "" && !strings.EqualFold(obsVendor, existingVendor) {
		return ClaimCreateNew
	}

	// L7 Confirmation check:
	hasL7Confirmation := false

	// 1. Hostname match (canonical equivalence)
	if obs.Hostname != "" && existing.Hostname != "" {
		if HostnamesAreEquivalent(obs.Hostname, existing.Hostname) {
			hasL7Confirmation = true
		}
	}

	// 2. Service signature match (when existing device has no hostname)
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

	// Sub-case 2a: L7 confirmation matches AND existing device was active recently (< 60s ago)
	if hasL7Confirmation && time.Since(existing.LastSeen) < 60*time.Second {
		return ClaimAttach
	}

	// Sub-case 2b, 2c, 2d:
	// - L7 confirmation matches but device is stale (>= 60s) -> Ambiguous (recycled IP)
	// - L7 confirmation fails -> Different device (DHCP reassignment)
	// - No hostnames present on either observation -> Conservative default: Create New Device
	return ClaimCreateNew
}
