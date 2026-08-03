// Package inventory provides identity helpers for DIS.
//
// File:    apps/discovery-service/internal/inventory/pdid.go
// Version: 2.1
package inventory

import (
	"net"
	"strings"

	"github.com/user/lias-dis/apps/discovery-service/internal/correlation"
	"github.com/user/lias-dis/shared/models"
)

// GeneratePDID generates a tiered PDID delegating to canonical tiered identity logic in correlation.
func GeneratePDID(mac string, hostname string, vendor string) string {
	tier, anchor := correlation.DeriveTierAndAnchor(mac, hostname, vendor)
	return correlation.GeneratePDID(tier, anchor)
}

// GenerateTieredPDID produces a tiered PDID directly using tier and anchor.
func GenerateTieredPDID(tier models.IdentityTier, anchor string) string {
	return correlation.GeneratePDID(tier, anchor)
}

// NormalizeMAC cleans and formats hardware addresses to colon-separated lowercase form.
func NormalizeMAC(macStr string) string {
	if macStr == "" {
		return ""
	}

	hw, err := net.ParseMAC(macStr)
	if err != nil {
		clean := strings.ReplaceAll(macStr, "-", "")
		clean = strings.ReplaceAll(clean, ".", "")
		clean = strings.ReplaceAll(clean, ":", "")
		if len(clean) == 12 {
			hw, err = net.ParseMAC(
				clean[0:2] + ":" + clean[2:4] + ":" + clean[4:6] + ":" +
					clean[6:8] + ":" + clean[8:10] + ":" + clean[10:12],
			)
		}
	}

	if err != nil || len(hw) == 0 {
		return ""
	}

	return hw.String()
}
