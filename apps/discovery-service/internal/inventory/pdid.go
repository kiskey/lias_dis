// Package inventory provides identity helpers for DIS.
//
// File:    apps/discovery-service/internal/inventory/pdid.go
// Version: 2.0
package inventory

import (
	"net"
	"strings"

	"github.com/user/lias-dis/shared/models"
)

// GeneratePDID generates a tiered PDID using current canonical identity logic.
func GeneratePDID(mac string, hostname string, vendor string) string {
	cleanMAC := NormalizeMAC(mac)
	cleanHost := strings.ToLower(strings.TrimSpace(hostname))

	if cleanMAC != "" {
		return "pdid_bia_" + cleanMAC[:6]
	}
	if cleanHost != "" {
		return "pdid_l7_" + cleanHost
	}
	return "pdid_tent_" + models.FormatMAC(net.HardwareAddr(mac))
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
