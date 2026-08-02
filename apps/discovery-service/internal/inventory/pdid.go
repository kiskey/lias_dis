// Package inventory provides the in-memory device store and persistent identity helpers for DIS.
//
// File:    apps/discovery-service/internal/inventory/pdid.go
// Version: 1.3
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"

	"github.com/user/lias-dis/pkg/oui"
)

// GeneratePDID creates a deterministic Persistent Device Identity (PDID).
func GeneratePDID(mac string, hostname string, vendor string) string {
	cleanMAC := NormalizeMAC(mac)
	cleanHost := strings.ToLower(strings.TrimSpace(hostname))
	cleanVendor := strings.ToLower(strings.TrimSpace(vendor))

	h := sha256.New()

	// 1. Apple / Android Private MAC (LAA) Anchor
	if cleanMAC != "" && oui.IsRandomizedMAC(cleanMAC) && cleanHost != "" {
		h.Write([]byte("laa_v1:"))
		h.Write([]byte(cleanHost))
		h.Write([]byte(":"))
		h.Write([]byte(cleanVendor))
		return "pdid_" + hex.EncodeToString(h.Sum(nil))[:16]
	}

	// 2. Static Hardware MAC (BIA) Anchor
	if cleanMAC != "" {
		h.Write([]byte("mac_v1:"))
		h.Write([]byte(cleanMAC))
		return "pdid_" + hex.EncodeToString(h.Sum(nil))[:16]
	}

	// 3. Tentative identity seed for MAC-less observations
	h.Write([]byte("tentative_v1:"))
	h.Write([]byte(cleanHost))
	h.Write([]byte(":"))
	h.Write([]byte(cleanVendor))

	return "pdid_" + hex.EncodeToString(h.Sum(nil))[:16]
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
