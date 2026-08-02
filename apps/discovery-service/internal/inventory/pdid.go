// Package inventory provides the in-memory device store and persistent identity helpers for DIS.
//
// File:    apps/discovery-service/internal/inventory/pdid.go
// Version: 1.1
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
)

// GeneratePDID creates a deterministic Persistent Device Identity (PDID).
//
// Primary Guarantee:
// Given a non-empty MAC address, the returned PDID will ALWAYS be identical
// across service restarts, cache purges, and network re-observations.
//
// Fallback Guarantee:
// If MAC is empty (e.g., initial DHCP observation before ARP resolution),
// a deterministic PDID is derived from normalized hostname and vendor attributes.
func GeneratePDID(mac string, hostname string, vendor string) string {
	cleanMAC := NormalizeMAC(mac)

	h := sha256.New()

	if cleanMAC != "" {
		// High-confidence primary MAC seed (Deterministic)
		h.Write([]byte("mac_v1:"))
		h.Write([]byte(cleanMAC))
	} else {
		// Tentative identity seed for MAC-less observations
		cleanHost := strings.ToLower(strings.TrimSpace(hostname))
		cleanVendor := strings.ToLower(strings.TrimSpace(vendor))

		h.Write([]byte("tentative_v1:"))
		h.Write([]byte(cleanHost))
		h.Write([]byte(":"))
		h.Write([]byte(cleanVendor))
	}

	return "pdid_" + hex.EncodeToString(h.Sum(nil))[:16]
}

// NormalizeMAC cleans and formats hardware addresses to colon-separated lowercase form (e.g. "aa:bb:cc:dd:ee:ff").
// Returns an empty string if the input is nil or invalid.
func NormalizeMAC(macStr string) string {
	if macStr == "" {
		return ""
	}

	hw, err := net.ParseMAC(macStr)
	if err != nil {
		// Attempt manual cleanup for non-standard delimiters or raw hex
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

	return hw.String() // Always returns lowercase colon-delimited format
}
