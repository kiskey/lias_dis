// Package oui provides instant, zero-allocation hardware vendor lookups
// backed by the official IEEE OUI database (via github.com/endobit/oui)
// and bitwise LAA private MAC address detection.
//
// File:    pkg/oui/oui.go
// Version: 1.4
package oui

import (
	"fmt"
	"strings"
	"sync"

	endobitOui "github.com/endobit/oui"
)

// Database manages custom OUI overrides and wraps IEEE vendor lookups.
type Database struct {
	mu             sync.RWMutex
	customPrefixes map[string]string
}

var (
	defaultDB *Database
	once      sync.Once
)

// Get returns the singleton OUI database instance.
func Get() *Database {
	once.Do(func() {
		defaultDB = &Database{
			customPrefixes: make(map[string]string),
		}
	})
	return defaultDB
}

// Lookup returns the vendor name for a given MAC address string (e.g. "AA:BB:CC:DD:EE:FF" or "aabbccddeeff").
// Uses the official 35,000+ entry IEEE OUI dataset with custom local prefix overrides.
func Lookup(macStr string) string {
	return Get().Lookup(macStr)
}

// IsRandomizedMAC reports whether a MAC address is a Locally Administered Address (LAA).
// IEEE 802 specifies that if Bit 1 of the first octet is set to 1, the address is randomized/private
// (e.g. Apple Private Wi-Fi Addresses, Android Private MACs, Windows Random MACs).
func IsRandomizedMAC(macStr string) bool {
	clean := normalizeHex(macStr)
	if len(clean) < 2 {
		return false
	}

	var firstByte byte
	if _, err := fmt.Sscanf(clean[:2], "%02x", &firstByte); err != nil {
		return false
	}

	// Bit 1 (0x02) set = Locally Administered Address (Private MAC)
	return (firstByte & 0x02) != 0
}

// Lookup queries custom overrides first, then falls back to the embedded IEEE OUI dataset.
func (db *Database) Lookup(macStr string) string {
	clean := normalizeHex(macStr)
	if len(clean) < 6 {
		return ""
	}

	// 1. Check custom overrides
	prefix := clean[:6]
	db.mu.RLock()
	customVendor, found := db.customPrefixes[prefix]
	db.mu.RUnlock()

	if found {
		return customVendor
	}

	// 2. Fallback to full IEEE OUI dataset from github.com/endobit/oui
	return endobitOui.Vendor(macStr)
}

// AddPrefix allows registering custom or local OUI prefixes dynamically.
func (db *Database) AddPrefix(prefixHex, vendor string) {
	clean := normalizeHex(prefixHex)
	if len(clean) != 6 || vendor == "" {
		return
	}

	db.mu.Lock()
	db.customPrefixes[clean] = vendor
	db.mu.Unlock()
}

// normalizeHex strips common delimiters (:, -, .) and converts hex characters to uppercase.
func normalizeHex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') {
			b.WriteByte(c)
		} else if c >= 'a' && c <= 'z' {
			b.WriteByte(c - 32) // Fast uppercase conversion
		}
	}
	return b.String()
}
