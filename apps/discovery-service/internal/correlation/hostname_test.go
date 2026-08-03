// Package correlation implements tests for DIS correlation logic.
//
// File:    apps/discovery-service/internal/correlation/hostname_test.go
// Version: 1.0
package correlation

import "testing"

func TestCanonicalizeHostname(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Bare hostname", "Pixel-6a", "pixel-6a"},
		{"Suffix .lan", "Pixel-6a.lan", "pixel-6a"},
		{"Suffix .local", "Pixel-6a.local", "pixel-6a"},
		{"Suffix .home.arpa", "Pixel-6a.home.arpa", "pixel-6a"},
		{"Double suffix .lan.local", "Pixel-6a.lan.local", "pixel-6a"},
		{"Trailing dot FQDN", "SRVNAKSHA.home.arpa.", "srvnaksha"},
		{"Consecutive dots", "SRV..NAKSHA..lan", "srv.naksha"},
		{"Whitespace padding", "  amazon-b3c93adb1.lan  ", "amazon-b3c93adb1"},
		{"Empty input", "", ""},
		{"Dots only", "...", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanonicalizeHostname(tt.input)
			if got != tt.expected {
				t.Errorf("CanonicalizeHostname(%q) = %q; want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestHostnamesAreEquivalent(t *testing.T) {
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"Pixel-6a", "Pixel-6a.lan", true},
		{"Pixel-6a.local", "pixel-6a.home.arpa", true},
		{"amazon-b3c93adb1", "amazon-b3c93adb1.lan", true},
		{"SRVNAKSHA", "Pixel-6a.lan", false},
		{"", "Pixel-6a.lan", false},
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := HostnamesAreEquivalent(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("HostnamesAreEquivalent(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}
