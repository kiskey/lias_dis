// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/hostname.go
// Version: 1.0
package correlation

import "strings"

// canonicalSuffixes are stripped from the right end of hostnames in priority order.
var canonicalSuffixes = []string{
	".home.arpa",
	".localdomain",
	".internal",
	".local",
	".lan",
	".home",
	".corp",
	".priv",
	".intranet",
}

// CanonicalizeHostname normalizes a raw hostname string for identity, ownership,
// and event-emission comparison purposes.
//
// Rules:
//  1. Trim leading/trailing whitespace.
//  2. Lowercase.
//  3. Strip trailing dot (FQDN terminator).
//  4. Repeatedly strip canonical suffixes until none match.
//  5. Collapse consecutive dots.
func CanonicalizeHostname(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return ""
	}

	changed := true
	for changed {
		changed = false
		for _, suf := range canonicalSuffixes {
			if strings.HasSuffix(h, suf) {
				h = strings.TrimSuffix(h, suf)
				changed = true
				break
			}
		}
	}

	// Collapse consecutive dots
	for strings.Contains(h, "..") {
		h = strings.ReplaceAll(h, "..", ".")
	}

	return strings.Trim(h, ".")
}

// HostnamesAreEquivalent reports whether two raw hostname strings canonicalize
// to the identical base hostname.
func HostnamesAreEquivalent(a, b string) bool {
	ca := CanonicalizeHostname(a)
	cb := CanonicalizeHostname(b)
	if ca == "" || cb == "" {
		return false
	}
	return ca == cb
}
