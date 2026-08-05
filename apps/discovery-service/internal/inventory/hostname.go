// Package inventory provides identity helpers for DIS.
//
// File:    apps/discovery-service/internal/inventory/hostname.go
// Version: 1.0
package inventory

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
