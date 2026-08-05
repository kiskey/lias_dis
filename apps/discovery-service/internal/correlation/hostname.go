// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/hostname.go
// Version: 1.1
package correlation

import (
    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
)

// CanonicalizeHostname delegates to inventory.CanonicalizeHostname to unify hostname logic.
func CanonicalizeHostname(raw string) string {
    return inventory.CanonicalizeHostname(raw)
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
