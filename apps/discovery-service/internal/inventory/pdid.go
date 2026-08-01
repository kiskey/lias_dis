// Package inventory provides the in-memory device store for DIS.
//
// File:    apps/discovery-service/internal/inventory/pdid.go
// Version: 1.0
package inventory

import (
    "crypto/sha256"
    "encoding/hex"
    "strconv"
    "time"
)

// GeneratePDID creates a Persistent Device Identity based on the initial
// observation of a device. It uses a combination of MAC, hostname, vendor,
// and a nanosecond timestamp to ensure uniqueness even for identical hardware
// profiles observed at different times.
// See §5.2 for generation rationale.
func GeneratePDID(mac string, hostname string, vendor string) string {
    h := sha256.New()
    h.Write([]byte(mac))
    h.Write([]byte(hostname))
    h.Write([]byte(vendor))
    h.Write([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
    return "pdid_" + hex.EncodeToString(h.Sum(nil))[:16]
}
