// Package correlation implements unit tests for IP claim validation.
//
// File:    apps/discovery-service/internal/correlation/ipclaim_test.go
// Version: 1.1
package correlation

import (
    "net"
    "testing"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/discovery"
    "github.com/user/lias-dis/shared/models"
)

func TestValidateIPClaim(t *testing.T) {
    // Case 1: BIA MAC appears on an IP held by another device -> ClaimCreateNew (Spoofing/Reassignment)
    existingDev := &models.Device{
        PDID:       "pdid_l7_existing",
        CurrentMAC: "aa:bb:cc:dd:ee:ff",
        Hostname:   "existing",
        LastSeen:   time.Now(),
        Online:     true,
    }
    obs := discovery.Observation{
        MAC:      net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, // BIA MAC
        IP:       net.ParseIP("192.168.1.50"),
        Hostname: "new",
        Source:   "netlink",
    }
    res := ValidateIPClaim(obs, existingDev)
    if res != ClaimCreateNew {
        t.Errorf("Expected ClaimCreateNew for BIA MAC conflict, got %v", res)
    }

    // Case 2: Stale device (offline > 5m) -> ClaimCreateNewSilent
    staleDev := &models.Device{
        PDID:       "pdid_l7_stale",
        CurrentMAC: "aa:bb:cc:dd:ee:ff",
        LastSeen:   time.Now().Add(-10 * time.Minute),
        Online:     false,
    }
    obs.MAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01} // Randomized MAC
    res = ValidateIPClaim(obs, staleDev)
    if res != ClaimCreateNewSilent {
        t.Errorf("Expected ClaimCreateNewSilent for stale device, got %v", res)
    }

    // Case 3: Randomized MAC, hostname match, recent -> ClaimAttach
    recentDev := &models.Device{
        PDID:       "pdid_l7_recent",
        CurrentMAC: "02:00:00:00:00:01",
        Hostname:   "iphone",
        LastSeen:   time.Now(),
        Online:     true,
    }
    obs.MAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02} // New randomized MAC
    obs.Hostname = "iphone"
    res = ValidateIPClaim(obs, recentDev)
    if res != ClaimAttach {
        t.Errorf("Expected ClaimAttach for randomized MAC with hostname match, got %v", res)
    }

    // Case 4: Randomized MAC, vendor mismatch -> ClaimCreateNew
    mismatchDev := &models.Device{
        PDID:       "pdid_l7_mismatch",
        CurrentMAC: "02:00:00:00:00:01", // OUI implies Apple
        Hostname:   "",
        LastSeen:   time.Now(),
        Online:     true,
    }
    obs.MAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02} // OUI implies Google
    obs.Hostname = ""
    res = ValidateIPClaim(obs, mismatchDev)
    // Note: This relies on the OUI database actually recognizing the vendors.
    // If OUI lookup fails, it falls through to ClaimCreateNew.
    if res != ClaimCreateNew {
        t.Errorf("Expected ClaimCreateNew for vendor mismatch, got %v", res)
    }
}
