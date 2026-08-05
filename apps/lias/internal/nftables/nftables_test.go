// Package nftables provides unit tests for the LIAS nftables builder diffing logic.
//
// File:    apps/lias/internal/nftables/nftables_test.go
// Version: 1.2
package nftables

import (
    "net"
    "testing"
)

func TestDiffIPs(t *testing.T) {
    current := map[string]net.IP{
        "192.168.1.10": net.ParseIP("192.168.1.10"),
        "192.168.1.11": net.ParseIP("192.168.1.11"),
    }
    desired := map[string]net.IP{
        "192.168.1.10": net.ParseIP("192.168.1.10"),
        "192.168.1.12": net.ParseIP("192.168.1.12"),
    }

    toAdd := make([]net.IP, 0)
    toRem := make([]net.IP, 0)
    
    diffIPs(desired, current, &toAdd, &toRem)

    if len(toAdd) != 1 || !toAdd[0].Equal(net.ParseIP("192.168.1.12")) {
        t.Errorf("Expected to add 192.168.1.12, got %v", toAdd)
    }
    if len(toRem) != 1 || !toRem[0].Equal(net.ParseIP("192.168.1.11")) {
        t.Errorf("Expected to remove 192.168.1.11, got %v", toRem)
    }
}

func TestDiffIPsEmpty(t *testing.T) {
    current := map[string]net.IP{
        "192.168.1.10": net.ParseIP("192.168.1.10"),
    }
    desired := map[string]net.IP{}

    toAdd := make([]net.IP, 0)
    toRem := make([]net.IP, 0)
    
    diffIPs(desired, current, &toAdd, &toRem)

    if len(toAdd) != 0 {
        t.Errorf("Expected 0 additions, got %d", len(toAdd))
    }
    if len(toRem) != 1 || !toRem[0].Equal(net.ParseIP("192.168.1.10")) {
        t.Errorf("Expected to remove 192.168.1.10, got %v", toRem)
    }
}

func TestDiffMACs(t *testing.T) {
    mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
    mac2, _ := net.ParseMAC("11:22:33:44:55:66")
    mac3, _ := net.ParseMAC("77:88:99:aa:bb:cc")

    current := map[string]net.HardwareAddr{
        mac1.String(): mac1,
        mac2.String(): mac2,
    }
    desired := map[string]net.HardwareAddr{
        mac1.String(): mac1,
        mac3.String(): mac3,
    }

    toAdd := make([]net.HardwareAddr, 0)
    toRem := make([]net.HardwareAddr, 0)
    
    diffMACs(desired, current, &toAdd, &toRem)

    // FIX: Replaced invalid ! operator syntax with !=
    if len(toAdd) != 1 || toAdd[0].String() != mac3.String() {
        t.Errorf("Expected to add %s, got %v", mac3.String(), toAdd)
    }
    if len(toRem) != 1 || toRem[0].String() != mac2.String() {
        t.Errorf("Expected to remove %s, got %v", mac2.String(), toRem)
    }
}
