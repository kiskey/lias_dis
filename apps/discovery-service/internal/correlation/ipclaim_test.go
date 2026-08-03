// Package correlation implements tests for DIS correlation logic.
//
// File:    apps/discovery-service/internal/correlation/ipclaim_test.go
// Version: 1.0
package correlation

import (
	"net"
	"testing"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	"github.com/user/lias-dis/shared/models"
)

func TestValidateIPClaim(t *testing.T) {
	// BIA MAC (Apple OUI: 00:17:f2)
	biaMAC, _ := net.ParseMAC("00:17:f2:11:22:33")
	// Private MACs (LAA bit set on first octet, e.g. 72:cd:d9)
	privMAC1, _ := net.ParseMAC("72:cd:d9:24:f4:b2")

	now := time.Now()

	t.Run("Case 1: BIA MAC returns ClaimCreateNew", func(t *testing.T) {
		obs := discovery.Observation{
			MAC:      biaMAC,
			IP:       net.ParseIP("192.168.1.50"),
			Hostname: "Pixel-6a",
		}
		existing := &models.Device{
			CurrentMAC: "bc:24:11:43:e0:ea",
			CurrentIP:  "192.168.1.50",
			Hostname:   "Pixel-6a",
			LastSeen:   now,
		}

		res := ValidateIPClaim(obs, existing)
		if res != ClaimCreateNew {
			t.Errorf("Expected ClaimCreateNew for BIA MAC, got %v", res)
		}
	})

	t.Run("Sub-case 2a: Private MAC with L7 confirmation < 60s returns ClaimAttach", func(t *testing.T) {
		obs := discovery.Observation{
			MAC:      privMAC1,
			IP:       net.ParseIP("192.168.1.50"),
			Hostname: "Pixel-6a.lan",
		}
		existing := &models.Device{
			CurrentMAC: "72:cd:d9:00:11:22",
			CurrentIP:  "192.168.1.50",
			Hostname:   "Pixel-6a",
			LastSeen:   now.Add(-10 * time.Second),
		}

		res := ValidateIPClaim(obs, existing)
		if res != ClaimAttach {
			t.Errorf("Expected ClaimAttach for matching L7 < 60s, got %v", res)
		}
	})

	t.Run("Sub-case 2b: Private MAC with L7 confirmation >= 60s returns ClaimCreateNew", func(t *testing.T) {
		obs := discovery.Observation{
			MAC:      privMAC1,
			IP:       net.ParseIP("192.168.1.50"),
			Hostname: "Pixel-6a.lan",
		}
		existing := &models.Device{
			CurrentMAC: "72:cd:d9:00:11:22",
			CurrentIP:  "192.168.1.50",
			Hostname:   "Pixel-6a",
			LastSeen:   now.Add(-90 * time.Second),
		}

		res := ValidateIPClaim(obs, existing)
		if res != ClaimCreateNew {
			t.Errorf("Expected ClaimCreateNew for stale device >= 60s, got %v", res)
		}
	})

	t.Run("Sub-case 2c: Hostname mismatch returns ClaimCreateNew", func(t *testing.T) {
		obs := discovery.Observation{
			MAC:      privMAC1,
			IP:       net.ParseIP("192.168.1.50"),
			Hostname: "SRVNAKSHA.lan",
		}
		existing := &models.Device{
			CurrentMAC: "72:cd:d9:00:11:22",
			CurrentIP:  "192.168.1.50",
			Hostname:   "Pixel-6a",
			LastSeen:   now.Add(-10 * time.Second),
		}

		res := ValidateIPClaim(obs, existing)
		if res != ClaimCreateNew {
			t.Errorf("Expected ClaimCreateNew for hostname mismatch, got %v", res)
		}
	})

	t.Run("Sub-case 2d: Missing hostnames on both returns ClaimCreateNew", func(t *testing.T) {
		obs := discovery.Observation{
			MAC: privMAC1,
			IP:  net.ParseIP("192.168.1.50"),
		}
		existing := &models.Device{
			CurrentMAC: "72:cd:d9:00:11:22",
			CurrentIP:  "192.168.1.50",
			LastSeen:   now.Add(-10 * time.Second),
		}

		res := ValidateIPClaim(obs, existing)
		if res != ClaimCreateNew {
			t.Errorf("Expected ClaimCreateNew for missing hostnames, got %v", res)
		}
	})
}
