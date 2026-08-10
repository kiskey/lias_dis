package inventory

import (
	"testing"
	"time"

	"github.com/user/lias-dis/shared/models"
)

func TestDormantDeviceRetainsIdentityOwnershipAndReactivates(t *testing.T) {
	cache := NewCache()
	defer cache.Stop()
	device := &models.Device{
		DeviceID: "dev_dormant", PDID: "pdid_dormant",
		CurrentMAC: "00:11:22:33:44:55", MACs: []string{"00:11:22:33:44:55"},
		LastSeen: time.Now().Add(-offlineTTL - time.Minute), Online: false,
	}
	cache.Upsert(device)
	cache.purgeOffline()
	if got := cache.List(); len(got) != 0 {
		t.Fatalf("dormant device remained in active inventory: %+v", got)
	}
	if got := cache.GetActive(device.PDID); got != nil {
		t.Fatalf("dormant device remained public: %+v", got)
	}
	resolved := cache.GetByMAC(device.CurrentMAC)
	if resolved == nil || resolved.PDID != device.PDID {
		t.Fatalf("dormant identity ownership was discarded: %+v", resolved)
	}
	resolved.LastSeen = time.Now()
	cache.Upsert(resolved)
	if got := cache.List(); len(got) != 1 || got[0].PDID != device.PDID {
		t.Fatalf("reactivation changed identity: %+v", got)
	}
}

func TestEveryHistoricalMACIsIndexed(t *testing.T) {
	cache := NewCache()
	defer cache.Stop()
	device := &models.Device{DeviceID: "dev_history", PDID: "pdid_history",
		CurrentMAC: "00:11:22:33:44:66",
		MACs:       []string{"00:11:22:33:44:55", "00:11:22:33:44:66"},
		LastSeen:   time.Now(),
	}
	cache.Upsert(device)
	for _, mac := range device.MACs {
		if got := cache.GetByMAC(mac); got == nil || got.PDID != device.PDID {
			t.Fatalf("historical MAC %s was not indexed: %+v", mac, got)
		}
	}
}

func TestIPOwnershipReleasePreservesHistory(t *testing.T) {
	cache := NewCache()
	defer cache.Stop()
	device := &models.Device{DeviceID: "dev_ip", PDID: "pdid_ip", CurrentIP: "192.0.2.10",
		IPs: []string{"192.0.2.10"}, LastSeen: time.Now()}
	cache.Upsert(device)
	cache.RemoveIPIndex(device.CurrentIP)
	got := cache.Get(device.PDID)
	if got == nil || got.CurrentIP != "" || len(got.IPs) != 1 || got.IPs[0] != device.CurrentIP {
		t.Fatalf("IP ownership release discarded history: %+v", got)
	}
	if cache.GetByIP(device.CurrentIP) != nil {
		t.Fatal("released IP still had a current owner")
	}
}

func TestDormantHistoricalMACStillResolves(t *testing.T) {
	cache := NewCache()
	defer cache.Stop()

	device := &models.Device{
		DeviceID:   "dev_multi_mac",
		PDID:       "pdid_multi_mac",
		CurrentMAC: "00:11:22:33:44:66",
		MACs:       []string{"00:11:22:33:44:55", "00:11:22:33:44:66"},
		LastSeen:   time.Now().Add(-offlineTTL - time.Minute),
		Online:     false,
	}
	cache.Upsert(device)
	cache.purgeOffline()

	for _, mac := range device.MACs {
		got := cache.GetByMAC(mac)
		if got == nil || got.PDID != device.PDID {
			t.Fatalf("dormant historical MAC %s resolved to %+v", mac, got)
		}
	}
}
