package correlation

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/apps/discovery-service/internal/storage"
	"github.com/user/lias-dis/shared/models"
)

func TestFixedMACIPChangePreservesPDID(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	engine := NewEngine(cache, broker)
	mac := mustMAC(t, "00:11:22:33:44:55")
	now := time.Now()
	engine.processObservation(discovery.Observation{Source: "netlink", Group: discovery.GroupA, MAC: mac, IP: net.ParseIP("192.168.1.10"), Online: true, Timestamp: now})
	first := cache.GetByMAC(mac.String())
	if first == nil {
		t.Fatal("initial device missing")
	}
	engine.lastSeenObs = make(map[string]time.Time)
	engine.processObservation(discovery.Observation{Source: "netlink", Group: discovery.GroupA, MAC: mac, IP: net.ParseIP("192.168.1.11"), Online: true, Timestamp: now.Add(time.Second)})
	second := cache.GetByMAC(mac.String())
	if second == nil || second.PDID != first.PDID || second.CurrentIP != "192.168.1.11" {
		t.Fatalf("fixed-MAC IP change split identity: before=%+v after=%+v", first, second)
	}
}

func TestAuthenticatedStableCredentialPreservesPolicyAcrossPrivateMACChangeAndRevokes(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "authenticated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := NewEngine(cache, broker)
	engine.SetStorage(store)
	now := time.Now()
	device := &models.Device{
		DeviceID: "dev_authenticated", PDID: "pdid_authenticated",
		CurrentMAC: "02:00:00:00:00:01", MACs: []string{"02:00:00:00:00:01"},
		CurrentIP: "192.168.1.20", IPs: []string{"192.168.1.20"},
		Tags: []string{"kids"}, UserID: "policy-owner", FirstSeen: now.Add(-time.Hour), LastSeen: now,
		IdentityTier: models.TierTentative,
	}
	cache.Upsert(device)
	if err := store.SaveDevice(device); err != nil {
		t.Fatal(err)
	}
	alias, err := engine.BindIdentityAlias(device.PDID, models.IdentityBindingRequest{Type: models.AliasMDMDeviceID, Value: "mdm-device-123", Source: "mdm"})
	if err != nil {
		t.Fatal(err)
	}

	engine.processObservation(discovery.Observation{
		Source: "mdm", Group: discovery.GroupE, MAC: mustMAC(t, "02:00:00:00:00:02"), IP: net.ParseIP("192.168.1.21"),
		Online: true, Timestamp: now.Add(time.Second), Raw: map[string]interface{}{"identity_authenticated": true, "mdm_device_id": "mdm-device-123"},
	})
	resolved := cache.Get(device.PDID)
	if resolved == nil || !resolved.HasMAC("02:00:00:00:00:02") || len(cache.List()) != 1 {
		t.Fatalf("authenticated private-MAC continuity failed: %+v", cache.List())
	}
	if !resolved.HasTag("kids") || resolved.UserID != "policy-owner" {
		t.Fatalf("policy continuity was lost: %+v", resolved)
	}

	if err := engine.RevokeIdentityAlias(device.PDID, alias.ID); err != nil {
		t.Fatal(err)
	}
	engine.processObservation(discovery.Observation{
		Source: "mdm", Group: discovery.GroupE, MAC: mustMAC(t, "02:00:00:00:00:03"), IP: net.ParseIP("192.168.1.22"),
		Online: true, Timestamp: now.Add(2 * time.Second), Raw: map[string]interface{}{"identity_authenticated": true, "mdm_device_id": "mdm-device-123"},
	})
	if len(cache.List()) != 2 || cache.Get(device.PDID).HasMAC("02:00:00:00:00:03") {
		t.Fatalf("revoked credential still merged identity: %+v", cache.List())
	}
}

func TestAuthenticatedIdentityCannotStealOwnedMAC(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	client := broker.Subscribe("mac-conflict", 0)
	defer broker.Unsubscribe(client.ID)
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "mac-conflict.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := NewEngine(cache, broker)
	engine.SetStorage(store)
	now := time.Now()
	identity := &models.Device{DeviceID: "dev_identity", PDID: "pdid_identity", CurrentMAC: "02:00:00:00:00:01",
		MACs: []string{"02:00:00:00:00:01"}, FirstSeen: now, LastSeen: now}
	owner := &models.Device{DeviceID: "dev_owner", PDID: "pdid_owner", CurrentMAC: "02:00:00:00:00:02",
		MACs: []string{"02:00:00:00:00:02"}, FirstSeen: now, LastSeen: now}
	for _, d := range []*models.Device{identity, owner} {
		if err := store.SaveDevice(d); err != nil {
			t.Fatal(err)
		}
		cache.Upsert(d)
	}
	if _, err := engine.BindIdentityAlias(identity.PDID, models.IdentityBindingRequest{
		Type: models.AliasMDMDeviceID, Value: "mdm-conflict", Source: "mdm",
	}); err != nil {
		t.Fatal(err)
	}
	engine.processObservation(discovery.Observation{Source: "mdm", Group: discovery.GroupE,
		MAC: mustMAC(t, owner.CurrentMAC), Timestamp: now.Add(time.Second),
		Raw: map[string]interface{}{"identity_authenticated": true, "mdm_device_id": "mdm-conflict"}})
	if cache.Get(identity.PDID).HasMAC(owner.CurrentMAC) {
		t.Fatal("authenticated identity stole a MAC owned by another PDID")
	}
	select {
	case event := <-client.Events:
		// Bind emits first; drain until the security alert arrives.
		if event.Type != models.EventIdentityBindingChanged {
			t.Fatalf("unexpected first event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("binding event missing")
	}
	select {
	case event := <-client.Events:
		if event.Type != models.EventSecurityAlert {
			t.Fatalf("MAC ownership conflict event=%+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("MAC ownership conflict did not emit a security alert")
	}
}
