package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/user/lias-dis/shared/models"
)

func TestAvahiResolvedRemoveTXTAndIPv6Scope(t *testing.T) {
	line := `=;eth0;IPv6;Living\032Room;_airplay._tcp;local;tv.local;fe80::1%eth0;7000;"model=TV" "flags=0x4"`
	event, key, rec, ok := parseAvahiBrowseLine(line, time.Now())
	if !ok || event != "resolved" || rec.FriendlyName != "Living Room" || rec.IP != "fe80::1" || rec.TXT["model"] != "TV" {
		t.Fatalf("failed to parse resolved record: event=%s rec=%+v", event, rec)
	}
	remove, removeKey, _, ok := parseAvahiBrowseLine(`-;eth0;IPv6;Living\032Room;_airplay._tcp;local`, time.Now())
	if !ok || remove != "removed" || removeKey != key {
		t.Fatal("remove event did not identify resolved record")
	}
}

func TestAvahiEnrichmentDeduplicatesServices(t *testing.T) {
	e := NewAvahiEnricher()
	now := time.Now()
	e.records["a"] = avahiRecord{Interface: "eth0", FriendlyName: "TV", Hostname: "tv", ServiceType: "_airplay._tcp", IP: "192.0.2.5", Timestamp: now}
	e.records["b"] = avahiRecord{Interface: "eth0", FriendlyName: "TV", Hostname: "tv", ServiceType: "_airplay._tcp", IP: "192.0.2.5", Timestamp: now}
	enrichment, err := e.Enrich(context.Background(), &models.Device{CurrentIP: "192.0.2.5"})
	if err != nil {
		t.Fatal(err)
	}
	if enrichment == nil || len(enrichment.Services) != 1 || enrichment.DeviceType != "tv" {
		t.Fatalf("unexpected enrichment: %+v", enrichment)
	}
}

func TestAvahiRecordStoreIsBounded(t *testing.T) {
	e := NewAvahiEnricher()
	base := time.Now().Add(-time.Hour)
	for i := 0; i < maxAvahiRecords; i++ {
		e.records[string(rune(i+1))] = avahiRecord{Timestamp: base.Add(time.Duration(i) * time.Second)}
	}
	e.upsertRecordLocked("new", avahiRecord{Timestamp: time.Now()})
	if len(e.records) != maxAvahiRecords {
		t.Fatalf("record store grew to %d", len(e.records))
	}
	if _, exists := e.records[string(rune(1))]; exists {
		t.Fatal("oldest record was not evicted")
	}
}
