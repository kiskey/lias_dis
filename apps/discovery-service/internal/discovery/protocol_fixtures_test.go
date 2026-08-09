package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readProtocolFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "protocol", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestProtocolParserFixtures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	dnsmasq, err := parseDNSMasqLeases(readProtocolFixture(t, "dnsmasq.leases"), now)
	if err != nil || len(dnsmasq) != 1 || dnsmasq[0].Hostname != "phone" || dnsmasq[0].Online {
		t.Fatalf("dnsmasq fixture: records=%+v err=%v", dnsmasq, err)
	}
	kea, err := parseKeaLeases(readProtocolFixture(t, "kea.csv"), now)
	if err != nil || len(kea) != 1 || kea[0].Hostname != "tablet" || kea[0].Online {
		t.Fatalf("Kea fixture: records=%+v err=%v", kea, err)
	}

	avahiLine := strings.TrimSpace(string(readProtocolFixture(t, "avahi.txt")))
	action, _, avahi, ok := parseAvahiBrowseLine(avahiLine, now)
	if !ok || action != "resolved" || avahi.IP != "192.168.1.30" || avahi.FriendlyName != "Living Room" {
		t.Fatalf("Avahi fixture rejected: action=%q record=%+v", action, avahi)
	}

	clients, err := parsePiholeClients("/api/network/devices", readProtocolFixture(t, "pihole_devices.json"))
	if err != nil || len(clients) != 1 || clients[0].IP != "192.168.1.40" || clients[0].Mac != "00:11:22:33:44:77" {
		t.Fatalf("Pi-hole fixture: clients=%+v err=%v", clients, err)
	}

	ssdpText := strings.TrimSpace(string(readProtocolFixture(t, "ssdp_response.txt")))
	ssdpText = strings.ReplaceAll(ssdpText, "\n", "\r\n") + "\r\n\r\n"
	ssdp, err := parseSSDPMessage([]byte(ssdpText))
	if err != nil || ssdp.headers["usn"] != "uuid:fixture-device::upnp:rootdevice" {
		t.Fatalf("SSDP response fixture: message=%+v err=%v", ssdp, err)
	}
	descriptor, err := parseSSDPDescriptor(readProtocolFixture(t, "ssdp_descriptor.xml"))
	if err != nil || descriptor.FriendlyName != "Fixture TV" || descriptor.DeviceType != "tv" {
		t.Fatalf("SSDP descriptor fixture: enrichment=%+v err=%v", descriptor, err)
	}

	nmap := parseNmapXML(readProtocolFixture(t, "nmap.xml"))
	if nmap == nil || nmap.Hostname != "fixture.local" || nmap.DeviceType != "printer" || len(nmap.Services) != 1 {
		t.Fatalf("Nmap fixture rejected: %+v", nmap)
	}
}
