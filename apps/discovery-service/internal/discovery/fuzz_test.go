package discovery

import (
	"testing"
	"time"
)

func FuzzParseNodeStatusResponse(f *testing.F) {
	request := buildNodeStatusRequest(0x1234)
	f.Add(request, uint16(0x1234))
	f.Add([]byte{0x12, 0x34}, uint16(0x1234))
	f.Fuzz(func(t *testing.T, data []byte, transactionID uint16) {
		names, err := parseNodeStatusResponse(data, transactionID)
		if err == nil && len(names) > 100 {
			t.Fatalf("parser exceeded NBSTAT name bound: %d", len(names))
		}
	})
}

func FuzzParseNodeStatusRDATA(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{1, 'D', 'E', 'V', 'I', 'C', 'E', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		names, err := parseNodeStatusRDATA(data)
		if err == nil && len(names) > 100 {
			t.Fatalf("RDATA parser exceeded name bound: %d", len(names))
		}
	})
}

func FuzzParseSSDPMessage(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.2/root.xml\r\nST: upnp:rootdevice\r\nUSN: uuid:test\r\n\r\n"))
	f.Add([]byte("NOTIFY * HTTP/1.1\r\nNTS: ssdp:byebye\r\nUSN: uuid:test\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := parseSSDPMessage(data)
		if err == nil {
			if msg.startLine != "HTTP/1.1 200 OK" && msg.startLine != "NOTIFY * HTTP/1.1" {
				t.Fatalf("unexpected accepted start line: %q", msg.startLine)
			}
			if len(msg.headers) > maxSSDPHeaders {
				t.Fatalf("SSDP header bound exceeded: %d", len(msg.headers))
			}
		}
	})
}

func FuzzParseSSDPDescriptor(f *testing.F) {
	f.Add([]byte(`<root><device><friendlyName>TV</friendlyName><manufacturer>Acme</manufacturer><modelName>One</modelName><deviceType>MediaRenderer</deviceType></device></root>`))
	f.Add([]byte(`<!DOCTYPE root><root/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		enr, err := parseSSDPDescriptor(data)
		if err == nil && enr != nil {
			if len(enr.FriendlyName) > 256 || len(enr.Manufacturer) > 256 || len(enr.Model) > 256 {
				t.Fatal("SSDP descriptor field bound exceeded")
			}
		}
	})
}

func FuzzParseDNSMasqLeases(f *testing.F) {
	now := time.Unix(1_700_000_000, 0)
	f.Add([]byte("1700003600 00:11:22:33:44:55 192.168.1.20 phone 01:02\n"))
	f.Add([]byte("not a lease\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		leases, _ := parseDNSMasqLeases(data, now)
		if len(leases) > maxDHCPRecords {
			t.Fatalf("dnsmasq record bound exceeded: %d", len(leases))
		}
	})
}

func FuzzParseKeaLeases(f *testing.F) {
	now := time.Unix(1_700_000_000, 0)
	f.Add([]byte("address,hwaddr,client_id,expire,hostname,state\n192.168.1.20,00:11:22:33:44:55,abc,1700003600,phone,0\n"))
	f.Add([]byte("address,broken\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		leases, _ := parseKeaLeases(data, now)
		if len(leases) > maxDHCPRecords {
			t.Fatalf("Kea record bound exceeded: %d", len(leases))
		}
	})
}

func FuzzParseAvahiBrowseLine(f *testing.F) {
	f.Add("=;eth0;IPv4;Living\\032Room;_airplay._tcp;local;tv.local;192.168.1.30;7000;\"model=TV\"")
	f.Add("-;eth0;IPv4;Living Room;_airplay._tcp;local")
	f.Fuzz(func(t *testing.T, line string) {
		action, key, record, ok := parseAvahiBrowseLine(line, time.Unix(1_700_000_000, 0))
		if ok && (key == "" || (action != "resolved" && action != "removed")) {
			t.Fatalf("invalid accepted Avahi result: action=%q key=%q record=%+v", action, key, record)
		}
	})
}

func FuzzParsePiholeClients(f *testing.F) {
	f.Add(true, []byte(`{"devices":[{"hwaddr":"00:11:22:33:44:55","macVendor":"Acme","ips":[{"ip":"192.168.1.2","name":"phone"}]}]}`))
	f.Add(false, []byte(`{"clients":[{"ip":"192.168.1.2","name":"phone"}]}`))
	f.Fuzz(func(t *testing.T, networkDevices bool, data []byte) {
		endpoint := "/api/stats/clients"
		if networkDevices {
			endpoint = "/api/network/devices"
		}
		clients, err := parsePiholeClients(endpoint, data)
		if err == nil && len(clients) > maxPiholeClients {
			t.Fatalf("Pi-hole client bound exceeded: %d", len(clients))
		}
	})
}

func FuzzParseNmapXML(f *testing.F) {
	f.Add([]byte(`<nmaprun><host><status state="up"/><ports><port portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`))
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		enr := parseNmapXML(data)
		if enr != nil && len(enr.Services) > 65_535 {
			t.Fatalf("unreasonable service count: %d", len(enr.Services))
		}
	})
}
