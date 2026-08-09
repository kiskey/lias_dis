package discovery

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseSSDPMessageAndLifecycle(t *testing.T) {
	raw := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"LOCATION: http://192.168.1.20:8080/root.xml\r\n" +
		"NTS: ssdp:alive\r\n" +
		"USN: uuid:test-device::upnp:rootdevice\r\n\r\n"
	msg, err := parseSSDPMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	e := NewSSDPEnricher("")
	e.ctx = context.Background()
	e.handleNotify(msg, net.ParseIP("192.168.1.20"))
	e.recordMu.Lock()
	_, exists := e.records["uuid:test-device::upnp:rootdevice"]
	e.recordMu.Unlock()
	if !exists {
		t.Fatal("ssdp:alive record was not stored")
	}

	byebye, err := parseSSDPMessage([]byte("NOTIFY * HTTP/1.1\r\nNTS: ssdp:byebye\r\nUSN: uuid:test-device::upnp:rootdevice\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	e.handleNotify(byebye, net.ParseIP("192.168.1.20"))
	e.recordMu.Lock()
	_, exists = e.records["uuid:test-device::upnp:rootdevice"]
	e.recordMu.Unlock()
	if exists {
		t.Fatal("ssdp:byebye record was not removed")
	}
}

func TestParseSSDPMessageRejectsAmbiguousInput(t *testing.T) {
	cases := [][]byte{
		[]byte("HTTP/1.0 200 OK\r\nLOCATION: http://192.168.1.2/a\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.2/a\r\nLOCATION: http://192.168.1.3/b\r\n\r\n"),
		append([]byte("HTTP/1.1 200 OK\r\nX: "), bytes.Repeat([]byte("a"), maxSSDPHeaderLine+1)...),
		bytes.Repeat([]byte("a"), maxSSDPDatagram+1),
	}
	for i, input := range cases {
		if _, err := parseSSDPMessage(input); err == nil {
			t.Fatalf("case %d: malformed datagram accepted", i)
		}
	}
}

func TestValidateDescriptorURLPinsAdvertisingHost(t *testing.T) {
	expected := net.ParseIP("192.168.1.20")
	if _, err := validateDescriptorURL("http://192.168.1.20:8080/root.xml", expected); err != nil {
		t.Fatalf("valid local descriptor rejected: %v", err)
	}
	invalid := []string{
		"http://192.168.1.21/root.xml",
		"http://example.com/root.xml",
		"http://user:pass@192.168.1.20/root.xml",
		"file:///etc/passwd",
		"http://127.0.0.1/root.xml",
		"http://192.168.1.20/root.xml#fragment",
	}
	for _, candidate := range invalid {
		if _, err := validateDescriptorURL(candidate, expected); err == nil {
			t.Fatalf("unsafe descriptor URL accepted: %s", candidate)
		}
	}
}

func TestSSDPCacheTTLBounds(t *testing.T) {
	if got := parseSSDPCacheTTL("public, max-age=1"); got != 30*time.Second {
		t.Fatalf("minimum TTL not enforced: %s", got)
	}
	if got := parseSSDPCacheTTL("max-age=999999"); got != 24*time.Hour {
		t.Fatalf("maximum TTL not enforced: %s", got)
	}
	if got := parseSSDPCacheTTL("no-cache"); got != 0 {
		t.Fatalf("invalid TTL accepted: %s", got)
	}
}

func TestParseSSDPDescriptorBoundsAndRejectsDTD(t *testing.T) {
	xml := `<root><device><friendlyName>Living Room</friendlyName><manufacturer>Acme</manufacturer><modelName>Box</modelName><modelNumber>1</modelNumber><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType></device></root>`
	enr, err := parseSSDPDescriptor([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if enr.FriendlyName != "Living Room" || enr.DeviceType != "tv" {
		t.Fatalf("unexpected enrichment: %#v", enr)
	}
	if _, err := parseSSDPDescriptor([]byte(`<!DOCTYPE root [<!ENTITY x "boom">]><root/>`)); err == nil {
		t.Fatal("DTD/entity descriptor accepted")
	}
	if _, err := parseSSDPDescriptor([]byte(strings.Repeat("x", maxDescriptorBytes+1))); err == nil {
		t.Fatal("oversized descriptor accepted")
	}
}
