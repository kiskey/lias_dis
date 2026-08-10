package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/user/lias-dis/shared/models"
)

func TestNmapCommandArgsAreBoundedAndUnprivilegedByDefault(t *testing.T) {
	e := NewNmapEnricher(NmapOptions{
		HostTimeout:    7 * time.Second,
		ProcessTimeout: 9 * time.Second,
		MaxRate:        25,
	})
	args := e.commandArgs("192.168.1.50")
	joined := " " + strings.Join(args, " ") + " "
	for _, required := range []string{" -Pn ", " -n ", " -sT ", " --version-light ", " --max-retries 1 ", " --host-timeout 7s ", " --max-rate 25 ", " -F ", " -oX - "} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing bounded nmap argument %q in %q", required, joined)
		}
	}
	if strings.Contains(joined, " -O ") || strings.Contains(joined, " -T4 ") || strings.Contains(joined, " -A ") {
		t.Fatalf("aggressive/privileged scan enabled by default: %q", joined)
	}
	if args[len(args)-1] != "192.168.1.50" {
		t.Fatalf("validated target is not final argument: %#v", args)
	}
}

func TestNmapOSDetectionRequiresExplicitOptIn(t *testing.T) {
	e := NewNmapEnricher(NmapOptions{EnableOSDetection: true})
	joined := " " + strings.Join(e.commandArgs("192.168.1.2"), " ") + " "
	if !strings.Contains(joined, " -O ") || !strings.Contains(joined, " --osscan-limit ") {
		t.Fatalf("explicit OS detection option not honored: %q", joined)
	}
}

func TestNmapOutputBufferEnforcesLimit(t *testing.T) {
	w := &limitedBuffer{limit: 4}
	if _, err := w.Write([]byte("12345")); !errors.Is(err, ErrNmapOutputLimit) {
		t.Fatalf("expected output limit error, got %v", err)
	}
	if !w.exceeded || string(w.Bytes()) != "1234" {
		t.Fatalf("unexpected limited buffer state: exceeded=%v bytes=%q", w.exceeded, w.Bytes())
	}
}

func TestNmapRejectsNonLANTargetBeforeExecution(t *testing.T) {
	e := NewNmapEnricher()
	_, err := e.Enrich(context.Background(), &models.Device{CurrentIP: "8.8.8.8"})
	if err == nil || !strings.Contains(err.Error(), "non-LAN") {
		t.Fatalf("public target was not rejected: %v", err)
	}
}

func TestParseNmapXMLOnlyUsesOpenPorts(t *testing.T) {
	data := []byte(`<nmaprun><host><status state="up"/><ports><port portid="22"><state state="closed"/><service name="ssh"/></port><port portid="631"><state state="open"/><service name="ipp"/></port></ports></host></nmaprun>`)
	enr := parseNmapXML(data)
	if enr == nil || len(enr.Services) != 1 || enr.Services[0] != "ipp" || enr.DeviceType != "printer" {
		t.Fatalf("closed port influenced result: %#v", enr)
	}
}
