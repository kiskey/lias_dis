package discovery

import (
	"strings"
	"testing"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/config"
)

func TestDNSMasqLeaseFormatHasNoOption55(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	data := strings.Join([]string{
		"2000000600 00:11:22:33:44:55 192.0.2.10 phone 01:aa:bb",
		"2000000600 00:11:22:33:44:56 192.0.2.11 wrong 01:aa:bb 1,3,6,15",
		"1999999999 00:11:22:33:44:57 192.0.2.12 expired *",
	}, "\n")
	observations, err := parseDNSMasqLeases([]byte(data), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 {
		t.Fatalf("expected one valid lease, got %d", len(observations))
	}
	obs := observations[0]
	if obs.Online {
		t.Fatal("a DHCP lease was treated as live presence")
	}
	if _, exists := obs.Raw["dhcp_option_55"]; exists {
		t.Fatal("fabricated Option 55 was retained")
	}
	if _, exists := obs.Raw["dhcp_client_id_hash"]; !exists {
		t.Fatal("client ID was not privacy-hashed")
	}
	if _, exists := obs.Raw["dhcp_client_id"]; exists {
		t.Fatal("raw client credential was retained")
	}
}

func TestKeaCSVUsesHeaderAndLeaseState(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	csv := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n" +
		"192.0.2.20,00:11:22:33:44:66,01aabb,600,2000000600,1,kea-phone,0\n" +
		"192.0.2.21,00:11:22:33:44:67,,600,2000000600,1,old-active,0\n" +
		"192.0.2.21,00:11:22:33:44:67,,600,2000000600,1,declined,1\n"
	observations, err := parseKeaLeases([]byte(csv), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Hostname != "kea-phone" || observations[0].Online {
		t.Fatalf("unexpected Kea observations: %+v", observations)
	}
}

func TestOpenWrtParsersRequireStationAndReachableState(t *testing.T) {
	station, ok := parseOpenWrtStationLine("wlan0 02:11:22:33:44:55")
	if !ok || station.Source != "openwrt_ap" || !station.Online {
		t.Fatalf("bad station observation: %+v", station)
	}
	if _, ok := parseOpenWrtNeighborLine("192.0.2.10 02:11:22:33:44:55 STALE"); ok {
		t.Fatal("STALE neighbour accepted")
	}
	neighbor, ok := parseOpenWrtNeighborLine("192.0.2.10 02:11:22:33:44:55 REACHABLE")
	if !ok || neighbor.Source != "openwrt_neigh" || !neighbor.Online {
		t.Fatalf("bad neighbour observation: %+v", neighbor)
	}
}

func TestUnchangedLeaseIsNotReemittedEachPoll(t *testing.T) {
	p := NewDHCPProvider(config.DHCPConfig{})
	obs := Observation{MAC: mustHardwareAddr(t, "00:11:22:33:44:55"), IP: []byte{192, 0, 2, 10}, Hostname: "phone", Raw: map[string]interface{}{"lease_expires_at": "x"}}
	p.emitChangedLeases([]Observation{obs})
	if len(p.events) != 1 {
		t.Fatal("first lease was not emitted")
	}
	<-p.events
	p.emitChangedLeases([]Observation{obs})
	if len(p.events) != 0 {
		t.Fatal("unchanged lease was reemitted")
	}
}
