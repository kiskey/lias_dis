package discovery

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestNetlinkOnlyReachableIsPresence(t *testing.T) {
	p := NewNetlinkProvider("eth0")
	p.targetIdx = 7
	base := netlink.Neigh{LinkIndex: 7, IP: net.ParseIP("192.0.2.10"), HardwareAddr: mustHardwareAddr(t, "02:11:22:33:44:55")}
	for _, state := range []int{unix.NUD_STALE, unix.NUD_DELAY, unix.NUD_PROBE, unix.NUD_PERMANENT, unix.NUD_FAILED} {
		neigh := base
		neigh.State = state
		p.handleNeighUpdate(netlink.NeighUpdate{Type: unix.RTM_NEWNEIGH, Neigh: neigh})
		select {
		case obs := <-p.events:
			t.Fatalf("state %d emitted presence: %+v", state, obs)
		default:
		}
	}
	reachable := base
	reachable.State = unix.NUD_REACHABLE
	p.handleNeighUpdate(netlink.NeighUpdate{Type: unix.RTM_NEWNEIGH, Neigh: reachable})
	select {
	case obs := <-p.events:
		if !obs.Online || obs.Vendor != "" || obs.Raw["nud_state"] != "reachable" {
			t.Fatalf("unexpected reachable observation: %+v", obs)
		}
	default:
		t.Fatal("reachable transition was not emitted")
	}
}

func mustHardwareAddr(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}
