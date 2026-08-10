package correlation

import (
	"net"
	"testing"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
)

func BenchmarkDuplicateObservationStorm(b *testing.B) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	engine := NewEngine(cache, broker)
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	obs := discovery.Observation{Source: "netlink", Group: discovery.GroupA, MAC: mac,
		IP: net.ParseIP("192.168.1.20"), Online: true, Timestamp: time.Now()}
	engine.processObservation(obs)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.processObservation(obs)
	}
}
