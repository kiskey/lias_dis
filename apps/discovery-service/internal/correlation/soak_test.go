package correlation

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
)

func TestDISSoak(t *testing.T) {
	if os.Getenv("DIS_RUN_SOAK") != "1" {
		t.Skip("set DIS_RUN_SOAK=1 to run the opt-in 72-hour soak")
	}
	duration := 72 * time.Hour
	if configured := os.Getenv("DIS_SOAK_DURATION"); configured != "" {
		parsed, err := time.ParseDuration(configured)
		if err != nil || parsed < time.Minute {
			t.Fatalf("invalid DIS_SOAK_DURATION %q", configured)
		}
		duration = parsed
	}

	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	engine := NewEngine(cache, broker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.Run(ctx, nil)
	baselineGoroutines := runtime.NumGoroutine()
	var baseline runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&baseline)

	deadline := time.Now().Add(duration)
	ticker := time.NewTicker(100 * time.Millisecond)
	sample := time.NewTicker(time.Minute)
	defer ticker.Stop()
	defer sample.Stop()
	iteration := 0
	for time.Now().Before(deadline) {
		select {
		case now := <-ticker.C:
			for i := 0; i < 200; i++ {
				mac, _ := net.ParseMAC(fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256))
				engine.processObservation(discovery.Observation{Source: "netlink", Group: discovery.GroupA,
					MAC: mac, IP: net.ParseIP(fmt.Sprintf("192.168.%d.%d", i/254, i%254+1)), Online: true, Timestamp: now})
			}
			iteration++
		case <-sample.C:
			runtime.GC()
			var current runtime.MemStats
			runtime.ReadMemStats(&current)
			if growth := runtime.NumGoroutine() - baselineGoroutines; growth > 16 {
				t.Fatalf("goroutine growth exceeded budget: %d", growth)
			}
			if current.HeapAlloc > baseline.HeapAlloc+(75<<20) {
				t.Fatalf("heap growth exceeded 75 MiB budget: baseline=%d current=%d", baseline.HeapAlloc, current.HeapAlloc)
			}
			if len(cache.List()) > 200 {
				t.Fatalf("device cache grew beyond fixture population: %d", len(cache.List()))
			}
		}
	}
	t.Logf("soak complete: duration=%s iterations=%d devices=%d goroutines=%d", duration, iteration, len(cache.List()), runtime.NumGoroutine())
}
