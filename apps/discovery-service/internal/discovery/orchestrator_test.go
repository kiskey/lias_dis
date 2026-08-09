// Package discovery provides unit tests for the DIS orchestrator and nmap enrichment gating.
//
// File:    apps/discovery-service/internal/discovery/orchestrator_test.go
// Version: 1.3 (Fixed Nmap Cooldown Backdating in MaxRetries Test)
package discovery

import (
    "context"
	"fmt"
	"sync/atomic"
    "testing"
    "time"

    disAPI "github.com/user/lias-dis/apps/discovery-service/internal/api"
    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/models"
)

// mockEnricher is a test double for the Enricher interface used to count nmap invocations.
type mockEnricher struct {
    name        string
	invocations atomic.Int32
    enrichFunc  func(ctx context.Context, d *models.Device) (*models.Enrichment, error)
}

type concurrencyEnricher struct {
	active  atomic.Int32
	maximum atomic.Int32
	release <-chan struct{}
}

func (e *concurrencyEnricher) Name() string                { return "bounded" }
func (e *concurrencyEnricher) Start(context.Context) error { return nil }
func (e *concurrencyEnricher) Stop() error                 { return nil }
func (e *concurrencyEnricher) Enrich(ctx context.Context, _ *models.Device) (*models.Enrichment, error) {
	active := e.active.Add(1)
	defer e.active.Add(-1)
	for {
		maximum := e.maximum.Load()
		if active <= maximum || e.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.release:
		return nil, nil
	}
}

func (m *mockEnricher) Name() string { return m.name }
func (m *mockEnricher) Start(ctx context.Context) error { return nil }
func (m *mockEnricher) Stop() error { return nil }
func (m *mockEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
	m.invocations.Add(1)
    return m.enrichFunc(ctx, d)
}

func waitForOrchestratorIdle(t *testing.T, orch *Orchestrator) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		orch.pendingMu.Lock()
		pending := len(orch.pending)
		orch.pendingMu.Unlock()
		if pending == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("orchestrator did not become idle")
}

// TestNmapMaxRetries verifies that an incomplete device does NOT trigger nmap more than 3 times.
// This validates the P1-FIX: Max Retry Limit.
func TestNmapMaxRetries(t *testing.T) {
    cache := inventory.NewCache()
    defer cache.Stop()
    broker := disAPI.NewBroker(cache)

    fallback := &mockEnricher{
        name: "nmap_mock",
        enrichFunc: func(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
            // Simulate nmap failing to find anything
            return nil, ErrNmapNoResults 
        },
    }

    orch := NewOrchestrator(cache, broker, nil, fallback, 0)
	defer orch.Stop()
    
    dev := &models.Device{
        PDID:       "pdid_test_max_retries",
        CurrentIP:  "192.168.1.50",
        // Vendor and DeviceType are missing, so it is incomplete
    }
    cache.Upsert(dev)

    // Trigger 5 times with force=false.
    // We must manually backdate BOTH the 1-hour enrichment cooldown AND the 24-hour 
    // nmap cooldown to directly test the max retry logic boundary.
    for i := 0; i < 5; i++ {
        // 1. Backdate 1-hour enrichment cooldown
        orch.lastAttemptMap.Store(dev.PDID, time.Now().Add(-2*time.Hour))
        
        // 2. Backdate 24-hour nmap cooldown on the cached device
        cachedDev := cache.Get(dev.PDID)
        if cachedDev != nil {
            cachedDev.LastNmapScanAt = time.Now().Add(-25 * time.Hour)
            cache.Upsert(cachedDev)
        }

        orch.TriggerEnrichment(dev.PDID, false)
		waitForOrchestratorIdle(t, orch)
    }

	if got := fallback.invocations.Load(); got != 3 {
		t.Fatalf("Expected nmap to be invoked exactly 3 times, got %d", got)
    }
}

// TestNmapSkippedForFullyIdentified verifies that a fully identified device never triggers nmap.
// This validates the P1-FIX: Completeness Check.
func TestNmapSkippedForFullyIdentified(t *testing.T) {
    cache := inventory.NewCache()
    defer cache.Stop()
    broker := disAPI.NewBroker(cache)

    fallback := &mockEnricher{
        name: "nmap_mock",
        enrichFunc: func(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
            return nil, nil
        },
    }

    orch := NewOrchestrator(cache, broker, nil, fallback, 0)
	defer orch.Stop()
    
    dev := &models.Device{
        PDID:               "pdid_test_fully_identified",
        CurrentIP:          "192.168.1.51",
        Vendor:             "Apple Inc.",
        DeviceType:         "phone",
        Hostname:           "iPhone",
        IsFullyIdentified:  true, // Mark as fully identified
    }
    cache.Upsert(dev)

    // Force trigger to bypass time-based cooldowns and test ONLY the fully identified logic
    orch.TriggerEnrichment(dev.PDID, true)
	waitForOrchestratorIdle(t, orch)

	if got := fallback.invocations.Load(); got != 0 {
		t.Fatalf("Expected nmap to NOT be invoked for fully identified device, got %d invocations", got)
    }
}

// TestForceBypassesCooldowns verifies that force=true bypasses time-based and retry cooldowns.
// This validates that manual UI refreshes always work regardless of negative cache state.
func TestForceBypassesCooldowns(t *testing.T) {
    cache := inventory.NewCache()
    defer cache.Stop()
    broker := disAPI.NewBroker(cache)

    fallback := &mockEnricher{
        name: "nmap_mock",
        enrichFunc: func(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
            return nil, ErrNmapNoResults
        },
    }

    orch := NewOrchestrator(cache, broker, nil, fallback, 0)
	defer orch.Stop()
    
    dev := &models.Device{
        PDID:             "pdid_test_force_bypass",
        CurrentIP:        "192.168.1.52",
        NmapAttemptCount: 5,            // Exceeded max retries (3)
        LastNmapScanAt:   time.Now(),   // Within 24h cooldown
    }
    cache.Upsert(dev)

    // 1. Normal trigger should be blocked by 24h cooldown and max retries
    orch.lastAttemptMap.Store(dev.PDID, time.Now().Add(-2*time.Hour)) // Bypass 1h cooldown
    orch.TriggerEnrichment(dev.PDID, false)
	waitForOrchestratorIdle(t, orch)
	if got := fallback.invocations.Load(); got != 0 {
		t.Fatalf("Expected 0 invocations without force, got %d", got)
    }

    // 2. Force trigger should bypass cooldowns AND retry limits (e.g., manual UI refresh)
    orch.TriggerEnrichment(dev.PDID, true)
	waitForOrchestratorIdle(t, orch)
	if got := fallback.invocations.Load(); got != 1 {
		t.Fatalf("Expected 1 invocation with force=true, got %d", got)
	}
    }

func TestOrchestratorBoundsWorkersQueueAndCoalesces(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := disAPI.NewBroker(cache)
	release := make(chan struct{})
	enricher := &concurrencyEnricher{release: release}
	orch := NewOrchestratorWithOptions(cache, broker, []Enricher{enricher}, nil, 0, OrchestratorOptions{
		WorkerCount:    2,
		QueueSize:      2,
		PrimaryTimeout: time.Second,
	})
	defer orch.Stop()

	for i := 0; i < 10; i++ {
		pdid := fmt.Sprintf("pdid-bounded-%d", i)
		cache.Upsert(&models.Device{PDID: pdid, CurrentIP: fmt.Sprintf("192.168.1.%d", i+10)})
		orch.TriggerEnrichment(pdid, true)
		orch.TriggerEnrichment(pdid, true)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && enricher.active.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	if got := enricher.maximum.Load(); got > 2 {
		t.Fatalf("worker bound exceeded: %d", got)
	}
	orch.pendingMu.Lock()
	pending := len(orch.pending)
	orch.pendingMu.Unlock()
	if pending > 4 {
		t.Fatalf("active plus queued work exceeded bound: %d", pending)
	}
	close(release)
	waitForOrchestratorIdle(t, orch)
}
