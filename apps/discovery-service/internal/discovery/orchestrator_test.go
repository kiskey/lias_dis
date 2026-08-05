// Package discovery provides unit tests for the DIS orchestrator and nmap enrichment gating.
//
// File:    apps/discovery-service/internal/discovery/orchestrator_test.go
// Version: 1.0
package discovery

import (
    "context"
    "testing"
    "time"

    disAPI "github.com/user/lias-dis/apps/discovery-service/internal/api"
    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/models"
)

// mockEnricher is a test double for the Enricher interface used to count nmap invocations.
type mockEnricher struct {
    name       string
    invocations int
    enrichFunc func(ctx context.Context, d *models.Device) (*models.Enrichment, error)
}

func (m *mockEnricher) Name() string { return m.name }
func (m *mockEnricher) Start(ctx context.Context) error { return nil }
func (m *mockEnricher) Stop() error { return nil }
func (m *mockEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    m.invocations++
    return m.enrichFunc(ctx, d)
}

// TestNmapMaxRetries verifies that an incomplete device does NOT trigger nmap more than 3 times.
// This validates the P1-FIX: Max Retry Limit.
func TestNmapMaxRetries(t *testing.T) {
    cache := inventory.NewCache()
    defer cache.Stop()
    broker := disAPI.NewBroker(cache)
    defer broker.Stop()

    fallback := &mockEnricher{
        name: "nmap_mock",
        enrichFunc: func(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
            // Simulate nmap failing to find anything
            return nil, ErrNmapNoResults 
        },
    }

    orch := NewOrchestrator(cache, broker, nil, fallback, 0)
    
    dev := &models.Device{
        PDID:       "pdid_test_max_retries",
        CurrentIP:  "192.168.1.50",
        // Vendor and DeviceType are missing, so it is incomplete
    }
    cache.Upsert(dev)

    // Trigger 5 times with force=true to bypass the 1-hour cooldown, 
    // directly testing the max retry logic boundary.
    for i := 0; i < 5; i++ {
        orch.TriggerEnrichment(dev.PDID, true)
    }

    if fallback.invocations != 3 {
        t.Fatalf("Expected nmap to be invoked exactly 3 times, got %d", fallback.invocations)
    }
}

// TestNmapSkippedForFullyIdentified verifies that a fully identified device never triggers nmap.
// This validates the P1-FIX: Completeness Check.
func TestNmapSkippedForFullyIdentified(t *testing.T) {
    cache := inventory.NewCache()
    defer cache.Stop()
    broker := disAPI.NewBroker(cache)
    defer broker.Stop()

    fallback := &mockEnricher{
        name: "nmap_mock",
        enrichFunc: func(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
            return nil, nil
        },
    }

    orch := NewOrchestrator(cache, broker, nil, fallback, 0)
    
    dev := &models.Device{
        PDID:               "pdid_test_fully_identified",
        CurrentIP:          "192.168.1.51",
        Vendor:             "Apple Inc.",
        DeviceType:         "phone",
        Hostname:           "iPhone",
        IsFullyIdentified:  true, // Mark as fully identified
    }
    cache.Upsert(dev)

    // Force trigger to bypass cooldowns and test ONLY the fully identified logic
    orch.TriggerEnrichment(dev.PDID, true)

    if fallback.invocations != 0 {
        t.Fatalf("Expected nmap to NOT be invoked for fully identified device, got %d invocations", fallback.invocations)
    }
}

// TestForceBypassesCooldowns verifies that force=true bypasses all cooldowns and retry limits.
// This validates that manual UI refreshes always work regardless of negative cache state.
func TestForceBypassesCooldowns(t *testing.T) {
    cache := inventory.NewCache()
    defer cache.Stop()
    broker := disAPI.NewBroker(cache)
    defer broker.Stop()

    fallback := &mockEnricher{
        name: "nmap_mock",
        enrichFunc: func(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
            return nil, ErrNmapNoResults
        },
    }

    orch := NewOrchestrator(cache, broker, nil, fallback, 0)
    
    dev := &models.Device{
        PDID:             "pdid_test_force_bypass",
        CurrentIP:        "192.168.1.52",
        NmapAttemptCount: 5,            // Exceeded max retries (3)
        LastNmapScanAt:   time.Now(),   // Within 24h cooldown
    }
    cache.Upsert(dev)

    // 1. Normal trigger should be blocked by 24h cooldown and max retries
    orch.TriggerEnrichment(dev.PDID, false)
    if fallback.invocations != 0 {
        t.Fatalf("Expected 0 invocations without force, got %d", fallback.invocations)
    }

    // 2. Force trigger should bypass cooldowns AND retry limits (e.g., manual UI refresh)
    orch.TriggerEnrichment(dev.PDID, true)
    if fallback.invocations != 1 {
        t.Fatalf("Expected 1 invocation with force=true, got %d", fallback.invocations)
    }
}
