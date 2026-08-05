package discovery

import (
    "context"
    "testing"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/api"
    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/models"
)

// Mock Enricher for testing
type mockEnricher struct {
    name      string
    enrichFunc func(ctx context.Context, d *models.Device) (*models.Enrichment, error)
}

func (m *mockEnricher) Name() string { return m.name }
func (m *mockEnricher) Start(ctx context.Context) error { return nil }
func (m *mockEnricher) Stop() error { return nil }
func (m *mockEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    return m.enrichFunc(ctx, d)
}

func TestNmapMaxRetries(t *testing.T) {
    cache := inventory.NewCache()
    broker := api.NewBroker(cache)
    
    invocations := 0
    fallback := &mockEnricher{
        name: "nmap_mock",
        enrichFunc: func(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
            invocations++
            return nil, ErrNmapNoResults // Simulate nmap finding nothing
        },
    }

    orch := NewOrchestrator(cache, broker, nil, fallback, 0)
    
    dev := &models.Device{
        PDID:       "pdid_test_1",
        CurrentIP:  "192.168.1.50",
        Vendor:     "", 
        DeviceType: "",
    }
    cache.Upsert(dev)

    // Trigger 5 times with force=true to bypass the 1-hour cooldown, 
    // directly testing the max retry logic
    for i := 0; i < 5; i++ {
        orch.TriggerEnrichment(dev.PDID, true)
    }

    if invocations != 3 {
        t.Fatalf("Expected nmap to be invoked exactly 3 times, got %d", invocations)
    }
}
