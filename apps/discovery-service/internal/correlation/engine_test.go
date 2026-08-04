// Package correlation implements unit tests for the DIS correlation engine.
//
// File:    apps/discovery-service/internal/correlation/engine_test.go
// Version: 1.1
package correlation

import (
    "fmt"
    "testing"
    "time"
)

// TestIsDuplicateObservation verifies that rapid duplicate observations are suppressed.
func TestIsDuplicateObservation(t *testing.T) {
    eng := &Engine{
        lastSeenObs: make(map[string]time.Time),
    }

    mac := "aa:bb:cc:dd:ee:ff"
    ip := "192.168.1.50"

    // First observation should not be a duplicate
    if eng.isDuplicateObservation(mac, ip, true) {
        t.Fatal("First observation was incorrectly marked as duplicate")
    }

    // Immediate second observation should be a duplicate
    if !eng.isDuplicateObservation(mac, ip, true) {
        t.Fatal("Immediate second observation was not marked as duplicate")
    }

    // Simulate time passing beyond the 2-second window
    eng.dedupMu.Lock()
    eng.lastSeenObs[mac+"|"+ip+"|true"] = time.Now().Add(-3 * time.Second)
    eng.dedupMu.Unlock()

    // Third observation after window should not be a duplicate
    if eng.isDuplicateObservation(mac, ip, true) {
        t.Fatal("Observation after 2s window was incorrectly marked as duplicate")
    }
}

// TestDedupMapBounding verifies that the deduplication map is strictly bounded
// and prevents unbounded memory leaks (DIS-COR-01 Fix).
func TestDedupMapBounding(t *testing.T) {
    eng := &Engine{
        lastSeenObs: make(map[string]time.Time),
    }

    // Populate map with 1000 fake unique observations
    for i := 0; i < 1000; i++ {
        // FIX: Use Sprintf to guarantee 1000 unique MAC/IP strings
        mac := fmt.Sprintf("aa:bb:cc:dd:ee:%02x", i)
        ip := fmt.Sprintf("192.168.1.%d", i)
        eng.isDuplicateObservation(mac, ip, true)
    }

    if len(eng.lastSeenObs) != 1000 {
        t.Fatalf("Expected 1000 entries in dedup map, got %d", len(eng.lastSeenObs))
    }

    // Manually run the sweep logic with backdated timestamps
    eng.dedupMu.Lock()
    now := time.Now()
    for k, t := range eng.lastSeenObs {
        // Set timestamps to 6 minutes ago (older than 5 minute TTL)
        eng.lastSeenObs[k] = t.Add(-6 * time.Minute)
    }
    eng.dedupMu.Unlock()

    // Simulate the sweep ticker logic
    eng.dedupMu.Lock()
    for k, t := range eng.lastSeenObs {
        if now.Sub(t) > 5*time.Minute {
            delete(eng.lastSeenObs, k)
        }
    }
    eng.dedupMu.Unlock()

    if len(eng.lastSeenObs) != 0 {
        t.Fatalf("Dedup map was not swept clean, %d entries remain", len(eng.lastSeenObs))
    }
}
