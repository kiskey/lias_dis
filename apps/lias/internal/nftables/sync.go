// Package nftables implements the isolated firewall controller for LIAS.
//
// File:    apps/lias/internal/nftables/sync.go
// Version: 1.2
package nftables

import (
    "context"
    "log/slog"
    "time"

    "github.com/user/lias-dis/apps/lias/internal/policy"
)

// Sync coordinates the evaluation of policies and schedules, triggering
// the Builder to update nftables rules whenever state changes.
type Sync struct {
    builder *Builder
    policy  policy.PolicyEvaluator
    sched   policy.ScheduleEvaluator
    trigger chan struct{}
}

// NewSync initializes the synchronization loop.
func NewSync(b *Builder, p policy.PolicyEvaluator, s policy.ScheduleEvaluator, trigger chan struct{}) *Sync {
    return &Sync{
        builder: b,
        policy:  p,
        sched:   s,
        trigger: trigger,
    }
}

// Run starts the synchronization loop.
// It resyncs immediately when triggered, and falls back to a 10-second
// periodic self-healing resync to protect against external table flushes.
func (s *Sync) Run(ctx context.Context) {
    // 10-second self-healing ticker
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    // Initial sync on startup
    s.resync()

    for {
        select {
        case <-ctx.Done():
            return
        case <-s.trigger:
            s.resync()
        case <-ticker.C:
            s.resync()
        }
    }
}

// resync executes the builder and logs any errors.
func (s *Sync) resync() {
    if err := s.builder.Sync(s.policy, s.sched); err != nil {
        slog.Error("Failed to sync nftables rules", "error", err)
    }
}
