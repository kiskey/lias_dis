// Package nftables implements the isolated firewall controller for LIAS.
//
// File:    apps/lias/internal/nftables/sync.go
// Version: 1.1
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
// The trigger channel allows external components (like the API handlers) to
// request an immediate firewall resync.
func NewSync(b *Builder, p policy.PolicyEvaluator, s policy.ScheduleEvaluator, trigger chan struct{}) *Sync {
    return &Sync{
        builder: b,
        policy:  p,
        sched:   s,
        trigger: trigger,
    }
}

// Run starts the synchronization loop.
func (s *Sync) Run(ctx context.Context) {
    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()

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
