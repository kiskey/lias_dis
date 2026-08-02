// Package nftables implements the isolated firewall controller for LIAS.
//
// File:    apps/lias/internal/nftables/sync.go
// Version: 1.3
package nftables

import (
	"context"
	"log/slog"
	"time"

	"github.com/user/lias-dis/apps/lias/internal/policy"
)

// Sync coordinates periodic and trigger-driven netfilter set synchronization.
type Sync struct {
	builder *Builder
	policy  policy.PolicyEvaluator
	sched   policy.ScheduleEvaluator
	trigger chan struct{}
}

// NewSync initializes the synchronization engine.
func NewSync(b *Builder, p policy.PolicyEvaluator, s policy.ScheduleEvaluator, trigger chan struct{}) *Sync {
	return &Sync{
		builder: b,
		policy:  p,
		sched:   s,
		trigger: trigger,
	}
}

// Run starts the background sync loop.
func (s *Sync) Run(ctx context.Context) {
	// 10-second self-healing ticker to protect against external netfilter flushes
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

func (s *Sync) resync() {
	if err := s.builder.Sync(s.policy, s.sched); err != nil {
		slog.Error("Failed to synchronize nftables rules", "error", err)
	}
}
