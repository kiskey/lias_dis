package identitymigration

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/user/lias-dis/apps/lias/internal/policy"
	"github.com/user/lias-dis/apps/lias/internal/storage"
	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/shared/models"
)

// Coordinator is the only LIAS entry point for device.reidentified. It
// serializes events so storage, policy memory, and device memory reconcile in
// deterministic commit order.
type Coordinator struct {
	mu       sync.Mutex
	store    *storage.Storage
	cache    *liasSync.Cache
	policies *policy.Engine
}

func New(store *storage.Storage, cache *liasSync.Cache, policies *policy.Engine) *Coordinator {
	return &Coordinator{store: store, cache: cache, policies: policies}
}

func (c *Coordinator) MigrateIdentity(oldPDID, newPDID string, migratedMACs []string) (liasSync.MigrationResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if oldPDID == "" || newPDID == "" || oldPDID == newPDID {
		return liasSync.MigrationResult{}, fmt.Errorf("invalid identity migration")
	}
	if c.store == nil {
		// Memory-only mode cannot provide crash recovery, but it must still stop
		// enforcing against the obsolete PDID immediately.
		var migrated []models.Policy
		for _, item := range c.policies.ListPolicies() {
			if item.Type == models.PolicyTypeDevice && item.TargetID == oldPDID {
				item.TargetID = newPDID
				for _, prefix := range []string{"pol_pause_", "pol_extend_device_"} {
					if item.ID == prefix+oldPDID {
						item.ID = prefix + newPDID
					}
				}
				migrated = append(migrated, item)
			} else if item.Type == models.PolicyTypeDevice && item.TargetID == newPDID {
				migrated = append(migrated, item)
			}
		}
		c.policies.ReconcileDeviceIdentity(oldPDID, newPDID, migrated)
		c.cache.MigrateDeviceIdentity(oldPDID, newPDID, migratedMACs)
		return liasSync.MigrationResult{}, nil
	}
	committed, err := c.store.MigrateIdentityState(oldPDID, newPDID)
	if err != nil {
		return liasSync.MigrationResult{}, err
	}
	c.policies.ReconcileDeviceIdentity(oldPDID, newPDID, committed.Policies)
	c.cache.ReconcileIdentityMigration(oldPDID, newPDID, migratedMACs, committed.Tags, committed.FriendlyName, committed.UserID)
	for _, conflict := range committed.Conflicts {
		slog.Warn("LIAS identity migration conflict recorded", "old_pdid", oldPDID, "new_pdid", newPDID,
			"object_type", conflict.ObjectType, "winner_id", conflict.WinnerID, "loser_id", conflict.LoserID)
	}
	return liasSync.MigrationResult{Conflicts: len(committed.Conflicts), Replayed: committed.Replayed}, nil
}
