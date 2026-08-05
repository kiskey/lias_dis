// Package reporting provides asynchronous flow logging and analytics collection.
//
// File:    apps/lias/internal/reporting/reporting.go
// Version: 1.0
package reporting

import (
    "log/slog"
    "sync"

    "github.com/user/lias-dis/apps/lias/internal/storage"
    "github.com/user/lias-dis/shared/models"
)

// StatsCollector asynchronously records policy decisions to the database.
type StatsCollector struct {
    store *storage.Storage
    queue chan models.FlowLog
    wg    sync.WaitGroup
}

// NewStatsCollector initializes the collector.
func NewStatsCollector(store *storage.Storage, bufferSize int) *StatsCollector {
    if bufferSize <= 0 {
        bufferSize = 1024
    }
    sc := &StatsCollector{
        store: store,
        queue: make(chan models.FlowLog, bufferSize),
    }
    sc.wg.Add(1)
    go sc.run()
    return sc
}

// RecordEvent queues a flow log entry. Non-blocking; drops if queue is full.
func (sc *StatsCollector) RecordEvent(pdid string, action models.Action, bytes int64) {
    if sc == nil || sc.store == nil {
        return
    }

    log := models.FlowLog{
        PDID:   pdid,
        Action: action,
        Bytes:  bytes,
    }

    select {
    case sc.queue <- log:
    default:
        slog.Warn("Reporting queue full, dropping flow log", "pdid", pdid)
    }
}

func (sc *StatsCollector) run() {
    defer sc.wg.Done()

    for log := range sc.queue {
        if err := sc.store.SaveFlowLog(log.PDID, log.Action, log.Bytes); err != nil {
            slog.Error("Failed to save flow log", "pdid", log.PDID, "error", err)
        }
    }
}

// Stop gracefully drains the queue and shuts down the collector.
func (sc *StatsCollector) Stop() {
    if sc == nil {
        return
    }
    close(sc.queue)
    sc.wg.Wait()
}
