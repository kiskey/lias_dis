// Package api implements the HTTP server, REST handlers, and SSE broker for LIAS.
//
// File:    apps/lias/internal/api/broker.go
// Version: 1.1 (Added ResetBackoff channel for SSE)
package api

import (
    "log/slog"
    "sync"
    "time"

    "github.com/user/lias-dis/shared/models"
)

const historyBufferCapacity = 100

type Client struct {
    ID     string
    Events chan models.Event
}

// Broker manages real-time SSE stream client connections for the LIAS Web Dashboard.
type Broker struct {
    mu           sync.RWMutex
    clients      map[string]*Client
    history      []models.Event
    histHead     int
    stopPing     chan struct{}
    ResetBackoff chan struct{} // CPU-05 Fix: Channel to signal SSE backoff reset
}

func NewBroker() *Broker {
    b := &Broker{
        clients:      make(map[string]*Client),
        history:      make([]models.Event, 0, historyBufferCapacity),
        stopPing:     make(chan struct{}),
        ResetBackoff: make(chan struct{}, 1),
    }
    go b.pingLoop()
    return b
}

func (b *Broker) pingLoop() {
    ticker := time.NewTicker(15 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-b.stopPing:
            return
        case <-ticker.C:
            b.mu.RLock()
            pingEvent := models.Event{
                Type:      models.EventType("ping"),
                Timestamp: time.Now(),
            }
            for _, client := range b.clients {
                select {
                case client.Events <- pingEvent:
                default:
                }
            }
            b.mu.RUnlock()
        }
    }
}

func (b *Broker) Subscribe(clientID string, lastEventID int64) *Client {
    b.mu.Lock()
    defer b.mu.Unlock()

    client := &Client{
        ID:     clientID,
        Events: make(chan models.Event, 128),
    }
    b.clients[clientID] = client
    slog.Info("LIAS SSE client subscribed", "client_id", clientID, "total_clients", len(b.clients))

    if lastEventID > 0 {
        b.replayEventsLocked(client, lastEventID)
    }

    return client
}

func (b *Broker) Unsubscribe(clientID string) {
    b.mu.Lock()
    defer b.mu.Unlock()

    if client, ok := b.clients[clientID]; ok {
        close(client.Events)
        delete(b.clients, clientID)
        slog.Info("LIAS SSE client unsubscribed", "client_id", clientID, "total_clients", len(b.clients))
    }
}

func (b *Broker) Broadcast(event models.Event) {
    b.mu.Lock()
    defer b.mu.Unlock()

    if len(b.history) < historyBufferCapacity {
        b.history = append(b.history, event)
    } else {
        b.history[b.histHead] = event
        b.histHead = (b.histHead + 1) % historyBufferCapacity
    }

    for _, client := range b.clients {
        select {
        case client.Events <- event:
        default:
            slog.Warn("LIAS SSE client buffer full, dropping real-time event", "client_id", client.ID, "event_type", event.Type)
        }
    }
}

func (b *Broker) replayEventsLocked(client *Client, lastEventID int64) {
    count := 0
    for _, evt := range b.history {
        if evt.Timestamp.UnixNano() > lastEventID {
            select {
            case client.Events <- evt:
                count++
            default:
                slog.Warn("LIAS SSE client replay buffer full", "client_id", client.ID)
                return
            }
        }
    }
    if count > 0 {
        slog.Info("Replayed missed SSE events for LIAS client", "client_id", client.ID, "count", count)
    }
}

func (b *Broker) Stop() {
    close(b.stopPing)
}
