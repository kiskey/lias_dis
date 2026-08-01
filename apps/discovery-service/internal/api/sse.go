// Package api implements the HTTP server, middleware, and SSE broker for DIS.
//
// File:    apps/discovery-service/internal/api/sse.go
// Version: 1.0
package api

import (
    "log/slog"
    "sync"

    "github.com/user/lias-dis/shared/models"
)

// Client represents a connected SSE consumer.
type Client struct {
    ID     string
    Events chan models.Event
}

// Broker manages connected SSE clients and broadcasts events to them.
type Broker struct {
    mu      sync.RWMutex
    clients map[string]*Client
}

// NewBroker initializes a new SSE broker.
func NewBroker() *Broker {
    return &Broker{
        clients: make(map[string]*Client),
    }
}

// Subscribe registers a new SSE client and returns it.
func (b *Broker) Subscribe(clientID string) *Client {
    b.mu.Lock()
    defer b.mu.Unlock()

    client := &Client{
        ID:     clientID,
        Events: make(chan models.Event, 64), // Buffered to prevent slow consumers blocking the broker
    }
    b.clients[clientID] = client
    slog.Info("SSE client subscribed", "client_id", clientID, "total_clients", len(b.clients))
    return client
}

// Unsubscribe removes a client and closes its event channel.
func (b *Broker) Unsubscribe(clientID string) {
    b.mu.Lock()
    defer b.mu.Unlock()

    if client, ok := b.clients[clientID]; ok {
        close(client.Events)
        delete(b.clients, clientID)
        slog.Info("SSE client unsubscribed", "client_id", clientID, "total_clients", len(b.clients))
    }
}

// Broadcast sends an event to all connected clients.
// If a client's buffer is full, the event is dropped for that client to
// prevent a slow consumer from blocking the entire discovery pipeline.
func (b *Broker) Broadcast(event models.Event) {
    b.mu.RLock()
    defer b.mu.RUnlock()

    for _, client := range b.clients {
        select {
        case client.Events <- event:
        default:
            slog.Warn("SSE client buffer full, dropping event", "client_id", client.ID, "event_type", event.Type)
        }
    }
}
