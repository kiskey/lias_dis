// Package api implements the HTTP server, middleware, and SSE broker for DIS.
//
// File:    apps/discovery-service/internal/api/sse.go
// Version: 2.0
package api

import (
	"log/slog"
	"sync"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/shared/models"
)

const historyBufferCapacity = 100

type Client struct {
	ID     string
	Events chan models.Event
}

type Broker struct {
	mu       sync.RWMutex
	cache    *inventory.Cache
	clients  map[string]*Client
	history  []models.Event
	histHead int
	stopPing chan struct{}
}

func NewBroker(cache *inventory.Cache) *Broker {
	b := &Broker{
		cache:    cache,
		clients:  make(map[string]*Client),
		history:  make([]models.Event, 0, historyBufferCapacity),
		stopPing: make(chan struct{}),
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
	slog.Info("SSE client subscribed", "client_id", clientID, "total_clients", len(b.clients))

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
		slog.Info("SSE client unsubscribed", "client_id", clientID, "total_clients", len(b.clients))
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
			slog.Warn("SSE client buffer full, dropping real-time event", "client_id", client.ID, "event_type", event.Type)
		}
	}
}

func (b *Broker) replayEventsLocked(client *Client, lastEventID int64) {
	count := 0
	for _, evt := range b.history {
		if evt.Timestamp.UnixNano() > lastEventID {
			// Suppress device.online replays for devices currently online to prevent reconnect bursts
			if evt.Type == models.EventDeviceOnline && b.cache != nil {
				if dev := b.cache.Get(evt.DeviceID); dev != nil && dev.Online {
					continue
				}
			}

			select {
			case client.Events <- evt:
				count++
			default:
				slog.Warn("SSE client replay buffer full", "client_id", client.ID)
				return
			}
		}
	}
	if count > 0 {
		slog.Info("Replayed missed SSE events for client", "client_id", client.ID, "count", count)
	}
}
