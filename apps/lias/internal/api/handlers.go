// Package api implements the HTTP server and REST handlers for LIAS.
//
// File:    apps/lias/internal/api/handlers.go
// Version: 1.5
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	liasNftables "github.com/user/lias-dis/apps/lias/internal/nftables"
	"github.com/user/lias-dis/apps/lias/internal/policy"
	"github.com/user/lias-dis/apps/lias/internal/schedule"
	"github.com/user/lias-dis/apps/lias/internal/storage"
	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/apps/lias/internal/tags"
	"github.com/user/lias-dis/shared/api"
	"github.com/user/lias-dis/shared/models"
)

type Handlers struct {
	cache    *liasSync.Cache
	tagMgr   *tags.Manager
	polEng   *policy.Engine
	schedEng *schedule.Engine
	nftCtrl  *liasNftables.Controller
	store    *storage.Storage
	trigger  chan struct{}
}

func NewHandlers(
	cache *liasSync.Cache,
	tagMgr *tags.Manager,
	polEng *policy.Engine,
	schedEng *schedule.Engine,
	nftCtrl *liasNftables.Controller,
	store *storage.Storage,
	trigger chan struct{},
) *Handlers {
	return &Handlers{
		cache:    cache,
		tagMgr:   tagMgr,
		polEng:   polEng,
		schedEng: schedEng,
		nftCtrl:  nftCtrl,
		store:    store,
		trigger:  trigger,
	}
}

func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/devices", h.ListDevices)
	mux.HandleFunc("GET /api/v1/devices/{pdid}", h.GetDevice)
	mux.HandleFunc("POST /api/v1/devices/{pdid}/tags", h.AssignDeviceTag)

	mux.HandleFunc("GET /api/v1/tags", h.ListTags)
	mux.HandleFunc("POST /api/v1/tags", h.CreateTag)
	mux.HandleFunc("PUT /api/v1/tags/{id}", h.UpdateTag)
	mux.HandleFunc("DELETE /api/v1/tags/{id}", h.DeleteTag)

	mux.HandleFunc("GET /api/v1/policies", h.ListPolicies)
	mux.HandleFunc("POST /api/v1/policies", h.CreatePolicy)
	mux.HandleFunc("PUT /api/v1/policies/{id}", h.UpdatePolicy)
	mux.HandleFunc("DELETE /api/v1/policies/{id}", h.DeletePolicy)

	mux.HandleFunc("GET /api/v1/schedules", h.ListSchedules)
	mux.HandleFunc("POST /api/v1/schedules", h.CreateSchedule)
	mux.HandleFunc("PUT /api/v1/schedules/{id}", h.UpdateSchedule)
	mux.HandleFunc("DELETE /api/v1/schedules/{id}", h.DeleteSchedule)

	mux.HandleFunc("POST /api/v1/nftables/flush", h.FlushNftables)
}

func (h *Handlers) tryTrigger() {
	select {
	case h.trigger <- struct{}{}:
	default:
	}
}

func (h *Handlers) ListDevices(w http.ResponseWriter, r *http.Request) {
	localDevs := h.cache.List()
	devs := make([]models.Device, 0, len(localDevs))
	for _, ld := range localDevs {
		dev := ld.Device
		dev.Tags = ld.Tags // Copy local LIAS assigned tags onto outer device representation!
		devs = append(devs, dev)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(api.DeviceListResponse{
		Devices: devs,
		Total:   len(devs),
	})
}

func (h *Handlers) GetDevice(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	d := h.cache.Get(pdid)
	if d == nil {
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
		return
	}
	dev := d.Device
	dev.Tags = d.Tags // Synchronize tags on single device query

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dev)
}

func (h *Handlers) AssignDeviceTag(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	var req struct {
		TagID string `json:"tag_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	h.cache.SetTags(pdid, []string{req.TagID})

	d := h.cache.Get(pdid)
	mac := ""
	if d != nil {
		mac = d.CurrentMAC
	}

	if h.store != nil {
		_ = h.store.SaveDeviceTag(pdid, req.TagID, mac)
	}

	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListTags(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.tagMgr.List())
}

func (h *Handlers) CreateTag(w http.ResponseWriter, r *http.Request) {
	var t tags.Tag
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	created, err := h.tagMgr.Create(t.Name, t.Color)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	if h.store != nil {
		_ = h.store.SaveTag(created)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func (h *Handlers) UpdateTag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var t tags.Tag
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	updated, err := h.tagMgr.Update(id, t.Name, t.Color)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	if h.store != nil {
		_ = h.store.SaveTag(updated)
	}

	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func (h *Handlers) DeleteTag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.tagMgr.Delete(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	if h.store != nil {
		_ = h.store.DeleteTag(id)
	}

	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListPolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.polEng.ListPolicies())
}

func (h *Handlers) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var p models.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if p.ID == "" {
		p.ID = "pol_" + generateID()
	}
	h.polEng.UpsertPolicy(p)

	if h.store != nil {
		_ = h.store.SavePolicy(p)
	}

	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(p)
}

func (h *Handlers) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var p models.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	p.ID = id
	h.polEng.UpsertPolicy(p)

	if h.store != nil {
		_ = h.store.SavePolicy(p)
	}

	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (h *Handlers) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.polEng.DeletePolicy(id)

	if h.store != nil {
		_ = h.store.DeletePolicy(id)
	}

	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListSchedules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.schedEng.ListSchedules())
}

func (h *Handlers) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	var s models.Schedule
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if s.ID == "" {
		s.ID = "sched_" + generateID()
	}
	h.schedEng.UpsertSchedule(s)

	if h.store != nil {
		_ = h.store.SaveSchedule(s)
	}

	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(s)
}

func (h *Handlers) UpdateSchedule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var s models.Schedule
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	s.ID = id
	h.schedEng.UpsertSchedule(s)

	if h.store != nil {
		_ = h.store.SaveSchedule(s)
	}

	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}

func (h *Handlers) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.schedEng.DeleteSchedule(id)

	if h.store != nil {
		_ = h.store.DeleteSchedule(id)
	}

	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) FlushNftables(w http.ResponseWriter, r *http.Request) {
	if err := h.nftCtrl.FlushTable(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
