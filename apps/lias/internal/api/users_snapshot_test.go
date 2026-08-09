package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/user/lias-dis/apps/lias/internal/policy"
	"github.com/user/lias-dis/apps/lias/internal/schedule"
	"github.com/user/lias-dis/apps/lias/internal/storage"
	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/apps/lias/internal/tags"
	"github.com/user/lias-dis/shared/models"
)

func newUserTestHandler(t *testing.T) (http.Handler, *liasSync.Cache) {
	t.Helper()
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveUser(models.User{ID: "persisted", Name: "Persisted User"}); err != nil {
		t.Fatal(err)
	}
	cache := liasSync.NewCache()
	cache.UpsertDevice(models.Device{PDID: "device-1", CurrentMAC: "02:00:00:00:00:01"})
	policies := policy.NewEngine()
	trigger := make(chan struct{}, 1)
	schedules := schedule.NewEngine(cache, policies, trigger)
	broker := NewBroker()
	t.Cleanup(broker.Stop)
	handlers := NewHandlers(cache, tags.NewManager(), policies, schedules, nil, store, trigger, broker)
	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux, "")
	return mux, cache
}

func TestUsersCRUDValidationAndLegacyUnassign(t *testing.T) {
	handler, cache := newUserTestHandler(t)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, path, strings.NewReader(body)))
		return recorder
	}
	listed := request(http.MethodGet, "/api/v1/users", "")
	var users []models.User
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &users) != nil || len(users) != 1 || users[0].ID != "persisted" {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	if invalid := request(http.MethodPost, "/api/v1/users", `{"name":"  "}`); invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid user status=%d", invalid.Code)
	}
	if unknown := request(http.MethodPost, "/api/v1/users", `{"name":"Child","unexpected":true}`); unknown.Code != http.StatusBadRequest || unknown.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unknown field status=%d type=%q body=%s", unknown.Code, unknown.Header().Get("Content-Type"), unknown.Body.String())
	}
	created := request(http.MethodPost, "/api/v1/users", `{"id":"child","name":"Child"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	if missingUser := request(http.MethodPost, "/api/v1/devices/device-1/user", `{"user_id":"missing"}`); missingUser.Code != http.StatusNotFound {
		t.Fatalf("missing user status=%d", missingUser.Code)
	}
	if assigned := request(http.MethodPost, "/api/v1/devices/device-1/user", `{"user_id":"child"}`); assigned.Code != http.StatusNoContent || cache.Get("device-1").UserID != "child" {
		t.Fatalf("assign status=%d device=%+v", assigned.Code, cache.Get("device-1"))
	}
	if conflict := request(http.MethodDelete, "/api/v1/users/child", ""); conflict.Code != http.StatusConflict {
		t.Fatalf("assigned delete status=%d", conflict.Code)
	}
	// Empty user_id remains a compatible unassign operation for old clients.
	if unassigned := request(http.MethodPost, "/api/v1/devices/device-1/user", `{"user_id":""}`); unassigned.Code != http.StatusNoContent || cache.Get("device-1").UserID != "" {
		t.Fatalf("legacy unassign status=%d device=%+v", unassigned.Code, cache.Get("device-1"))
	}
	if updated := request(http.MethodPut, "/api/v1/users/child", `{"name":"Teen"}`); updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	if deleted := request(http.MethodDelete, "/api/v1/users/child", ""); deleted.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestSnapshotETagAndRevision(t *testing.T) {
	handler, cache := newUserTestHandler(t)
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil))
	etag := first.Header().Get("ETag")
	if first.Code != http.StatusOK || etag == "" || !strings.Contains(first.Body.String(), `"users"`) {
		t.Fatalf("snapshot status=%d etag=%q body=%s", first.Code, etag, first.Body.String())
	}
	unchangedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil)
	unchangedRequest.Header.Set("If-None-Match", etag)
	unchanged := httptest.NewRecorder()
	handler.ServeHTTP(unchanged, unchangedRequest)
	if unchanged.Code != http.StatusNotModified {
		t.Fatalf("unchanged status=%d", unchanged.Code)
	}
	cache.SetFriendlyName("device-1", "Renamed")
	changedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil)
	changedRequest.Header.Set("If-None-Match", etag)
	changed := httptest.NewRecorder()
	handler.ServeHTTP(changed, changedRequest)
	if changed.Code != http.StatusOK || changed.Header().Get("ETag") == etag {
		t.Fatalf("changed status=%d old=%q new=%q", changed.Code, etag, changed.Header().Get("ETag"))
	}
}
