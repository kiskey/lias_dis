package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	disapi "github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/correlation"
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/apps/discovery-service/internal/storage"
	"github.com/user/lias-dis/shared/models"
)

func TestCandidateListAndDetailRoutes(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := disapi.NewBroker(cache)
	defer broker.Stop()
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := correlation.NewEngine(cache, broker)
	engine.SetStorage(store)
	now := time.Now()
	for _, device := range []*models.Device{
		{DeviceID: "source-device", PDID: "source", Hostname: "New Phone", FirstSeen: now, LastSeen: now},
		{DeviceID: "target-device", PDID: "target", FriendlyName: "Known Phone", FirstSeen: now, LastSeen: now},
	} {
		if err := store.SaveDevice(device); err != nil {
			t.Fatal(err)
		}
		cache.Upsert(device)
	}
	id, err := store.UpsertIdentityCandidate(models.IdentityCandidateLink{SourcePDID: "source", TargetPDID: "target", Probability: .83, Ambiguous: true})
	if err != nil {
		t.Fatal(err)
	}
	handlers := disapi.NewHandlers(cache, broker, nil)
	handlers.SetIdentityManager(engine)
	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux, "")

	list := httptest.NewRecorder()
	mux.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/v1/identity/candidates?status=pending&limit=1", nil))
	if list.Code != http.StatusOK || list.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	var response models.IdentityCandidateListResponse
	if err := json.NewDecoder(list.Body).Decode(&response); err != nil || len(response.Candidates) != 1 || response.Candidates[0].SourceDevice == nil {
		t.Fatalf("list=%+v err=%v", response, err)
	}

	detail := httptest.NewRecorder()
	mux.ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/api/v1/identity/candidates/"+jsonNumber(id), nil))
	if detail.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", detail.Code, detail.Body.String())
	}

	badLimit := httptest.NewRecorder()
	mux.ServeHTTP(badLimit, httptest.NewRequest(http.MethodGet, "/api/v1/identity/candidates?limit=101", nil))
	if badLimit.Code != http.StatusBadRequest || badLimit.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("bad limit status=%d body=%s", badLimit.Code, badLimit.Body.String())
	}
}

func jsonNumber(value int64) string {
	data, _ := json.Marshal(value)
	return string(data)
}
