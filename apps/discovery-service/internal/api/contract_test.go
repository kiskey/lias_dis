package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	sharedapi "github.com/user/lias-dis/shared/api"
)

func newContractHandler(t *testing.T) http.Handler {
	t.Helper()
	cache := inventory.NewCache()
	broker := NewBroker(cache)
	t.Cleanup(broker.Stop)
	t.Cleanup(cache.Stop)
	mux := http.NewServeMux()
	NewHandlers(cache, broker, nil).RegisterRoutes(mux, "")
	return mux
}

func TestCapabilitiesRouteV1Contract(t *testing.T) {
	recorder := httptest.NewRecorder()
	newContractHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type=%q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "private, max-age=300" {
		t.Fatalf("cache control=%q", got)
	}
	var capabilities sharedapi.CapabilitiesResponse
	if err := json.NewDecoder(recorder.Body).Decode(&capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities.APIVersion != sharedapi.APIVersionV1 ||
		capabilities.SchemaVersion != sharedapi.APISchemaVersion ||
		capabilities.PublicDeviceKey != "pdid" ||
		len(capabilities.Features) == 0 {
		t.Fatalf("capabilities=%+v", capabilities)
	}
}

func TestLegacyDeviceListRouteContract(t *testing.T) {
	recorder := httptest.NewRecorder()
	newContractHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response sharedapi.DeviceListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Total != 0 || response.Devices == nil || len(response.Devices) != 0 {
		t.Fatalf("empty list contract changed: %+v", response)
	}
}

func TestCapabilitiesUsesExistingBearerAuthentication(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := NewBroker(cache)
	defer broker.Stop()
	mux := http.NewServeMux()
	NewHandlers(cache, broker, nil).RegisterRoutes(mux, "secret")

	unauthorized := httptest.NewRecorder()
	mux.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer secret")
	authorized := httptest.NewRecorder()
	mux.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized status=%d body=%s", authorized.Code, authorized.Body.String())
	}
}
