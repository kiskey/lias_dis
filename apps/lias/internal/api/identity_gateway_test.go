package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/user/lias-dis/apps/lias/internal/policy"
	"github.com/user/lias-dis/apps/lias/internal/schedule"
	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/apps/lias/internal/tags"
	sharedapi "github.com/user/lias-dis/shared/api"
)

type gatewayStub struct{}

func (gatewayStub) CapabilitiesSnapshot() sharedapi.LIASCapabilitiesResponse {
	return sharedapi.LIASCapabilitiesResponse{CapabilitiesResponse: sharedapi.CapabilitiesResponse{APIVersion: "v1", Features: []string{sharedapi.FeatureIdentityCandidates}}}
}
func (gatewayStub) SystemStatus() sharedapi.SystemStatusResponse {
	return sharedapi.SystemStatusResponse{Status: "ok", APIVersion: "v1"}
}
func (gatewayStub) response() liasSync.GatewayResponse {
	return liasSync.GatewayResponse{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{}`)}
}
func (g gatewayStub) ListIdentityCandidates(context.Context, url.Values) liasSync.GatewayResponse {
	return g.response()
}
func (g gatewayStub) GetIdentityCandidate(context.Context, int64) liasSync.GatewayResponse {
	return g.response()
}
func (g gatewayStub) GetIdentityProfile(context.Context, string) liasSync.GatewayResponse {
	return g.response()
}
func (g gatewayStub) BindIdentity(context.Context, string, []byte) liasSync.GatewayResponse {
	return g.response()
}
func (g gatewayStub) RevokeIdentity(context.Context, string, int64) liasSync.GatewayResponse {
	return g.response()
}
func (g gatewayStub) DecideIdentityCandidate(context.Context, int64, string, []byte) liasSync.GatewayResponse {
	return g.response()
}
func (g gatewayStub) SplitIdentity(context.Context, string, []byte) liasSync.GatewayResponse {
	return g.response()
}

func TestIdentityGatewayRouteMatrixIsAdditiveAndAuthenticated(t *testing.T) {
	cache := liasSync.NewCache()
	policyEngine := policy.NewEngine()
	trigger := make(chan struct{}, 1)
	scheduleEngine := schedule.NewEngine(cache, policyEngine, trigger)
	broker := NewBroker()
	defer broker.Stop()
	handlers := NewHandlers(cache, tags.NewManager(), policyEngine, scheduleEngine, nil, nil, trigger, broker)
	handlers.SetIdentityGateway(gatewayStub{})
	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux, "lias-secret")

	tests := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/capabilities", ""},
		{http.MethodGet, "/api/v1/system/status", ""},
		{http.MethodGet, "/api/v1/identity/candidates?status=pending&limit=10", ""},
		{http.MethodGet, "/api/v1/identity/candidates/1", ""},
		{http.MethodPost, "/api/v1/identity/candidates/1/confirm", ""},
		{http.MethodPost, "/api/v1/identity/candidates/1/reject", `{}`},
		{http.MethodPost, "/api/v1/identity/candidates/1/reopen", `{}`},
		{http.MethodGet, "/api/v1/devices/pdid-1/identity", ""},
		{http.MethodPost, "/api/v1/devices/pdid-1/identity/bindings", `{"type":"mac","value":"02:00:00:00:00:01"}`},
		{http.MethodDelete, "/api/v1/devices/pdid-1/identity/bindings/1", ""},
		{http.MethodPost, "/api/v1/devices/pdid-1/identity/split", `{"mac":"02:00:00:00:00:01"}`},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer lias-secret")
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}

	unauthorized := httptest.NewRecorder()
	mux.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/identity/candidates", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("identity route bypassed LIAS auth: %d", unauthorized.Code)
	}
}
