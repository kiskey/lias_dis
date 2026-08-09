package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/user/lias-dis/apps/lias/internal/policy"
	"github.com/user/lias-dis/apps/lias/internal/schedule"
	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/apps/lias/internal/tags"
)

func newSessionTestHandler(t *testing.T, secure bool) http.Handler {
	t.Helper()
	cache := liasSync.NewCache()
	policies := policy.NewEngine()
	trigger := make(chan struct{}, 1)
	schedules := schedule.NewEngine(cache, policies, trigger)
	broker := NewBroker()
	t.Cleanup(broker.Stop)
	handlers := NewHandlers(cache, tags.NewManager(), policies, schedules, nil, nil, trigger, broker)
	handlers.SetSecureCookies(secure)
	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux, "dashboard-secret")
	return mux
}

func TestBrowserSessionRequiresCSRFForMutationsAndPreservesBearer(t *testing.T) {
	handler := newSessionTestHandler(t, false)

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"dashboard-secret"}`)))
	if login.Code != http.StatusNoContent {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body.String())
	}
	var sessionCookie, csrfCookie *http.Cookie
	for _, cookie := range login.Result().Cookies() {
		switch cookie.Name {
		case browserSessionCookie:
			sessionCookie = cookie
		case browserCSRFCookie:
			csrfCookie = cookie
		}
		if cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge < 7*60*60 {
			t.Fatalf("unsafe cookie attributes: %+v", cookie)
		}
	}
	if sessionCookie == nil || csrfCookie == nil || !sessionCookie.HttpOnly || csrfCookie.HttpOnly {
		t.Fatalf("unexpected session cookies: session=%+v csrf=%+v", sessionCookie, csrfCookie)
	}

	read := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	read.AddCookie(sessionCookie)
	readResult := httptest.NewRecorder()
	handler.ServeHTTP(readResult, read)
	if readResult.Code != http.StatusOK {
		t.Fatalf("cookie read status=%d body=%s", readResult.Code, readResult.Body.String())
	}

	withoutCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/vacation", strings.NewReader(`{"enabled":true}`))
	withoutCSRF.AddCookie(sessionCookie)
	withoutCSRF.AddCookie(csrfCookie)
	withoutResult := httptest.NewRecorder()
	handler.ServeHTTP(withoutResult, withoutCSRF)
	if withoutResult.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status=%d body=%s", withoutResult.Code, withoutResult.Body.String())
	}

	withCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/vacation", strings.NewReader(`{"enabled":true}`))
	withCSRF.AddCookie(sessionCookie)
	withCSRF.AddCookie(csrfCookie)
	withCSRF.Header.Set(browserCSRFHeader, csrfCookie.Value)
	withResult := httptest.NewRecorder()
	handler.ServeHTTP(withResult, withCSRF)
	if withResult.Code != http.StatusOK {
		t.Fatalf("csrf mutation status=%d body=%s", withResult.Code, withResult.Body.String())
	}

	bearer := httptest.NewRequest(http.MethodPost, "/api/v1/vacation", strings.NewReader(`{"enabled":false}`))
	bearer.Header.Set("Authorization", "Bearer dashboard-secret")
	bearerResult := httptest.NewRecorder()
	handler.ServeHTTP(bearerResult, bearer)
	if bearerResult.Code != http.StatusOK {
		t.Fatalf("bearer mutation status=%d body=%s", bearerResult.Code, bearerResult.Body.String())
	}
}

func TestBrowserSessionRejectsInvalidLoginAndSupportsSecureLogout(t *testing.T) {
	handler := newSessionTestHandler(t, true)
	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"wrong"}`)))
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid login status=%d", invalid.Code)
	}

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"dashboard-secret"}`)))
	cookies := login.Result().Cookies()
	if len(cookies) != 2 || !cookies[0].Secure || !cookies[1].Secure {
		t.Fatalf("secure cookies not set: %+v", cookies)
	}
	logout := httptest.NewRequest(http.MethodDelete, "/api/v1/session", nil)
	var csrf string
	for _, cookie := range cookies {
		logout.AddCookie(cookie)
		if cookie.Name == browserCSRFCookie {
			csrf = cookie.Value
		}
	}
	logout.Header.Set(browserCSRFHeader, csrf)
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, logout)
	if result.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d body=%s", result.Code, result.Body.String())
	}
}
