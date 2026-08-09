package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/user/lias-dis/apps/lias/internal/config"
	sharedapi "github.com/user/lias-dis/shared/api"
)

func TestIdentityGatewayNegotiatesAndForwardsAllowListedRoute(t *testing.T) {
	var sawAuthorization, sawQuery bool
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") == "Bearer dis-secret" {
			sawAuthorization = true
		}
		switch r.URL.Path {
		case "/api/v1/capabilities":
			payload, _ := json.Marshal(sharedapi.DISCapabilities())
			return testHTTPResponse(http.StatusOK, payload), nil
		case "/api/v1/identity/candidates":
			sawQuery = r.URL.Query().Get("status") == "pending" && r.URL.Query().Get("limit") == "10"
			return testHTTPResponse(http.StatusOK, []byte(`{"candidates":[]}`)), nil
		default:
			return testHTTPResponse(http.StatusNotFound, nil), nil
		}
	})
	client := NewDISClient(config.DISConfig{URL: "http://dis.test:8080", AuthToken: "dis-secret"}, NewCache(), make(chan struct{}, 1), nil, nil)
	client.client.Transport = transport
	client.refreshCapabilities(context.Background())
	snapshot := client.CapabilitiesSnapshot()
	if snapshot.DISCapabilities == nil || snapshot.SchemaVersion != sharedapi.APISchemaVersion || !snapshot.Upstream.Reachable {
		t.Fatalf("capabilities=%+v", snapshot)
	}
	response := client.ListIdentityCandidates(context.Background(), url.Values{"status": {"pending"}, "limit": {"10"}})
	if response.Status != http.StatusOK || !sawAuthorization || !sawQuery || string(response.Body) != `{"candidates":[]}` {
		t.Fatalf("response=%+v auth=%v query=%v", response, sawAuthorization, sawQuery)
	}
}

func TestIdentityGatewayLegacyAndUnavailableModes(t *testing.T) {
	client := NewDISClient(config.DISConfig{URL: "http://legacy.test:8080"}, NewCache(), make(chan struct{}, 1), nil, nil)
	client.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusNotFound, nil), nil
	})
	client.refreshCapabilities(context.Background())
	if response := client.GetIdentityCandidate(context.Background(), 1); response.Status != http.StatusNotImplemented || !strings.Contains(string(response.Body), "feature_not_supported") {
		t.Fatalf("legacy response=%+v", response)
	}
	unavailable := NewDISClient(config.DISConfig{URL: "http://unavailable.test:8080"}, NewCache(), make(chan struct{}, 1), nil, nil)
	unavailable.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})
	unavailable.refreshCapabilities(context.Background())
	if response := unavailable.GetIdentityCandidate(context.Background(), 1); response.Status != http.StatusServiceUnavailable || !strings.Contains(string(response.Body), "discovery_unavailable") {
		t.Fatalf("unavailable response=%+v", response)
	}
}

func TestIdentityGatewayEscapesPDIDPathSegment(t *testing.T) {
	var escapedPath string
	client := NewDISClient(config.DISConfig{URL: "http://dis.test:8080"}, NewCache(), make(chan struct{}, 1), nil, nil)
	client.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/capabilities" {
			payload, _ := json.Marshal(sharedapi.DISCapabilities())
			return testHTTPResponse(http.StatusOK, payload), nil
		}
		escapedPath = r.URL.EscapedPath()
		return testHTTPResponse(http.StatusOK, []byte(`{}`)), nil
	})
	client.refreshCapabilities(context.Background())
	response := client.GetIdentityProfile(context.Background(), "pdid/with slash")
	if response.Status != http.StatusOK || !strings.Contains(strings.ToLower(escapedPath), "pdid%2fwith%20slash") {
		t.Fatalf("status=%d escaped_path=%q", response.Status, escapedPath)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func testHTTPResponse(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(body))}
}
