package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	sharedapi "github.com/user/lias-dis/shared/api"
)

const maxIdentityGatewayResponseBytes = 2 << 20

type GatewayResponse struct {
	Status      int
	ContentType string
	Body        []byte
}

func (c *DISClient) capabilityLoop(ctx context.Context) {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refreshCapabilities(ctx)
		}
	}
}

func (c *DISClient) refreshCapabilities(ctx context.Context) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.getEndpointURL("/api/v1/capabilities"), nil)
	if err != nil {
		c.recordUpstreamError(err)
		return
	}
	if c.cfg.AuthToken != "" {
		request.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}
	response, err := c.client.Do(request)
	now := time.Now()
	if err != nil {
		c.recordUpstreamError(err)
		c.stateMu.Lock()
		c.upstream.LastCapabilityCheck = now
		c.stateMu.Unlock()
		return
	}
	defer response.Body.Close()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.upstream.LastCapabilityCheck = now
	if response.StatusCode == http.StatusNotFound {
		c.disCapabilities = nil
		c.upstream.Reachable = true
		c.upstream.LegacyMode = true
		c.upstream.LastError = ""
		return
	}
	if response.StatusCode != http.StatusOK {
		c.upstream.Reachable = false
		c.upstream.LastError = fmt.Sprintf("capabilities status %d", response.StatusCode)
		return
	}
	var capabilities sharedapi.CapabilitiesResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 128<<10))
	if err := decoder.Decode(&capabilities); err != nil {
		c.upstream.Reachable = false
		c.upstream.LastError = "invalid capabilities response"
		return
	}
	c.disCapabilities = &capabilities
	c.upstream.Reachable = true
	c.upstream.LegacyMode = false
	c.upstream.LastError = ""
}

func (c *DISClient) recordUpstreamError(err error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.upstream.Reachable = false
	if err != nil {
		c.upstream.LastError = "discovery_unavailable"
	}
}

func (c *DISClient) CapabilitiesSnapshot() sharedapi.LIASCapabilitiesResponse {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	features := []string{sharedapi.FeatureDeviceInventory, sharedapi.FeatureSnapshotV1, sharedapi.FeatureSSEEvents, sharedapi.FeatureSSEReplay}
	if c.disCapabilities != nil {
		for _, feature := range c.disCapabilities.Features {
			switch feature {
			case sharedapi.FeatureAuthenticatedIdentity, sharedapi.FeatureIdentityBindings,
				sharedapi.FeatureIdentityCandidates, sharedapi.FeatureIdentityCandidateQueue,
				sharedapi.FeatureIdentityCandidateReopen, sharedapi.FeatureIdentitySplit:
				features = append(features, feature)
			}
		}
	}
	base := sharedapi.CapabilitiesResponse{APIVersion: sharedapi.APIVersionV1, SchemaVersion: sharedapi.APISchemaVersion,
		MinClientAPIVersion: sharedapi.APIVersionV1, PublicDeviceKey: "pdid", ResponseCompatibility: "additive", Features: features}
	var dis *sharedapi.CapabilitiesResponse
	if c.disCapabilities != nil {
		copy := *c.disCapabilities
		copy.Features = append([]string(nil), c.disCapabilities.Features...)
		dis = &copy
	}
	return sharedapi.LIASCapabilitiesResponse{CapabilitiesResponse: base, DISCapabilities: dis, Upstream: c.upstream}
}

func (c *DISClient) SystemStatus() sharedapi.SystemStatusResponse {
	snapshot := c.CapabilitiesSnapshot()
	status := "ok"
	if !snapshot.Upstream.Reachable {
		status = "degraded"
	}
	return sharedapi.SystemStatusResponse{Status: status, APIVersion: sharedapi.APIVersionV1,
		SchemaVersion: sharedapi.APISchemaVersion, Upstream: snapshot.Upstream}
}

func (c *DISClient) ListIdentityCandidates(ctx context.Context, query url.Values) GatewayResponse {
	return c.identityRequest(ctx, http.MethodGet, "/api/v1/identity/candidates", query, nil, sharedapi.FeatureIdentityCandidateQueue)
}

func (c *DISClient) GetIdentityCandidate(ctx context.Context, id int64) GatewayResponse {
	return c.identityRequest(ctx, http.MethodGet, "/api/v1/identity/candidates/"+strconv.FormatInt(id, 10), nil, nil, sharedapi.FeatureIdentityCandidateQueue)
}

func (c *DISClient) GetIdentityProfile(ctx context.Context, pdid string) GatewayResponse {
	return c.identityRequest(ctx, http.MethodGet, "/api/v1/devices/"+url.PathEscape(pdid)+"/identity", nil, nil, sharedapi.FeatureIdentityCandidates)
}

func (c *DISClient) BindIdentity(ctx context.Context, pdid string, body []byte) GatewayResponse {
	return c.identityRequest(ctx, http.MethodPost, "/api/v1/devices/"+url.PathEscape(pdid)+"/identity/bindings", nil, body, sharedapi.FeatureIdentityBindings)
}

func (c *DISClient) RevokeIdentity(ctx context.Context, pdid string, aliasID int64) GatewayResponse {
	return c.identityRequest(ctx, http.MethodDelete, "/api/v1/devices/"+url.PathEscape(pdid)+"/identity/bindings/"+strconv.FormatInt(aliasID, 10), nil, nil, sharedapi.FeatureIdentityBindings)
}

func (c *DISClient) DecideIdentityCandidate(ctx context.Context, id int64, action string, body []byte) GatewayResponse {
	feature := sharedapi.FeatureIdentityCandidates
	if action == "reopen" {
		feature = sharedapi.FeatureIdentityCandidateReopen
	}
	return c.identityRequest(ctx, http.MethodPost, "/api/v1/identity/candidates/"+strconv.FormatInt(id, 10)+"/"+action, nil, body, feature)
}

func (c *DISClient) SplitIdentity(ctx context.Context, pdid string, body []byte) GatewayResponse {
	return c.identityRequest(ctx, http.MethodPost, "/api/v1/devices/"+url.PathEscape(pdid)+"/identity/split", nil, body, sharedapi.FeatureIdentitySplit)
}

func (c *DISClient) identityRequest(ctx context.Context, method, path string, query url.Values, body []byte, feature string) GatewayResponse {
	available, reachable := c.featureAvailability(feature)
	if !reachable {
		return gatewayError(http.StatusServiceUnavailable, "discovery_unavailable", true)
	}
	if !available {
		return gatewayError(http.StatusNotImplemented, "feature_not_supported", false)
	}
	target := c.getEndpointURL(path)
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return gatewayError(http.StatusBadGateway, "discovery_request_failed", true)
	}
	if c.cfg.AuthToken != "" {
		request.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		c.recordUpstreamError(err)
		return gatewayError(http.StatusServiceUnavailable, "discovery_unavailable", true)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxIdentityGatewayResponseBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil || len(payload) > maxIdentityGatewayResponseBytes {
		return gatewayError(http.StatusBadGateway, "invalid_discovery_response", true)
	}
	contentType := response.Header.Get("Content-Type")
	if contentType == "" && len(payload) > 0 {
		contentType = "application/json"
	}
	return GatewayResponse{Status: response.StatusCode, ContentType: contentType, Body: payload}
}

func (c *DISClient) featureAvailability(feature string) (available, reachable bool) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	if !c.upstream.Reachable && !c.upstream.LegacyMode {
		return false, false
	}
	if c.upstream.LegacyMode || c.disCapabilities == nil {
		return false, true
	}
	for _, candidate := range c.disCapabilities.Features {
		if candidate == feature {
			return true, true
		}
	}
	return false, true
}

func gatewayError(status int, code string, retryable bool) GatewayResponse {
	payload, _ := json.Marshal(sharedapi.ErrorResponse{Error: code, Code: code, Retryable: retryable})
	return GatewayResponse{Status: status, ContentType: "application/json", Body: payload}
}
