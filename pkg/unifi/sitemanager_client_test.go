package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewSiteManagerClient(t *testing.T) {
	client := NewSiteManagerClient("test-api-key")

	if client.APIKey != "test-api-key" {
		t.Errorf("expected APIKey to be 'test-api-key', got %q", client.APIKey)
	}
	if client.BaseURL != "https://api.ui.com" {
		t.Errorf("expected BaseURL to be 'https://api.ui.com', got %q", client.BaseURL)
	}
	if client.HTTPClient == nil {
		t.Error("expected HTTPClient to be non-nil")
	}
}

func TestListHosts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/hosts" {
			t.Errorf("expected path '/v1/hosts', got %q", r.URL.Path)
		}
		if r.Header.Get("X-API-KEY") != "test-key" {
			t.Errorf("expected X-API-KEY header 'test-key', got %q", r.Header.Get("X-API-KEY"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept header 'application/json', got %q", r.Header.Get("Accept"))
		}

		resp := map[string]any{
			"data": []map[string]any{
				{"id": "host-1", "type": "ucore"},
				{"id": "host-2", "type": "network-server"},
			},
			"httpStatusCode": 200,
			"traceId":        "trace-123",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	resp, err := client.ListHosts(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(resp.Hosts))
	}
	if resp.Hosts[0].ID != "host-1" {
		t.Errorf("expected first host ID 'host-1', got %q", resp.Hosts[0].ID)
	}
	if resp.TraceID != "trace-123" {
		t.Errorf("expected TraceID 'trace-123', got %q", resp.TraceID)
	}
}

func TestListHostsWithPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageSize := r.URL.Query().Get("pageSize")
		nextToken := r.URL.Query().Get("nextToken")

		if pageSize != "10" {
			t.Errorf("expected pageSize '10', got %q", pageSize)
		}
		if nextToken != "token-abc" {
			t.Errorf("expected nextToken 'token-abc', got %q", nextToken)
		}

		resp := map[string]any{
			"data":           []map[string]any{},
			"httpStatusCode": 200,
			"traceId":        "trace-123",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	_, err := client.ListHosts(context.Background(), &ListHostsOptions{
		PageSize:  10,
		NextToken: "token-abc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/hosts/host-123" {
			t.Errorf("expected path '/v1/hosts/host-123', got %q", r.URL.Path)
		}

		resp := map[string]any{
			"data": map[string]any{
				"id":   "host-123",
				"type": "ucore",
			},
			"httpStatusCode": 200,
			"traceId":        "trace-456",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	resp, err := client.GetHost(context.Background(), "host-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Host.ID != "host-123" {
		t.Errorf("expected host ID 'host-123', got %q", resp.Host.ID)
	}
	if resp.TraceID != "trace-456" {
		t.Errorf("expected TraceID 'trace-456', got %q", resp.TraceID)
	}
}

func TestListSites(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sites" {
			t.Errorf("expected path '/v1/sites', got %q", r.URL.Path)
		}

		resp := map[string]any{
			"data": []map[string]any{
				{"siteId": "site-1", "hostId": "host-1"},
				{"siteId": "site-2", "hostId": "host-2"},
			},
			"httpStatusCode": 200,
			"traceId":        "trace-789",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	resp, err := client.ListSites(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Sites) != 2 {
		t.Errorf("expected 2 sites, got %d", len(resp.Sites))
	}
	if resp.Sites[0].SiteID != "site-1" {
		t.Errorf("expected first site ID 'site-1', got %q", resp.Sites[0].SiteID)
	}
}

func TestListDevices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/devices" {
			t.Errorf("expected path '/v1/devices', got %q", r.URL.Path)
		}

		resp := map[string]any{
			"data": []map[string]any{
				{
					"hostId":   "host-1",
					"hostName": "UDM-SE",
					"devices": []map[string]any{
						{
							"id":          "device-1",
							"mac":         "AA:BB:CC:DD:EE:FF",
							"name":        "U6 Pro",
							"model":       "U6 Pro",
							"productLine": "network",
							"status":      "online",
						},
					},
					"updatedAt": "2025-01-01T00:00:00Z",
				},
			},
			"httpStatusCode": 200,
			"traceId":        "trace-devices",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	resp, err := client.ListDevices(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.HostDevices) != 1 {
		t.Errorf("expected 1 host, got %d", len(resp.HostDevices))
	}
	if resp.HostDevices[0].HostID != "host-1" {
		t.Errorf("expected host ID 'host-1', got %q", resp.HostDevices[0].HostID)
	}
	if len(resp.HostDevices[0].Devices) != 1 {
		t.Errorf("expected 1 device, got %d", len(resp.HostDevices[0].Devices))
	}
	if resp.HostDevices[0].Devices[0].Name != "U6 Pro" {
		t.Errorf("expected device name 'U6 Pro', got %q", resp.HostDevices[0].Devices[0].Name)
	}
	if resp.TraceID != "trace-devices" {
		t.Errorf("expected TraceID 'trace-devices', got %q", resp.TraceID)
	}
}

func TestListDevicesWithHostFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostIDs := r.URL.Query()["hostIds"]
		if len(hostIDs) != 2 || hostIDs[0] != "host-1" || hostIDs[1] != "host-2" {
			t.Errorf("expected hostIds=['host-1', 'host-2'], got %v", hostIDs)
		}

		resp := map[string]any{
			"data":           []map[string]any{},
			"httpStatusCode": 200,
			"traceId":        "trace-123",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	_, err := client.ListDevices(context.Background(), &ListDevicesOptions{
		HostIDs: []string{"host-1", "host-2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    error
	}{
		{"BadRequest", 400, ErrBadRequest},
		{"Unauthorized", 401, ErrUnauthorized},
		{"Forbidden", 403, ErrForbidden},
		{"NotFound", 404, ErrNotFound},
		{"RateLimited", 429, ErrRateLimited},
		{"ServerError", 500, ErrServerError},
		{"BadGateway", 502, ErrBadGateway},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte("error message"))
			}))
			defer server.Close()

			client := NewSiteManagerClient("test-key")
			client.BaseURL = server.URL
			client.MaxRetries = 0

			_, err := client.ListHosts(context.Background(), nil)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatal("expected APIError")
			}
			if apiErr.StatusCode != tt.statusCode {
				t.Errorf("expected status code %d, got %d", tt.statusCode, apiErr.StatusCode)
			}
			if apiErr.Message != "error message" {
				t.Errorf("expected message 'error message', got %q", apiErr.Message)
			}
		})
	}
}

func TestUnknownErrorCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(418) // I'm a teapot
		w.Write([]byte("teapot error"))
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	_, err := client.ListHosts(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatal("expected APIError")
	}
	if apiErr.StatusCode != 418 {
		t.Errorf("expected status code 418, got %d", apiErr.StatusCode)
	}
	if apiErr.Err != nil {
		t.Errorf("expected nil sentinel error for unknown status, got %v", apiErr.Err)
	}
}

func TestListAllHostsPagination(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var resp map[string]any

		if callCount == 1 {
			resp = map[string]any{
				"data": []map[string]any{
					{"id": "host-1"},
				},
				"httpStatusCode": 200,
				"traceId":        "trace-1",
				"nextToken":      "page-2-token",
			}
		} else {
			resp = map[string]any{
				"data": []map[string]any{
					{"id": "host-2"},
				},
				"httpStatusCode": 200,
				"traceId":        "trace-2",
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	hosts, err := client.ListAllHosts(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected 2 API calls, got %d", callCount)
	}
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0].ID != "host-1" || hosts[1].ID != "host-2" {
		t.Errorf("unexpected host IDs: %v", hosts)
	}
}

func TestListAllSitesPagination(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var resp map[string]any

		if callCount == 1 {
			resp = map[string]any{
				"data": []map[string]any{
					{"siteId": "site-1"},
				},
				"httpStatusCode": 200,
				"traceId":        "trace-1",
				"nextToken":      "page-2-token",
			}
		} else {
			resp = map[string]any{
				"data": []map[string]any{
					{"siteId": "site-2"},
				},
				"httpStatusCode": 200,
				"traceId":        "trace-2",
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	sites, err := client.ListAllSites(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected 2 API calls, got %d", callCount)
	}
	if len(sites) != 2 {
		t.Errorf("expected 2 sites, got %d", len(sites))
	}
	if sites[0].SiteID != "site-1" || sites[1].SiteID != "site-2" {
		t.Errorf("unexpected site IDs: %v", sites)
	}
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.ListHosts(ctx, nil)
	if err == nil {
		t.Fatal("expected error due to cancelled context")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context canceled error, got: %v", err)
	}
}

func TestContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.ListHosts(ctx, nil)
	if err == nil {
		t.Fatal("expected error due to context timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("expected deadline exceeded error, got: %v", err)
	}
}

func TestMalformedJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	_, err := client.ListHosts(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error due to malformed JSON")
	}
	if !strings.Contains(err.Error(), "decoding response") {
		t.Errorf("expected decoding error, got: %v", err)
	}
}

func TestEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	resp, err := client.ListHosts(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(resp.Hosts))
	}
}

func TestNetworkError(t *testing.T) {
	client := NewSiteManagerClient("test-key")
	client.BaseURL = "http://localhost:99999"

	_, err := client.ListHosts(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error due to network failure")
	}
	if !strings.Contains(err.Error(), "executing request") {
		t.Errorf("expected executing request error, got: %v", err)
	}
}

func TestRateLimitRetry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(429)
			w.Write([]byte(`{"code":"rate_limit","httpStatusCode":429,"message":"rate limit exceeded, retry after 0.01s"}`))
			return
		}
		resp := map[string]any{
			"data":           []map[string]any{{"id": "host-1"}},
			"httpStatusCode": 200,
			"traceId":        "trace-123",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	resp, err := client.ListHosts(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 3 {
		t.Errorf("expected 3 API calls, got %d", callCount)
	}
	if len(resp.Hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(resp.Hosts))
	}
}

func TestRateLimitExhausted(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(429)
		w.Write([]byte(`{"code":"rate_limit","httpStatusCode":429,"message":"rate limit exceeded, retry after 0.01s"}`))
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL
	client.MaxRetries = 2

	_, err := client.ListHosts(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}

	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("expected ErrRateLimited, got %v", err)
	}

	if callCount != 3 {
		t.Errorf("expected 3 API calls (1 + 2 retries), got %d", callCount)
	}
}

func TestRateLimitContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte(`{"code":"rate_limit","httpStatusCode":429,"message":"rate limit exceeded, retry after 10s"}`))
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.ListHosts(ctx, nil)
	if err == nil {
		t.Fatal("expected error due to context timeout")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestParseRetryAfterBody(t *testing.T) {
	tests := []struct {
		msg      string
		expected time.Duration
	}{
		{`{"message":"rate limit exceeded, retry after 5.372786998s"}`, 5372786998 * time.Nanosecond},
		{`{"message":"rate limit exceeded, retry after 1s"}`, 1 * time.Second},
		{`{"message":"rate limit exceeded, retry after 0.5s"}`, 500 * time.Millisecond},
		{`{"message":"some other error"}`, 5 * time.Second},
		{`invalid`, 5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			got := parseRetryAfterBody(tt.msg)
			if got != tt.expected {
				t.Errorf("parseRetryAfterBody(%q) = %v, want %v", tt.msg, got, tt.expected)
			}
		})
	}
}

func TestParseRetryAfterHeader(t *testing.T) {
	tests := []struct {
		header   string
		expected time.Duration
	}{
		{"5", 5 * time.Second},
		{"60", 60 * time.Second},
		{"0", 0},
		{"", 0},
		{"invalid", 0},
		{"1.5", 1500 * time.Millisecond},
		{"0.5", 500 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got := parseRetryAfterHeader(tt.header)
			if got != tt.expected {
				t.Errorf("parseRetryAfterHeader(%q) = %v, want %v", tt.header, got, tt.expected)
			}
		})
	}
}

func TestParseRetryAfterHeaderHTTPDate(t *testing.T) {
	future := time.Now().Add(10 * time.Second).UTC().Format(http.TimeFormat)
	got := parseRetryAfterHeader(future)
	if got < 9*time.Second || got > 11*time.Second {
		t.Errorf("parseRetryAfterHeader(%q) = %v, want ~10s", future, got)
	}

	past := time.Now().Add(-10 * time.Second).UTC().Format(http.TimeFormat)
	got = parseRetryAfterHeader(past)
	if got != 0 {
		t.Errorf("parseRetryAfterHeader(%q) = %v, want 0 for past date", past, got)
	}
}

func TestApplyBackoffWithJitter(t *testing.T) {
	for range 100 {
		wait := applyBackoffWithJitter(0, 0)
		if wait < 1*time.Second || wait > 1500*time.Millisecond {
			t.Errorf("attempt 0: wait %v not in expected range [1s, 1.5s]", wait)
		}
	}

	for range 100 {
		wait := applyBackoffWithJitter(0, 2)
		if wait < 4*time.Second || wait > 6*time.Second {
			t.Errorf("attempt 2: wait %v not in expected range [4s, 6s]", wait)
		}
	}

	for range 100 {
		wait := applyBackoffWithJitter(10*time.Second, 0)
		if wait != 10*time.Second {
			t.Errorf("server wait 10s: want exactly 10s, got %v", wait)
		}
	}

	for range 100 {
		wait := applyBackoffWithJitter(0, 10)
		if wait > 30*time.Second {
			t.Errorf("attempt 10: wait %v should be capped at 30s", wait)
		}
	}
}

func TestRateLimitRetryWithHeader(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 2 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			w.Write([]byte(`{"message":"rate limited"}`))
			return
		}
		resp := map[string]any{
			"data":           []map[string]any{{"id": "host-1"}},
			"httpStatusCode": 200,
			"traceId":        "trace-123",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL

	start := time.Now()
	resp, err := client.ListHosts(context.Background(), nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected 2 API calls, got %d", callCount)
	}
	if len(resp.Hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(resp.Hosts))
	}
	if elapsed < 1*time.Second {
		t.Errorf("expected retry to wait at least 1s from header, got %v", elapsed)
	}
}

func TestDefaultTimeout(t *testing.T) {
	client := NewSiteManagerClient("test-key")
	if client.HTTPClient.Timeout != 30*time.Second {
		t.Errorf("expected default timeout of 30s, got %v", client.HTTPClient.Timeout)
	}
}

func TestRetryAfterHeaderInAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
		w.Write([]byte(`{"message":"rate limited"}`))
	}))
	defer server.Close()

	client := NewSiteManagerClient("test-key")
	client.BaseURL = server.URL
	client.MaxRetries = 0

	_, err := client.ListHosts(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatal("expected APIError")
	}
	if apiErr.RetryAfterHeader != "120" {
		t.Errorf("expected RetryAfterHeader '120', got %q", apiErr.RetryAfterHeader)
	}
}
