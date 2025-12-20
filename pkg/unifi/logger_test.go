package unifi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewStdLogger(t *testing.T) {
	logger := NewStdLogger()
	if logger == nil {
		t.Fatal("NewStdLogger() returned nil")
	}
	if logger.Logger == nil {
		t.Fatal("NewStdLogger().Logger is nil")
	}
}

type testLogger struct {
	messages []string
}

func (l *testLogger) Printf(format string, v ...any) {
	l.messages = append(l.messages, fmt.Sprintf(format, v...))
}

func TestNetworkClientLogging(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/self":
			w.Header().Set("X-Csrf-Token", "test-token")
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	logger := &testLogger{}
	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
		Logger:   logger,
	})

	client.Login(context.Background())
	client.ListNetworks(context.Background())

	if len(logger.messages) == 0 {
		t.Fatal("expected log messages, got none")
	}

	hasRequest := false
	hasResponse := false
	for _, msg := range logger.messages {
		if strings.Contains(msg, "-> ") {
			hasRequest = true
		}
		if strings.Contains(msg, "<- ") {
			hasResponse = true
		}
	}

	if !hasRequest {
		t.Error("expected request log (-> method url)")
	}
	if !hasResponse {
		t.Error("expected response log (<- status)")
	}
}

func TestNetworkClientLoggingOnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/self":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
		}
	}))
	defer server.Close()

	logger := &testLogger{}
	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
		Logger:   logger,
	})

	client.Login(context.Background())
	client.ListNetworks(context.Background())

	has500 := false
	for _, msg := range logger.messages {
		if strings.Contains(msg, "500") {
			has500 = true
			break
		}
	}

	if !has500 {
		t.Errorf("expected error status in logs, got: %v", logger.messages)
	}
}

func TestSiteManagerClientLogging(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[],"httpStatusCode":200,"traceId":"test"}`))
	}))
	defer server.Close()

	logger := &testLogger{}
	client, _ := NewSiteManagerClient(SiteManagerClientConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Logger:  logger,
	})

	client.ListHosts(context.Background(), nil)

	if len(logger.messages) == 0 {
		t.Fatal("expected log messages, got none")
	}

	hasRequest := false
	hasResponse := false
	for _, msg := range logger.messages {
		if strings.Contains(msg, "-> GET") {
			hasRequest = true
		}
		if strings.Contains(msg, "<- 200") {
			hasResponse = true
		}
	}

	if !hasRequest {
		t.Error("expected request log (-> GET ...)")
	}
	if !hasResponse {
		t.Error("expected response log (<- 200)")
	}
}

func TestClientLoggingCSRFToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/self":
			w.Header().Set("X-Csrf-Token", "acquired-token")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	logger := &testLogger{}
	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
		Logger:   logger,
	})

	client.Login(context.Background())

	hasCSRF := false
	for _, msg := range logger.messages {
		if strings.Contains(msg, "CSRF") {
			hasCSRF = true
			break
		}
	}

	if !hasCSRF {
		t.Error("expected CSRF token acquisition log")
	}
}
