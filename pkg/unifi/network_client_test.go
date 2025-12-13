// Tests use hardcoded credentials for httptest mock servers only.
// These credentials never touch real systems.
//
//nolint:gosec // test credentials for mock servers
package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewNetworkClient(t *testing.T) {
	tests := []struct {
		name    string
		config  NetworkClientConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: NetworkClientConfig{
				BaseURL:  "https://192.168.1.1",
				Username: "admin",
				Password: "password",
			},
			wantErr: false,
		},
		{
			name: "missing base URL",
			config: NetworkClientConfig{
				Username: "admin",
				Password: "password",
			},
			wantErr: true,
		},
		{
			name: "missing username",
			config: NetworkClientConfig{
				BaseURL:  "https://192.168.1.1",
				Password: "password",
			},
			wantErr: true,
		},
		{
			name: "missing password",
			config: NetworkClientConfig{
				BaseURL:  "https://192.168.1.1",
				Username: "admin",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewNetworkClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewNetworkClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewNetworkClient() returned nil client without error")
			}
		})
	}
}

func TestNetworkClientDefaultSite(t *testing.T) {
	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  "https://192.168.1.1",
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}
	if client.Site != "default" {
		t.Errorf("Site = %v, want 'default'", client.Site)
	}
}

func TestNetworkClientLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/login" {
			t.Errorf("expected path /api/auth/login, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		if payload["username"] != "admin" || payload["password"] != "password" {
			t.Errorf("unexpected credentials: %v", payload)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if client.IsLoggedIn() {
		t.Error("client should not be logged in initially")
	}

	if err := client.Login(context.Background()); err != nil {
		t.Errorf("Login() error = %v", err)
	}

	if !client.IsLoggedIn() {
		t.Error("client should be logged in after Login()")
	}
}

func TestNetworkClientLoginFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "invalid credentials"}`))
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "wrongpass",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	err = client.Login(context.Background())
	if err == nil {
		t.Error("Login() should have failed")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Errorf("error should be APIError, got %T", err)
	}

	if !client.IsLoggedIn() {
		return // Expected
	}
	t.Error("client should not be logged in after failed login")
}

func TestNetworkClientLoginFailureScenarios(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		expectedErr    error
		checkSentinel  bool
	}{
		{
			name:          "forbidden",
			statusCode:    403,
			responseBody:  `{"error": "forbidden"}`,
			expectedErr:   ErrForbidden,
			checkSentinel: true,
		},
		{
			name:          "internal server error",
			statusCode:    500,
			responseBody:  `{"error": "internal server error"}`,
			expectedErr:   ErrServerError,
			checkSentinel: true,
		},
		{
			name:          "bad gateway",
			statusCode:    502,
			responseBody:  `{"error": "bad gateway"}`,
			expectedErr:   ErrBadGateway,
			checkSentinel: true,
		},
		{
			name:          "service unavailable",
			statusCode:    503,
			responseBody:  `{"error": "service unavailable"}`,
			expectedErr:   ErrServiceUnavail,
			checkSentinel: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			client, _ := NewNetworkClient(NetworkClientConfig{
				BaseURL:  server.URL,
				Username: "admin",
				Password: "password",
			})

			err := client.Login(context.Background())
			if err == nil {
				t.Fatal("Login() should have failed")
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error should be APIError, got %T: %v", err, err)
			}

			if apiErr.StatusCode != tt.statusCode {
				t.Errorf("expected status code %d, got %d", tt.statusCode, apiErr.StatusCode)
			}

			if tt.checkSentinel && !errors.Is(err, tt.expectedErr) {
				t.Errorf("expected %v, got %v", tt.expectedErr, err)
			}

			if client.IsLoggedIn() {
				t.Error("client should not be logged in after failed login")
			}
		})
	}
}

func TestNetworkClientNotLoggedIn(t *testing.T) {
	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  "https://192.168.1.1",
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	_, err = client.ListNetworks(context.Background())
	if err == nil {
		t.Error("ListNetworks() should fail when not logged in")
	}
}

func TestNetworkClientListNetworks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf":
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{
						"_id":       "abc123",
						"name":      "LAN",
						"ip_subnet": "192.168.1.0/24",
						"vlan":      1,
					},
					{
						"_id":       "def456",
						"name":      "Guest",
						"ip_subnet": "192.168.2.0/24",
						"vlan":      10,
					},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	networks, err := client.ListNetworks(context.Background())
	if err != nil {
		t.Fatalf("ListNetworks() error = %v", err)
	}

	if len(networks) != 2 {
		t.Errorf("expected 2 networks, got %d", len(networks))
	}

	if networks[0].ID != "abc123" {
		t.Errorf("expected ID abc123, got %s", networks[0].ID)
	}
	if networks[0].Name != "LAN" {
		t.Errorf("expected name LAN, got %s", networks[0].Name)
	}
}

func TestNetworkClientGetNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf/abc123":
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{
						"_id":       "abc123",
						"name":      "LAN",
						"ip_subnet": "192.168.1.0/24",
					},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	network, err := client.GetNetwork(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("GetNetwork() error = %v", err)
	}

	if network.ID != "abc123" {
		t.Errorf("expected ID abc123, got %s", network.ID)
	}
}

func TestNetworkClientCreateNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf":
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}

			var network Network
			if err := json.NewDecoder(r.Body).Decode(&network); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}

			if network.Name != "TestNetwork" {
				t.Errorf("expected name TestNetwork, got %s", network.Name)
			}

			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{
						"_id":       "new123",
						"name":      network.Name,
						"ip_subnet": network.IPSubnet,
					},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	network := &Network{
		Name:     "TestNetwork",
		IPSubnet: "10.0.0.0/24",
	}

	created, err := client.CreateNetwork(context.Background(), network)
	if err != nil {
		t.Fatalf("CreateNetwork() error = %v", err)
	}

	if created.ID != "new123" {
		t.Errorf("expected ID new123, got %s", created.ID)
	}
}

func TestNetworkClientDeleteNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf/abc123":
			if r.Method != "DELETE" {
				t.Errorf("expected DELETE, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []any{},
			}
			json.NewEncoder(w).Encode(response)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if err := client.DeleteNetwork(context.Background(), "abc123"); err != nil {
		t.Fatalf("DeleteNetwork() error = %v", err)
	}
}

func TestNetworkClientDeleteAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf/abc123":
			response := map[string]any{
				"meta": map[string]string{
					"rc":  "error",
					"msg": "api.err.ObjectInUse",
				},
				"data": []any{},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	err = client.DeleteNetwork(context.Background(), "abc123")
	if err == nil {
		t.Fatal("DeleteNetwork() should have failed with API error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Errorf("error should be APIError, got %T", err)
	}
	if apiErr.Message != "api.err.ObjectInUse" {
		t.Errorf("expected message 'api.err.ObjectInUse', got '%s'", apiErr.Message)
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("expected errors.Is(err, ErrConflict) to be true")
	}
}

func TestNetworkClientAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf":
			response := map[string]any{
				"meta": map[string]string{
					"rc":  "error",
					"msg": "api.err.InvalidObject",
				},
				"data": []any{},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	_, err = client.ListNetworks(context.Background())
	if err == nil {
		t.Error("ListNetworks() should have failed")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Errorf("error should be APIError, got %T", err)
	}
	if apiErr.Message != "api.err.InvalidObject" {
		t.Errorf("expected message 'api.err.InvalidObject', got '%s'", apiErr.Message)
	}
}

func TestNetworkClientFirewallRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/firewallrule":
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{
						"_id":     "rule1",
						"name":    "Block All",
						"action":  "drop",
						"enabled": true,
					},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	rules, err := client.ListFirewallRules(context.Background())
	if err != nil {
		t.Fatalf("ListFirewallRules() error = %v", err)
	}

	if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "Block All" {
		t.Errorf("expected name 'Block All', got '%s'", rules[0].Name)
	}
}

func TestNetworkClientFirewallGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/firewallgroup":
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{
						"_id":           "group1",
						"name":          "Web Servers",
						"group_type":    "address-group",
						"group_members": []string{"192.168.1.10", "192.168.1.11"},
					},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	groups, err := client.ListFirewallGroups(context.Background())
	if err != nil {
		t.Fatalf("ListFirewallGroups() error = %v", err)
	}

	if len(groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(groups))
	}
	if groups[0].GroupType != "address-group" {
		t.Errorf("expected group_type 'address-group', got '%s'", groups[0].GroupType)
	}
}

func TestNetworkClientPortForwards(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/portforward":
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{
						"_id":      "pf1",
						"name":     "Web Server",
						"dst_port": "80",
						"fwd":      "192.168.1.10",
						"fwd_port": "80",
					},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	forwards, err := client.ListPortForwards(context.Background())
	if err != nil {
		t.Fatalf("ListPortForwards() error = %v", err)
	}

	if len(forwards) != 1 {
		t.Errorf("expected 1 forward, got %d", len(forwards))
	}
	if forwards[0].DstPort != "80" {
		t.Errorf("expected dst_port '80', got '%s'", forwards[0].DstPort)
	}
}

func TestNetworkClientWLANs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/wlanconf":
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{
						"_id":      "wlan1",
						"name":     "Home WiFi",
						"security": "wpapsk",
						"enabled":  true,
					},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	wlans, err := client.ListWLANs(context.Background())
	if err != nil {
		t.Fatalf("ListWLANs() error = %v", err)
	}

	if len(wlans) != 1 {
		t.Errorf("expected 1 WLAN, got %d", len(wlans))
	}
	if wlans[0].Security != "wpapsk" {
		t.Errorf("expected security 'wpapsk', got '%s'", wlans[0].Security)
	}
}

func TestNetworkClientLogout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/api/auth/logout":
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if !client.IsLoggedIn() {
		t.Error("client should be logged in")
	}

	if err := client.Logout(context.Background()); err != nil {
		t.Errorf("Logout() error = %v", err)
	}

	if client.IsLoggedIn() {
		t.Error("client should not be logged in after logout")
	}
}

func TestNetworkClientCustomSite(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/mysite/rest/networkconf":
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []any{},
			}
			json.NewEncoder(w).Encode(response)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
		Site:     "mysite",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if client.Site != "mysite" {
		t.Errorf("Site = %v, want 'mysite'", client.Site)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	_, err = client.ListNetworks(context.Background())
	if err != nil {
		t.Fatalf("ListNetworks() error = %v", err)
	}
}

func TestNetworkClientUpdateNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf/abc123":
			if r.Method != "PUT" {
				t.Errorf("expected PUT, got %s", r.Method)
			}

			var network Network
			if err := json.NewDecoder(r.Body).Decode(&network); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}

			if network.Name != "UpdatedNetwork" {
				t.Errorf("expected name UpdatedNetwork, got %s", network.Name)
			}

			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{
						"_id":       "abc123",
						"name":      network.Name,
						"ip_subnet": network.IPSubnet,
					},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	network := &Network{
		Name:     "UpdatedNetwork",
		IPSubnet: "10.0.0.0/24",
	}

	updated, err := client.UpdateNetwork(context.Background(), "abc123", network)
	if err != nil {
		t.Fatalf("UpdateNetwork() error = %v", err)
	}

	if updated.ID != "abc123" {
		t.Errorf("expected ID abc123, got %s", updated.ID)
	}
	if updated.Name != "UpdatedNetwork" {
		t.Errorf("expected name UpdatedNetwork, got %s", updated.Name)
	}
}

func TestNetworkClientUpdateFirewallRule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/firewallrule/rule123":
			if r.Method != "PUT" {
				t.Errorf("expected PUT, got %s", r.Method)
			}

			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{
						"_id":    "rule123",
						"name":   "Updated Rule",
						"action": "accept",
					},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	rule := &FirewallRule{
		Name:   "Updated Rule",
		Action: "accept",
	}

	updated, err := client.UpdateFirewallRule(context.Background(), "rule123", rule)
	if err != nil {
		t.Fatalf("UpdateFirewallRule() error = %v", err)
	}

	if updated.Name != "Updated Rule" {
		t.Errorf("expected name 'Updated Rule', got '%s'", updated.Name)
	}
}

func TestNetworkClientConflictError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf/abc123":
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"error": "resource has dependencies"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	err = client.DeleteNetwork(context.Background(), "abc123")
	if err == nil {
		t.Fatal("DeleteNetwork() should have failed with conflict")
	}

	if !errors.Is(err, ErrConflict) {
		t.Errorf("expected ErrConflict, got %v", err)
	}
}

func TestNetworkClientPortConfs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/portconf":
			if r.Method == "GET" {
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":     "port1",
							"name":    "All",
							"forward": "all",
						},
						{
							"_id":     "port2",
							"name":    "VLAN 100",
							"forward": "native",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			} else if r.Method == "POST" {
				var portconf PortConf
				if err := json.NewDecoder(r.Body).Decode(&portconf); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":     "newport",
							"name":    portconf.Name,
							"forward": portconf.Forward,
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			}
		case "/proxy/network/api/s/default/rest/portconf/port1":
			switch r.Method {
			case "GET":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":     "port1",
							"name":    "All",
							"forward": "all",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			case "PUT":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":     "port1",
							"name":    "Updated",
							"forward": "native",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			case "DELETE":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []any{},
				}
				json.NewEncoder(w).Encode(response)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	t.Run("List", func(t *testing.T) {
		portconfs, err := client.ListPortConfs(context.Background())
		if err != nil {
			t.Fatalf("ListPortConfs() error = %v", err)
		}
		if len(portconfs) != 2 {
			t.Errorf("expected 2 port profiles, got %d", len(portconfs))
		}
		if portconfs[0].Forward != "all" {
			t.Errorf("expected forward 'all', got '%s'", portconfs[0].Forward)
		}
	})

	t.Run("Get", func(t *testing.T) {
		portconf, err := client.GetPortConf(context.Background(), "port1")
		if err != nil {
			t.Fatalf("GetPortConf() error = %v", err)
		}
		if portconf.ID != "port1" {
			t.Errorf("expected ID 'port1', got '%s'", portconf.ID)
		}
	})

	t.Run("Create", func(t *testing.T) {
		portconf := &PortConf{
			Name:    "New Profile",
			Forward: "native",
		}
		created, err := client.CreatePortConf(context.Background(), portconf)
		if err != nil {
			t.Fatalf("CreatePortConf() error = %v", err)
		}
		if created.ID != "newport" {
			t.Errorf("expected ID 'newport', got '%s'", created.ID)
		}
	})

	t.Run("Update", func(t *testing.T) {
		portconf := &PortConf{
			Name:    "Updated",
			Forward: "native",
		}
		updated, err := client.UpdatePortConf(context.Background(), "port1", portconf)
		if err != nil {
			t.Fatalf("UpdatePortConf() error = %v", err)
		}
		if updated.Name != "Updated" {
			t.Errorf("expected name 'Updated', got '%s'", updated.Name)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := client.DeletePortConf(context.Background(), "port1"); err != nil {
			t.Fatalf("DeletePortConf() error = %v", err)
		}
	})
}

func TestNetworkClientRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/routing":
			if r.Method == "GET" {
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":                    "route1",
							"name":                   "To VPN",
							"enabled":                true,
							"static-route_network":   "10.0.0.0/24",
							"static-route_nexthop":   "192.168.1.254",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			} else if r.Method == "POST" {
				var route Routing
				if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":  "newroute",
							"name": route.Name,
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			}
		case "/proxy/network/api/s/default/rest/routing/route1":
			switch r.Method {
			case "GET":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":  "route1",
							"name": "To VPN",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			case "PUT":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":  "route1",
							"name": "Updated Route",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			case "DELETE":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []any{},
				}
				json.NewEncoder(w).Encode(response)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	t.Run("List", func(t *testing.T) {
		routes, err := client.ListRoutes(context.Background())
		if err != nil {
			t.Fatalf("ListRoutes() error = %v", err)
		}
		if len(routes) != 1 {
			t.Errorf("expected 1 route, got %d", len(routes))
		}
		if routes[0].StaticRouteNetwork != "10.0.0.0/24" {
			t.Errorf("expected network '10.0.0.0/24', got '%s'", routes[0].StaticRouteNetwork)
		}
	})

	t.Run("Get", func(t *testing.T) {
		route, err := client.GetRoute(context.Background(), "route1")
		if err != nil {
			t.Fatalf("GetRoute() error = %v", err)
		}
		if route.ID != "route1" {
			t.Errorf("expected ID 'route1', got '%s'", route.ID)
		}
	})

	t.Run("Create", func(t *testing.T) {
		enabled := true
		route := &Routing{
			Name:               "New Route",
			Enabled:            &enabled,
			StaticRouteNetwork: "10.1.0.0/24",
			StaticRouteNexthop: "192.168.1.1",
		}
		created, err := client.CreateRoute(context.Background(), route)
		if err != nil {
			t.Fatalf("CreateRoute() error = %v", err)
		}
		if created.ID != "newroute" {
			t.Errorf("expected ID 'newroute', got '%s'", created.ID)
		}
	})

	t.Run("Update", func(t *testing.T) {
		route := &Routing{
			Name: "Updated Route",
		}
		updated, err := client.UpdateRoute(context.Background(), "route1", route)
		if err != nil {
			t.Fatalf("UpdateRoute() error = %v", err)
		}
		if updated.Name != "Updated Route" {
			t.Errorf("expected name 'Updated Route', got '%s'", updated.Name)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := client.DeleteRoute(context.Background(), "route1"); err != nil {
			t.Fatalf("DeleteRoute() error = %v", err)
		}
	})
}

func TestNetworkClientUserGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/usergroup":
			if r.Method == "GET" {
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":               "group1",
							"name":              "Default",
							"qos_rate_max_down": -1,
							"qos_rate_max_up":   -1,
						},
						{
							"_id":               "group2",
							"name":              "Limited",
							"qos_rate_max_down": 10000,
							"qos_rate_max_up":   5000,
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			} else if r.Method == "POST" {
				var group UserGroup
				if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":  "newgroup",
							"name": group.Name,
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			}
		case "/proxy/network/api/s/default/rest/usergroup/group1":
			switch r.Method {
			case "GET":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":  "group1",
							"name": "Default",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			case "PUT":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":  "group1",
							"name": "Updated Group",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			case "DELETE":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []any{},
				}
				json.NewEncoder(w).Encode(response)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	t.Run("List", func(t *testing.T) {
		groups, err := client.ListUserGroups(context.Background())
		if err != nil {
			t.Fatalf("ListUserGroups() error = %v", err)
		}
		if len(groups) != 2 {
			t.Errorf("expected 2 user groups, got %d", len(groups))
		}
		if groups[1].Name != "Limited" {
			t.Errorf("expected name 'Limited', got '%s'", groups[1].Name)
		}
	})

	t.Run("Get", func(t *testing.T) {
		group, err := client.GetUserGroup(context.Background(), "group1")
		if err != nil {
			t.Fatalf("GetUserGroup() error = %v", err)
		}
		if group.ID != "group1" {
			t.Errorf("expected ID 'group1', got '%s'", group.ID)
		}
	})

	t.Run("Create", func(t *testing.T) {
		down := 50000
		up := 25000
		group := &UserGroup{
			Name:           "New Group",
			QosRateMaxDown: &down,
			QosRateMaxUp:   &up,
		}
		created, err := client.CreateUserGroup(context.Background(), group)
		if err != nil {
			t.Fatalf("CreateUserGroup() error = %v", err)
		}
		if created.ID != "newgroup" {
			t.Errorf("expected ID 'newgroup', got '%s'", created.ID)
		}
	})

	t.Run("Update", func(t *testing.T) {
		group := &UserGroup{
			Name: "Updated Group",
		}
		updated, err := client.UpdateUserGroup(context.Background(), "group1", group)
		if err != nil {
			t.Fatalf("UpdateUserGroup() error = %v", err)
		}
		if updated.Name != "Updated Group" {
			t.Errorf("expected name 'Updated Group', got '%s'", updated.Name)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := client.DeleteUserGroup(context.Background(), "group1"); err != nil {
			t.Fatalf("DeleteUserGroup() error = %v", err)
		}
	})
}

func TestNetworkClientRADIUSProfiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/radiusprofile":
			if r.Method == "GET" {
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":  "radius1",
							"name": "Corporate RADIUS",
							"auth_servers": []map[string]any{
								{
									"ip":       "192.168.1.10",
									"port":     1812,
									"x_secret": "secret",
								},
							},
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			} else if r.Method == "POST" {
				var profile RADIUSProfile
				if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":  "newradius",
							"name": profile.Name,
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			}
		case "/proxy/network/api/s/default/rest/radiusprofile/radius1":
			switch r.Method {
			case "GET":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":  "radius1",
							"name": "Corporate RADIUS",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			case "PUT":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":  "radius1",
							"name": "Updated RADIUS",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			case "DELETE":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []any{},
				}
				json.NewEncoder(w).Encode(response)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	t.Run("List", func(t *testing.T) {
		profiles, err := client.ListRADIUSProfiles(context.Background())
		if err != nil {
			t.Fatalf("ListRADIUSProfiles() error = %v", err)
		}
		if len(profiles) != 1 {
			t.Errorf("expected 1 RADIUS profile, got %d", len(profiles))
		}
		if profiles[0].Name != "Corporate RADIUS" {
			t.Errorf("expected name 'Corporate RADIUS', got '%s'", profiles[0].Name)
		}
		if len(profiles[0].AuthServers) != 1 {
			t.Errorf("expected 1 auth server, got %d", len(profiles[0].AuthServers))
		}
	})

	t.Run("Get", func(t *testing.T) {
		profile, err := client.GetRADIUSProfile(context.Background(), "radius1")
		if err != nil {
			t.Fatalf("GetRADIUSProfile() error = %v", err)
		}
		if profile.ID != "radius1" {
			t.Errorf("expected ID 'radius1', got '%s'", profile.ID)
		}
	})

	t.Run("Create", func(t *testing.T) {
		port := 1812
		profile := &RADIUSProfile{
			Name: "New RADIUS",
			AuthServers: []RADIUSServer{
				{
					IP:      "10.0.0.1",
					Port:    &port,
					XSecret: "newsecret",
				},
			},
		}
		created, err := client.CreateRADIUSProfile(context.Background(), profile)
		if err != nil {
			t.Fatalf("CreateRADIUSProfile() error = %v", err)
		}
		if created.ID != "newradius" {
			t.Errorf("expected ID 'newradius', got '%s'", created.ID)
		}
	})

	t.Run("Update", func(t *testing.T) {
		profile := &RADIUSProfile{
			Name: "Updated RADIUS",
		}
		updated, err := client.UpdateRADIUSProfile(context.Background(), "radius1", profile)
		if err != nil {
			t.Fatalf("UpdateRADIUSProfile() error = %v", err)
		}
		if updated.Name != "Updated RADIUS" {
			t.Errorf("expected name 'Updated RADIUS', got '%s'", updated.Name)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := client.DeleteRADIUSProfile(context.Background(), "radius1"); err != nil {
			t.Fatalf("DeleteRADIUSProfile() error = %v", err)
		}
	})
}

func TestNetworkClientDynamicDNS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/dynamicdns":
			if r.Method == "GET" {
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":       "ddns1",
							"service":   "dyndns",
							"host_name": "myhost.dyndns.org",
							"login":     "user@example.com",
							"interface": "wan",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			} else if r.Method == "POST" {
				var config DynamicDNS
				if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":       "newddns",
							"service":   config.Service,
							"host_name": config.HostName,
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			}
		case "/proxy/network/api/s/default/rest/dynamicdns/ddns1":
			switch r.Method {
			case "GET":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":       "ddns1",
							"service":   "dyndns",
							"host_name": "myhost.dyndns.org",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			case "PUT":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []map[string]any{
						{
							"_id":       "ddns1",
							"service":   "dyndns",
							"host_name": "updated.dyndns.org",
						},
					},
				}
				json.NewEncoder(w).Encode(response)
			case "DELETE":
				response := map[string]any{
					"meta": map[string]string{"rc": "ok"},
					"data": []any{},
				}
				json.NewEncoder(w).Encode(response)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	t.Run("List", func(t *testing.T) {
		configs, err := client.ListDynamicDNS(context.Background())
		if err != nil {
			t.Fatalf("ListDynamicDNS() error = %v", err)
		}
		if len(configs) != 1 {
			t.Errorf("expected 1 DDNS config, got %d", len(configs))
		}
		if configs[0].Service != "dyndns" {
			t.Errorf("expected service 'dyndns', got '%s'", configs[0].Service)
		}
		if configs[0].HostName != "myhost.dyndns.org" {
			t.Errorf("expected hostname 'myhost.dyndns.org', got '%s'", configs[0].HostName)
		}
	})

	t.Run("Get", func(t *testing.T) {
		config, err := client.GetDynamicDNS(context.Background(), "ddns1")
		if err != nil {
			t.Fatalf("GetDynamicDNS() error = %v", err)
		}
		if config.ID != "ddns1" {
			t.Errorf("expected ID 'ddns1', got '%s'", config.ID)
		}
	})

	t.Run("Create", func(t *testing.T) {
		config := &DynamicDNS{
			Service:   "noip",
			HostName:  "newhost.noip.com",
			Login:     "user",
			XPassword: "pass",
			Interface: "wan",
		}
		created, err := client.CreateDynamicDNS(context.Background(), config)
		if err != nil {
			t.Fatalf("CreateDynamicDNS() error = %v", err)
		}
		if created.ID != "newddns" {
			t.Errorf("expected ID 'newddns', got '%s'", created.ID)
		}
	})

	t.Run("Update", func(t *testing.T) {
		config := &DynamicDNS{
			HostName: "updated.dyndns.org",
		}
		updated, err := client.UpdateDynamicDNS(context.Background(), "ddns1", config)
		if err != nil {
			t.Fatalf("UpdateDynamicDNS() error = %v", err)
		}
		if updated.HostName != "updated.dyndns.org" {
			t.Errorf("expected hostname 'updated.dyndns.org', got '%s'", updated.HostName)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := client.DeleteDynamicDNS(context.Background(), "ddns1"); err != nil {
			t.Fatalf("DeleteDynamicDNS() error = %v", err)
		}
	})
}

func TestNetworkClientGetNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		default:
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []any{},
			}
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer server.Close()

	client, err := NewNetworkClient(NetworkClientConfig{
		BaseURL:  server.URL,
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}

	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GetNetwork", func() error { _, err := client.GetNetwork(context.Background(), "notfound"); return err }},
		{"GetFirewallRule", func() error { _, err := client.GetFirewallRule(context.Background(), "notfound"); return err }},
		{"GetFirewallGroup", func() error { _, err := client.GetFirewallGroup(context.Background(), "notfound"); return err }},
		{"GetPortForward", func() error { _, err := client.GetPortForward(context.Background(), "notfound"); return err }},
		{"GetWLAN", func() error { _, err := client.GetWLAN(context.Background(), "notfound"); return err }},
		{"GetPortConf", func() error { _, err := client.GetPortConf(context.Background(), "notfound"); return err }},
		{"GetRoute", func() error { _, err := client.GetRoute(context.Background(), "notfound"); return err }},
		{"GetUserGroup", func() error { _, err := client.GetUserGroup(context.Background(), "notfound"); return err }},
		{"GetRADIUSProfile", func() error { _, err := client.GetRADIUSProfile(context.Background(), "notfound"); return err }},
		{"GetDynamicDNS", func() error { _, err := client.GetDynamicDNS(context.Background(), "notfound"); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("expected ErrNotFound, got %v", err)
			}
		})
	}
}

func TestNetworkClientGetFirewallRule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/firewallrule/rule123":
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "rule123", "name": "Allow SSH", "action": "accept"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	rule, err := client.GetFirewallRule(context.Background(), "rule123")
	if err != nil {
		t.Fatalf("GetFirewallRule() error = %v", err)
	}
	if rule.ID != "rule123" {
		t.Errorf("expected ID rule123, got %s", rule.ID)
	}
}

func TestNetworkClientCreateFirewallRule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/firewallrule":
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "newrule", "name": "Block All", "action": "drop"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	rule := &FirewallRule{Name: "Block All", Action: "drop"}
	created, err := client.CreateFirewallRule(context.Background(), rule)
	if err != nil {
		t.Fatalf("CreateFirewallRule() error = %v", err)
	}
	if created.ID != "newrule" {
		t.Errorf("expected ID newrule, got %s", created.ID)
	}
}

func TestNetworkClientDeleteFirewallRule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/firewallrule/rule123":
			if r.Method != "DELETE" {
				t.Errorf("expected DELETE, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []any{},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	if err := client.DeleteFirewallRule(context.Background(), "rule123"); err != nil {
		t.Fatalf("DeleteFirewallRule() error = %v", err)
	}
}

func TestNetworkClientGetFirewallGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/firewallgroup/group123":
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "group123", "name": "Blocked IPs", "group_type": "address-group"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	group, err := client.GetFirewallGroup(context.Background(), "group123")
	if err != nil {
		t.Fatalf("GetFirewallGroup() error = %v", err)
	}
	if group.ID != "group123" {
		t.Errorf("expected ID group123, got %s", group.ID)
	}
}

func TestNetworkClientCreateFirewallGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/firewallgroup":
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "newgroup", "name": "New Group", "group_type": "address-group"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	group := &FirewallGroup{Name: "New Group", GroupType: "address-group"}
	created, err := client.CreateFirewallGroup(context.Background(), group)
	if err != nil {
		t.Fatalf("CreateFirewallGroup() error = %v", err)
	}
	if created.ID != "newgroup" {
		t.Errorf("expected ID newgroup, got %s", created.ID)
	}
}

func TestNetworkClientUpdateFirewallGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/firewallgroup/group123":
			if r.Method != "PUT" {
				t.Errorf("expected PUT, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "group123", "name": "Updated Group"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	group := &FirewallGroup{Name: "Updated Group"}
	updated, err := client.UpdateFirewallGroup(context.Background(), "group123", group)
	if err != nil {
		t.Fatalf("UpdateFirewallGroup() error = %v", err)
	}
	if updated.Name != "Updated Group" {
		t.Errorf("expected name Updated Group, got %s", updated.Name)
	}
}

func TestNetworkClientDeleteFirewallGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/firewallgroup/group123":
			if r.Method != "DELETE" {
				t.Errorf("expected DELETE, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []any{},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	if err := client.DeleteFirewallGroup(context.Background(), "group123"); err != nil {
		t.Fatalf("DeleteFirewallGroup() error = %v", err)
	}
}

func TestNetworkClientGetPortForward(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/portforward/pf123":
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "pf123", "name": "SSH Forward", "dst_port": "22"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	pf, err := client.GetPortForward(context.Background(), "pf123")
	if err != nil {
		t.Fatalf("GetPortForward() error = %v", err)
	}
	if pf.ID != "pf123" {
		t.Errorf("expected ID pf123, got %s", pf.ID)
	}
}

func TestNetworkClientCreatePortForward(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/portforward":
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "newpf", "name": "New Forward"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	pf := &PortForward{Name: "New Forward", DstPort: "8080"}
	created, err := client.CreatePortForward(context.Background(), pf)
	if err != nil {
		t.Fatalf("CreatePortForward() error = %v", err)
	}
	if created.ID != "newpf" {
		t.Errorf("expected ID newpf, got %s", created.ID)
	}
}

func TestNetworkClientUpdatePortForward(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/portforward/pf123":
			if r.Method != "PUT" {
				t.Errorf("expected PUT, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "pf123", "name": "Updated Forward"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	pf := &PortForward{Name: "Updated Forward"}
	updated, err := client.UpdatePortForward(context.Background(), "pf123", pf)
	if err != nil {
		t.Fatalf("UpdatePortForward() error = %v", err)
	}
	if updated.Name != "Updated Forward" {
		t.Errorf("expected name Updated Forward, got %s", updated.Name)
	}
}

func TestNetworkClientDeletePortForward(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/portforward/pf123":
			if r.Method != "DELETE" {
				t.Errorf("expected DELETE, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []any{},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	if err := client.DeletePortForward(context.Background(), "pf123"); err != nil {
		t.Fatalf("DeletePortForward() error = %v", err)
	}
}

func TestNetworkClientGetWLAN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/wlanconf/wlan123":
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "wlan123", "name": "MyWiFi", "security": "wpapsk"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	wlan, err := client.GetWLAN(context.Background(), "wlan123")
	if err != nil {
		t.Fatalf("GetWLAN() error = %v", err)
	}
	if wlan.ID != "wlan123" {
		t.Errorf("expected ID wlan123, got %s", wlan.ID)
	}
}

func TestNetworkClientCreateWLAN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/wlanconf":
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "newwlan", "name": "GuestWiFi"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	wlan := &WLANConf{Name: "GuestWiFi", Security: "wpapsk"}
	created, err := client.CreateWLAN(context.Background(), wlan)
	if err != nil {
		t.Fatalf("CreateWLAN() error = %v", err)
	}
	if created.ID != "newwlan" {
		t.Errorf("expected ID newwlan, got %s", created.ID)
	}
}

func TestNetworkClientUpdateWLAN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/wlanconf/wlan123":
			if r.Method != "PUT" {
				t.Errorf("expected PUT, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{
					{"_id": "wlan123", "name": "UpdatedWiFi"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	wlan := &WLANConf{Name: "UpdatedWiFi"}
	updated, err := client.UpdateWLAN(context.Background(), "wlan123", wlan)
	if err != nil {
		t.Fatalf("UpdateWLAN() error = %v", err)
	}
	if updated.Name != "UpdatedWiFi" {
		t.Errorf("expected name UpdatedWiFi, got %s", updated.Name)
	}
}

func TestNetworkClientDeleteWLAN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/wlanconf/wlan123":
			if r.Method != "DELETE" {
				t.Errorf("expected DELETE, got %s", r.Method)
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []any{},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	if err := client.DeleteWLAN(context.Background(), "wlan123"); err != nil {
		t.Fatalf("DeleteWLAN() error = %v", err)
	}
}

func TestNetworkClientAPIErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		default:
			response := map[string]any{
				"meta": map[string]string{"rc": "error", "msg": "api.err.InvalidObject"},
				"data": []any{},
			}
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())

	_, err := client.ListNetworks(context.Background())
	if err == nil {
		t.Fatal("expected error for rc=error response")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.Message != "api.err.InvalidObject" {
		t.Errorf("expected message 'api.err.InvalidObject', got %q", apiErr.Message)
	}
}

func TestNetworkClientLogoutIdempotent(t *testing.T) {
	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: "https://192.168.1.1", Username: "admin", Password: "password",
	})

	err := client.Logout(context.Background())
	if err != nil {
		t.Errorf("Logout when not logged in should succeed (idempotent), got %v", err)
	}
}

func TestNetworkClientLogoutNetworkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		}
	}))

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL: server.URL, Username: "admin", Password: "password",
	})
	client.Login(context.Background())
	server.Close()

	err := client.Logout(context.Background())
	if err == nil {
		t.Fatal("expected error for network failure during logout")
	}
}

func TestNetworkClientTransientErrorRetry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf":
			callCount++
			if callCount < 2 {
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("temporary error"))
				return
			}
			response := map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]any{{"_id": "net1", "name": "LAN"}},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL:    server.URL,
		Username:   "admin",
		Password:   "password",
		MaxRetries: intPtr(2),
	})
	client.Login(context.Background())

	networks, err := client.ListNetworks(context.Background())
	if err != nil {
		t.Fatalf("ListNetworks() error = %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected 2 API calls (1 failure + 1 success), got %d", callCount)
	}
	if len(networks) != 1 {
		t.Errorf("expected 1 network, got %d", len(networks))
	}
}

func TestNetworkClientNonRetryableError(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/proxy/network/api/s/default/rest/networkconf":
			callCount++
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad request"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL:    server.URL,
		Username:   "admin",
		Password:   "password",
		MaxRetries: intPtr(3),
	})
	client.Login(context.Background())

	_, err := client.ListNetworks(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}

	if callCount != 1 {
		t.Errorf("expected 1 API call (no retries for 400), got %d", callCount)
	}

	if !errors.Is(err, ErrBadRequest) {
		t.Errorf("expected ErrBadRequest, got %v", err)
	}
}

func TestNetworkClientRetryExhausted(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		default:
			callCount++
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("gateway error"))
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL:    server.URL,
		Username:   "admin",
		Password:   "password",
		MaxRetries: intPtr(2),
	})
	client.Login(context.Background())

	_, err := client.ListNetworks(context.Background())
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}

	if !errors.Is(err, ErrBadGateway) {
		t.Errorf("expected ErrBadGateway, got %v", err)
	}

	if callCount != 3 {
		t.Errorf("expected 3 API calls (1 + 2 retries), got %d", callCount)
	}
}

func TestNetworkClientContextCancellationDuringRetry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
		default:
			callCount++
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("gateway error"))
		}
	}))
	defer server.Close()

	client, _ := NewNetworkClient(NetworkClientConfig{
		BaseURL:      server.URL,
		Username:     "admin",
		Password:     "password",
		MaxRetries:   intPtr(5),
		MaxRetryWait: 60 * time.Second,
	})
	client.Login(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.ListNetworks(ctx)
	if err == nil {
		t.Fatal("expected error")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 API call before context timeout, got %d", callCount)
	}
}
