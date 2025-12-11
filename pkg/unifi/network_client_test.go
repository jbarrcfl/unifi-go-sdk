package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
		Password: "wrong",
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
