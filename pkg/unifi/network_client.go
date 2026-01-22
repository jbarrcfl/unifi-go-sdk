package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"
)

const (
	defaultNetworkMaxRetries   = 3
	defaultNetworkMaxRetryWait = 60 * time.Second
)

// NetworkManager defines the interface for the UniFi Network API.
// This local controller API provides full CRUD operations on network configuration.
type NetworkManager interface {
	Login(ctx context.Context) error
	Logout(ctx context.Context) error
	HasLocalSession() bool

	// Legacy REST API - Networks
	ListNetworks(ctx context.Context) ([]Network, error)
	GetNetwork(ctx context.Context, id string) (*Network, error)
	CreateNetwork(ctx context.Context, network *Network) (*Network, error)
	UpdateNetwork(ctx context.Context, id string, network *Network) (*Network, error)
	DeleteNetwork(ctx context.Context, id string) error

	// Legacy REST API - Firewall Rules
	ListFirewallRules(ctx context.Context) ([]FirewallRule, error)
	GetFirewallRule(ctx context.Context, id string) (*FirewallRule, error)
	CreateFirewallRule(ctx context.Context, rule *FirewallRule) (*FirewallRule, error)
	UpdateFirewallRule(ctx context.Context, id string, rule *FirewallRule) (*FirewallRule, error)
	DeleteFirewallRule(ctx context.Context, id string) error

	// Legacy REST API - Firewall Groups
	ListFirewallGroups(ctx context.Context) ([]FirewallGroup, error)
	GetFirewallGroup(ctx context.Context, id string) (*FirewallGroup, error)
	CreateFirewallGroup(ctx context.Context, group *FirewallGroup) (*FirewallGroup, error)
	UpdateFirewallGroup(ctx context.Context, id string, group *FirewallGroup) (*FirewallGroup, error)
	DeleteFirewallGroup(ctx context.Context, id string) error

	// Legacy REST API - Port Forwards
	ListPortForwards(ctx context.Context) ([]PortForward, error)
	GetPortForward(ctx context.Context, id string) (*PortForward, error)
	CreatePortForward(ctx context.Context, forward *PortForward) (*PortForward, error)
	UpdatePortForward(ctx context.Context, id string, forward *PortForward) (*PortForward, error)
	DeletePortForward(ctx context.Context, id string) error

	// Legacy REST API - WLANs
	ListWLANs(ctx context.Context) ([]WLANConf, error)
	GetWLAN(ctx context.Context, id string) (*WLANConf, error)
	CreateWLAN(ctx context.Context, wlan *WLANConf) (*WLANConf, error)
	UpdateWLAN(ctx context.Context, id string, wlan *WLANConf) (*WLANConf, error)
	DeleteWLAN(ctx context.Context, id string) error

	// Legacy REST API - Port Profiles
	ListPortConfs(ctx context.Context) ([]PortConf, error)
	GetPortConf(ctx context.Context, id string) (*PortConf, error)
	CreatePortConf(ctx context.Context, portconf *PortConf) (*PortConf, error)
	UpdatePortConf(ctx context.Context, id string, portconf *PortConf) (*PortConf, error)
	DeletePortConf(ctx context.Context, id string) error

	// Legacy REST API - Static Routes
	ListRoutes(ctx context.Context) ([]Routing, error)
	GetRoute(ctx context.Context, id string) (*Routing, error)
	CreateRoute(ctx context.Context, route *Routing) (*Routing, error)
	UpdateRoute(ctx context.Context, id string, route *Routing) (*Routing, error)
	DeleteRoute(ctx context.Context, id string) error

	// Legacy REST API - User Groups
	ListUserGroups(ctx context.Context) ([]UserGroup, error)
	GetUserGroup(ctx context.Context, id string) (*UserGroup, error)
	CreateUserGroup(ctx context.Context, group *UserGroup) (*UserGroup, error)
	UpdateUserGroup(ctx context.Context, id string, group *UserGroup) (*UserGroup, error)
	DeleteUserGroup(ctx context.Context, id string) error

	// Legacy REST API - RADIUS Profiles
	ListRADIUSProfiles(ctx context.Context) ([]RADIUSProfile, error)
	GetRADIUSProfile(ctx context.Context, id string) (*RADIUSProfile, error)
	CreateRADIUSProfile(ctx context.Context, profile *RADIUSProfile) (*RADIUSProfile, error)
	UpdateRADIUSProfile(ctx context.Context, id string, profile *RADIUSProfile) (*RADIUSProfile, error)
	DeleteRADIUSProfile(ctx context.Context, id string) error

	// Legacy REST API - Dynamic DNS
	ListDynamicDNS(ctx context.Context) ([]DynamicDNS, error)
	GetDynamicDNS(ctx context.Context, id string) (*DynamicDNS, error)
	CreateDynamicDNS(ctx context.Context, config *DynamicDNS) (*DynamicDNS, error)
	UpdateDynamicDNS(ctx context.Context, id string, config *DynamicDNS) (*DynamicDNS, error)
	DeleteDynamicDNS(ctx context.Context, id string) error

	// Legacy REST API - Device Configuration (port overrides, LED settings, etc.)
	GetDeviceByMAC(ctx context.Context, mac string) (*DeviceConfig, error)
	UpdateDevice(ctx context.Context, id string, device *DeviceConfig) (*DeviceConfig, error)

	// v2 API - Firewall Policies (zone-based firewall)
	ListFirewallPolicies(ctx context.Context) ([]FirewallPolicy, error)
	GetFirewallPolicy(ctx context.Context, id string) (*FirewallPolicy, error)
	CreateFirewallPolicy(ctx context.Context, policy *FirewallPolicy) (*FirewallPolicy, error)
	UpdateFirewallPolicy(ctx context.Context, id string, policy *FirewallPolicy) (*FirewallPolicy, error)
	DeleteFirewallPolicy(ctx context.Context, id string) error

	// v2 API - Firewall Zones
	ListFirewallZones(ctx context.Context) ([]FirewallZone, error)
	GetFirewallZone(ctx context.Context, id string) (*FirewallZone, error)
	CreateFirewallZone(ctx context.Context, zone *FirewallZoneCreateRequest) (*FirewallZone, error)
	UpdateFirewallZone(ctx context.Context, id string, zone *FirewallZoneUpdateRequest) (*FirewallZone, error)
	DeleteFirewallZone(ctx context.Context, id string) error

	// v2 API - Static DNS
	ListStaticDNS(ctx context.Context) ([]StaticDNS, error)
	GetStaticDNS(ctx context.Context, id string) (*StaticDNS, error)
	CreateStaticDNS(ctx context.Context, record *StaticDNS) (*StaticDNS, error)
	UpdateStaticDNS(ctx context.Context, id string, record *StaticDNS) (*StaticDNS, error)
	DeleteStaticDNS(ctx context.Context, id string) error

	// v2 API - Clients (read-only)
	ListActiveClients(ctx context.Context) ([]Client, error)

	// v2 API - Devices (read-only)
	ListDevices(ctx context.Context) (*DeviceList, error)

	// v2 API - AP Groups (read-only)
	ListAPGroups(ctx context.Context) ([]APGroup, error)

	// v2 API - Traffic Rules
	ListTrafficRules(ctx context.Context) ([]TrafficRule, error)
	GetTrafficRule(ctx context.Context, id string) (*TrafficRule, error)
	CreateTrafficRule(ctx context.Context, rule *TrafficRule) (*TrafficRule, error)
	UpdateTrafficRule(ctx context.Context, id string, rule *TrafficRule) (*TrafficRule, error)
	DeleteTrafficRule(ctx context.Context, id string) error

	// v2 API - Traffic Routes (policy-based routing)
	ListTrafficRoutes(ctx context.Context) ([]TrafficRoute, error)
	GetTrafficRoute(ctx context.Context, id string) (*TrafficRoute, error)
	CreateTrafficRoute(ctx context.Context, route *TrafficRoute) (*TrafficRoute, error)
	UpdateTrafficRoute(ctx context.Context, id string, route *TrafficRoute) (*TrafficRoute, error)
	DeleteTrafficRoute(ctx context.Context, id string) error

	// v2 API - NAT Rules
	ListNatRules(ctx context.Context) ([]NatRule, error)
	GetNatRule(ctx context.Context, id string) (*NatRule, error)
	CreateNatRule(ctx context.Context, rule *NatRule) (*NatRule, error)
	UpdateNatRule(ctx context.Context, id string, rule *NatRule) (*NatRule, error)
	DeleteNatRule(ctx context.Context, id string) error

	// v2 API - ACL/QoS/Content Filtering (read-only)
	ListAclRules(ctx context.Context) ([]AclRule, error)
	ListQosRules(ctx context.Context) ([]QosRule, error)
	GetContentFiltering(ctx context.Context) (*ContentFiltering, error)

	// v2 API - VPN/WAN (read-only)
	ListVpnConnections(ctx context.Context) ([]VpnConnection, error)
	ListWanSlas(ctx context.Context) ([]WanSla, error)
}

var _ NetworkManager = (*NetworkClient)(nil)

// NetworkClient is a client for the UniFi Network API.
// It supports two authentication modes:
//   - API Key: Uses X-API-KEY header, no login required (preferred for automation)
//   - Session: Uses username/password with cookies (legacy)
//
// # API Key Authentication
//
// When configured with an API key, the client is immediately ready to use.
// Login() and Logout() become no-ops, and IsLoggedIn() always returns true.
// This mode avoids login rate limits and is recommended for Terraform providers.
//
// # Session Management (Username/Password)
//
// NetworkClient tracks login state locally via the IsLoggedIn method. However,
// server-side sessions can expire independently due to:
//   - Session timeout on the controller
//   - Controller restart
//   - Network interruption
//   - Manual session invalidation
//
// When a session expires server-side, API calls will return ErrUnauthorized.
// Callers should handle this by calling Login again to re-establish the session.
// The SDK does not automatically re-authenticate to avoid masking auth issues.
//
// # Credential Storage
//
// Credentials are stored in memory for the client's lifetime to enable
// re-authentication when sessions expire. This is standard practice for
// session-based SDKs and is appropriate for typical usage patterns like
// Terraform providers where the process is short-lived.
//
// # CSRF Token Handling
//
// For session-based auth, the controller requires a CSRF token for write operations
// (POST, PUT, DELETE). The token is automatically fetched during Login() and included
// in subsequent requests. API key auth does not require CSRF tokens.
type NetworkClient struct {
	BaseURL    string
	Site       string
	HTTPClient *http.Client
	Logger     Logger

	apiKey       string
	username     string
	password     string
	maxRetries   int
	maxRetryWait time.Duration
	mu           sync.RWMutex
	loggedIn     bool
	csrfToken    string
}

// NetworkClientConfig contains configuration options for creating a NetworkClient.
//
// Authentication can be provided via either:
//   - APIKey: Uses X-API-KEY header, no login required
//   - Username/Password: Uses session-based authentication with cookies
//
// You must provide either APIKey OR both Username and Password, but not both.
type NetworkClientConfig struct {
	BaseURL            string
	Site               string
	Username           string
	Password           string
	APIKey             string
	InsecureSkipVerify bool
	Timeout            time.Duration
	Logger             Logger
	MaxRetries         *int // nil = default (3), 0 = no retries
	MaxRetryWait       time.Duration
}

// NewNetworkClient creates a new Network API client with the given configuration.
func NewNetworkClient(cfg NetworkClientConfig) (*NetworkClient, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}

	hasAPIKey := cfg.APIKey != ""
	hasCredentials := cfg.Username != "" || cfg.Password != ""

	if hasAPIKey && hasCredentials {
		return nil, fmt.Errorf("cannot use both APIKey and Username/Password; choose one authentication method")
	}
	if !hasAPIKey && (cfg.Username == "" || cfg.Password == "") {
		return nil, fmt.Errorf("either APIKey or both Username and Password are required")
	}

	site := cfg.Site
	if site == "" {
		site = "default"
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	maxRetries := defaultNetworkMaxRetries
	if cfg.MaxRetries != nil {
		maxRetries = *cfg.MaxRetries
	}

	maxRetryWait := cfg.MaxRetryWait
	if maxRetryWait == 0 {
		maxRetryWait = defaultNetworkMaxRetryWait
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	client := &NetworkClient{
		BaseURL:      cfg.BaseURL,
		Site:         site,
		Logger:       cfg.Logger,
		apiKey:       cfg.APIKey,
		username:     cfg.Username,
		password:     cfg.Password,
		maxRetries:   maxRetries,
		maxRetryWait: maxRetryWait,
		HTTPClient: &http.Client{
			Timeout:   timeout,
			Jar:       jar,
			Transport: transport,
		},
	}

	if cfg.InsecureSkipVerify && client.Logger != nil {
		client.Logger.Printf("warning: TLS certificate verification disabled")
	}

	return client, nil
}

// Login authenticates with the UniFi controller using the configured credentials.
// On success, a session cookie is stored in the HTTP client's cookie jar and
// a CSRF token is fetched for subsequent write operations.
//
// Login can be called multiple times safely to re-establish an expired session.
// If API calls return ErrUnauthorized, call Login again to refresh the session.
//
// When using API key authentication, login is not required; this method
// returns nil immediately without making any network requests.
func (c *NetworkClient) Login(ctx context.Context) error {
	if c.apiKey != "" {
		return nil
	}

	payload := map[string]string{
		"username": c.username,
		"password": c.password,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling login payload: %w", err)
	}

	loginURL := c.BaseURL + "/api/auth/login"
	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if c.Logger != nil {
		c.Logger.Printf("-> POST %s", loginURL)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		if c.Logger != nil {
			c.Logger.Printf("<- error: %v", err)
		}
		return fmt.Errorf("executing login request: %w", err)
	}
	defer resp.Body.Close()

	if c.Logger != nil {
		c.Logger.Printf("<- %d %s", resp.StatusCode, resp.Status)
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return c.parseErrorResponse(resp.StatusCode, respBody, resp.Header.Get("Retry-After"))
	}

	token, err := c.fetchCSRFToken(ctx)
	if err != nil && c.Logger != nil {
		c.Logger.Printf("warning: failed to fetch CSRF token: %v", err)
	}

	c.mu.Lock()
	c.loggedIn = true
	c.csrfToken = token
	c.mu.Unlock()

	return nil
}

func (c *NetworkClient) fetchCSRFToken(ctx context.Context) (string, error) {
	csrfURL := c.BaseURL + "/proxy/network/api/s/" + url.PathEscape(c.Site) + "/self"
	req, err := http.NewRequestWithContext(ctx, "GET", csrfURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodySize))

	token := resp.Header.Get("X-Csrf-Token")
	if token != "" && c.Logger != nil {
		c.Logger.Printf("acquired CSRF token")
	}
	return token, nil
}

// Logout ends the current session with the UniFi controller.
// It is safe to call even if not currently logged in.
//
// When using API key authentication, logout is not required; this method
// returns nil immediately without making any network requests.
func (c *NetworkClient) Logout(ctx context.Context) error {
	if c.apiKey != "" {
		return nil
	}

	c.mu.RLock()
	loggedIn := c.loggedIn
	c.mu.RUnlock()

	if !loggedIn {
		return nil
	}

	logoutURL := c.BaseURL + "/api/auth/logout"
	req, err := http.NewRequestWithContext(ctx, "POST", logoutURL, nil)
	if err != nil {
		return fmt.Errorf("creating logout request: %w", err)
	}

	if c.Logger != nil {
		c.Logger.Printf("-> POST %s", logoutURL)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		if c.Logger != nil {
			c.Logger.Printf("<- error: %v", err)
		}
		return fmt.Errorf("executing logout request: %w", err)
	}
	defer resp.Body.Close()

	if c.Logger != nil {
		c.Logger.Printf("<- %d %s", resp.StatusCode, resp.Status)
	}

	c.mu.Lock()
	c.loggedIn = false
	c.csrfToken = ""
	jar, _ := cookiejar.New(nil)
	c.HTTPClient.Jar = jar
	c.mu.Unlock()

	return nil
}

// HasLocalSession returns true if the client is ready to make authenticated requests.
// This returns true when either:
//   - API key authentication is configured, or
//   - A session cookie exists from a previous Login() call
//
// Note: For session auth, this only reflects local state. The server-side session
// may have expired independently. See NetworkClient documentation for details.
func (c *NetworkClient) HasLocalSession() bool {
	if c.apiKey != "" {
		return true
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loggedIn
}

type networkAPIResponse struct {
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg,omitempty"`
	} `json:"meta"`
	Data json.RawMessage `json:"data"`
}

func (c *NetworkClient) do(ctx context.Context, method, path string, body any, result any) error {
	bodyBytes, err := c.prepareRequest(body)
	if err != nil {
		return err
	}
	return executeWithRetry(ctx, c.Logger, c.maxRetries, c.maxRetryWait, func() error {
		return c.doOnce(ctx, method, path, bodyBytes, result)
	})
}

func (c *NetworkClient) doV2(ctx context.Context, method, path string, body any, result any) error {
	bodyBytes, err := c.prepareRequest(body)
	if err != nil {
		return err
	}
	return executeWithRetry(ctx, c.Logger, c.maxRetries, c.maxRetryWait, func() error {
		return c.doV2Once(ctx, method, path, bodyBytes, result)
	})
}

func (c *NetworkClient) prepareRequest(body any) ([]byte, error) {
	if c.apiKey == "" {
		c.mu.RLock()
		loggedIn := c.loggedIn
		c.mu.RUnlock()

		if !loggedIn {
			return nil, fmt.Errorf("not logged in: call Login() first")
		}
	}

	if body == nil {
		return nil, nil
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request body: %w", err)
	}
	return bodyBytes, nil
}

func (c *NetworkClient) executeRequest(ctx context.Context, method, path string, bodyBytes []byte) ([]byte, int, string, error) {
	reqURL := c.BaseURL + path

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, 0, "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	} else {
		c.mu.RLock()
		csrfToken := c.csrfToken
		c.mu.RUnlock()
		isWriteOp := method == "POST" || method == "PUT" || method == "DELETE"
		if csrfToken != "" && isWriteOp {
			req.Header.Set("X-Csrf-Token", csrfToken)
		} else if csrfToken == "" && isWriteOp && c.Logger != nil {
			c.Logger.Printf("warning: making %s request without CSRF token", method)
		}
	}

	if c.Logger != nil {
		c.Logger.Printf("-> %s %s", method, reqURL)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		if c.Logger != nil {
			c.Logger.Printf("<- error: %v", err)
		}
		return nil, 0, "", fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if c.Logger != nil {
		c.Logger.Printf("<- %d %s", resp.StatusCode, resp.Status)
	}

	retryAfter := resp.Header.Get("Retry-After")

	var body []byte
	if resp.StatusCode >= 400 {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
	} else {
		body, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
		if err != nil {
			return nil, resp.StatusCode, "", fmt.Errorf("reading response body: %w", err)
		}
	}

	return body, resp.StatusCode, retryAfter, nil
}

func (c *NetworkClient) doV2Once(ctx context.Context, method, path string, bodyBytes []byte, result any) error {
	body, statusCode, retryAfter, err := c.executeRequest(ctx, method, path, bodyBytes)
	if err != nil {
		return err
	}

	if statusCode >= 400 {
		return c.parseErrorResponse(statusCode, body, retryAfter)
	}

	if result != nil {
		if err := json.Unmarshal(body, result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}

func (c *NetworkClient) doOnce(ctx context.Context, method, path string, bodyBytes []byte, result any) error {
	body, statusCode, retryAfter, err := c.executeRequest(ctx, method, path, bodyBytes)
	if err != nil {
		return err
	}

	if statusCode >= 400 {
		return c.parseErrorResponse(statusCode, body, retryAfter)
	}

	var apiResp networkAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if apiResp.Meta.RC != "ok" {
		return &APIError{
			StatusCode: statusCode,
			Message:    apiResp.Meta.Msg,
			Err:        sentinelForAPIMessage(apiResp.Meta.Msg),
		}
	}

	if result != nil {
		if err := json.Unmarshal(apiResp.Data, result); err != nil {
			return fmt.Errorf("unmarshaling response data: %w", err)
		}
	}

	return nil
}

func (c *NetworkClient) parseErrorResponse(statusCode int, body []byte, retryAfter string) error {
	return &APIError{
		StatusCode:       statusCode,
		Message:          string(body),
		RetryAfterHeader: retryAfter,
		Err:              sentinelForStatusCode(statusCode),
	}
}

func (c *NetworkClient) restPath(endpoint string) string {
	return "/proxy/network/api/s/" + url.PathEscape(c.Site) + "/rest/" + endpoint
}

func (c *NetworkClient) restPathWithID(endpoint, id string) string {
	return c.restPath(endpoint) + "/" + url.PathEscape(id)
}

func (c *NetworkClient) v2Path(endpoint string) string {
	return "/proxy/network/v2/api/site/" + url.PathEscape(c.Site) + "/" + endpoint
}

func (c *NetworkClient) v2PathWithID(endpoint, id string) string {
	return c.v2Path(endpoint) + "/" + url.PathEscape(id)
}

// Network CRUD operations

func (c *NetworkClient) ListNetworks(ctx context.Context) ([]Network, error) {
	var networks []Network
	err := c.do(ctx, "GET", c.restPath("networkconf"), nil, &networks)
	if err != nil {
		return nil, err
	}
	return networks, nil
}

func (c *NetworkClient) GetNetwork(ctx context.Context, id string) (*Network, error) {
	var networks []Network
	err := c.do(ctx, "GET", c.restPathWithID("networkconf", id), nil, &networks)
	if err != nil {
		return nil, err
	}
	if len(networks) == 0 {
		return nil, ErrNotFound
	}
	return &networks[0], nil
}

func (c *NetworkClient) CreateNetwork(ctx context.Context, network *Network) (*Network, error) {
	if err := network.Validate(); err != nil {
		return nil, err
	}
	var networks []Network
	endpoint := c.restPath("networkconf")
	err := c.do(ctx, "POST", endpoint, network, &networks)
	if err != nil {
		return nil, err
	}
	if len(networks) == 0 {
		return nil, &EmptyResponseError{Operation: "create", Resource: "network", Endpoint: endpoint}
	}
	return &networks[0], nil
}

func (c *NetworkClient) UpdateNetwork(ctx context.Context, id string, network *Network) (*Network, error) {
	if err := network.Validate(); err != nil {
		return nil, err
	}
	var networks []Network
	endpoint := c.restPathWithID("networkconf", id)
	err := c.do(ctx, "PUT", endpoint, network, &networks)
	if err != nil {
		return nil, err
	}
	if len(networks) == 0 {
		return nil, &EmptyResponseError{Operation: "update", Resource: "network", Endpoint: endpoint}
	}
	return &networks[0], nil
}

func (c *NetworkClient) DeleteNetwork(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("networkconf", id), nil, nil)
}

// FirewallRule CRUD operations

func (c *NetworkClient) ListFirewallRules(ctx context.Context) ([]FirewallRule, error) {
	var rules []FirewallRule
	err := c.do(ctx, "GET", c.restPath("firewallrule"), nil, &rules)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

func (c *NetworkClient) GetFirewallRule(ctx context.Context, id string) (*FirewallRule, error) {
	var rules []FirewallRule
	err := c.do(ctx, "GET", c.restPathWithID("firewallrule", id), nil, &rules)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, ErrNotFound
	}
	return &rules[0], nil
}

func (c *NetworkClient) CreateFirewallRule(ctx context.Context, rule *FirewallRule) (*FirewallRule, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	var rules []FirewallRule
	endpoint := c.restPath("firewallrule")
	err := c.do(ctx, "POST", endpoint, rule, &rules)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, &EmptyResponseError{Operation: "create", Resource: "firewall rule", Endpoint: endpoint}
	}
	return &rules[0], nil
}

func (c *NetworkClient) UpdateFirewallRule(ctx context.Context, id string, rule *FirewallRule) (*FirewallRule, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	var rules []FirewallRule
	endpoint := c.restPathWithID("firewallrule", id)
	err := c.do(ctx, "PUT", endpoint, rule, &rules)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, &EmptyResponseError{Operation: "update", Resource: "firewall rule", Endpoint: endpoint}
	}
	return &rules[0], nil
}

func (c *NetworkClient) DeleteFirewallRule(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("firewallrule", id), nil, nil)
}

// FirewallGroup CRUD operations

func (c *NetworkClient) ListFirewallGroups(ctx context.Context) ([]FirewallGroup, error) {
	var groups []FirewallGroup
	err := c.do(ctx, "GET", c.restPath("firewallgroup"), nil, &groups)
	if err != nil {
		return nil, err
	}
	return groups, nil
}

func (c *NetworkClient) GetFirewallGroup(ctx context.Context, id string) (*FirewallGroup, error) {
	var groups []FirewallGroup
	err := c.do(ctx, "GET", c.restPathWithID("firewallgroup", id), nil, &groups)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, ErrNotFound
	}
	return &groups[0], nil
}

func (c *NetworkClient) CreateFirewallGroup(ctx context.Context, group *FirewallGroup) (*FirewallGroup, error) {
	if err := group.Validate(); err != nil {
		return nil, err
	}
	var groups []FirewallGroup
	endpoint := c.restPath("firewallgroup")
	err := c.do(ctx, "POST", endpoint, group, &groups)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, &EmptyResponseError{Operation: "create", Resource: "firewall group", Endpoint: endpoint}
	}
	return &groups[0], nil
}

func (c *NetworkClient) UpdateFirewallGroup(ctx context.Context, id string, group *FirewallGroup) (*FirewallGroup, error) {
	if err := group.Validate(); err != nil {
		return nil, err
	}
	var groups []FirewallGroup
	endpoint := c.restPathWithID("firewallgroup", id)
	err := c.do(ctx, "PUT", endpoint, group, &groups)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, &EmptyResponseError{Operation: "update", Resource: "firewall group", Endpoint: endpoint}
	}
	return &groups[0], nil
}

func (c *NetworkClient) DeleteFirewallGroup(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("firewallgroup", id), nil, nil)
}

// PortForward CRUD operations

func (c *NetworkClient) ListPortForwards(ctx context.Context) ([]PortForward, error) {
	var forwards []PortForward
	err := c.do(ctx, "GET", c.restPath("portforward"), nil, &forwards)
	if err != nil {
		return nil, err
	}
	return forwards, nil
}

func (c *NetworkClient) GetPortForward(ctx context.Context, id string) (*PortForward, error) {
	var forwards []PortForward
	err := c.do(ctx, "GET", c.restPathWithID("portforward", id), nil, &forwards)
	if err != nil {
		return nil, err
	}
	if len(forwards) == 0 {
		return nil, ErrNotFound
	}
	return &forwards[0], nil
}

func (c *NetworkClient) CreatePortForward(ctx context.Context, forward *PortForward) (*PortForward, error) {
	if err := forward.Validate(); err != nil {
		return nil, err
	}
	var forwards []PortForward
	endpoint := c.restPath("portforward")
	err := c.do(ctx, "POST", endpoint, forward, &forwards)
	if err != nil {
		return nil, err
	}
	if len(forwards) == 0 {
		return nil, &EmptyResponseError{Operation: "create", Resource: "port forward", Endpoint: endpoint}
	}
	return &forwards[0], nil
}

func (c *NetworkClient) UpdatePortForward(ctx context.Context, id string, forward *PortForward) (*PortForward, error) {
	if err := forward.Validate(); err != nil {
		return nil, err
	}
	var forwards []PortForward
	endpoint := c.restPathWithID("portforward", id)
	err := c.do(ctx, "PUT", endpoint, forward, &forwards)
	if err != nil {
		return nil, err
	}
	if len(forwards) == 0 {
		return nil, &EmptyResponseError{Operation: "update", Resource: "port forward", Endpoint: endpoint}
	}
	return &forwards[0], nil
}

func (c *NetworkClient) DeletePortForward(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("portforward", id), nil, nil)
}

// WLANConf CRUD operations

func (c *NetworkClient) ListWLANs(ctx context.Context) ([]WLANConf, error) {
	var wlans []WLANConf
	err := c.do(ctx, "GET", c.restPath("wlanconf"), nil, &wlans)
	if err != nil {
		return nil, err
	}
	return wlans, nil
}

func (c *NetworkClient) GetWLAN(ctx context.Context, id string) (*WLANConf, error) {
	var wlans []WLANConf
	err := c.do(ctx, "GET", c.restPathWithID("wlanconf", id), nil, &wlans)
	if err != nil {
		return nil, err
	}
	if len(wlans) == 0 {
		return nil, ErrNotFound
	}
	return &wlans[0], nil
}

func (c *NetworkClient) CreateWLAN(ctx context.Context, wlan *WLANConf) (*WLANConf, error) {
	if err := wlan.Validate(); err != nil {
		return nil, err
	}
	var wlans []WLANConf
	endpoint := c.restPath("wlanconf")
	err := c.do(ctx, "POST", endpoint, wlan, &wlans)
	if err != nil {
		return nil, err
	}
	if len(wlans) == 0 {
		return nil, &EmptyResponseError{Operation: "create", Resource: "WLAN", Endpoint: endpoint}
	}
	return &wlans[0], nil
}

func (c *NetworkClient) UpdateWLAN(ctx context.Context, id string, wlan *WLANConf) (*WLANConf, error) {
	if err := wlan.Validate(); err != nil {
		return nil, err
	}
	var wlans []WLANConf
	endpoint := c.restPathWithID("wlanconf", id)
	err := c.do(ctx, "PUT", endpoint, wlan, &wlans)
	if err != nil {
		return nil, err
	}
	if len(wlans) == 0 {
		return nil, &EmptyResponseError{Operation: "update", Resource: "WLAN", Endpoint: endpoint}
	}
	return &wlans[0], nil
}

func (c *NetworkClient) DeleteWLAN(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("wlanconf", id), nil, nil)
}

// PortConf CRUD operations

func (c *NetworkClient) ListPortConfs(ctx context.Context) ([]PortConf, error) {
	var portconfs []PortConf
	err := c.do(ctx, "GET", c.restPath("portconf"), nil, &portconfs)
	if err != nil {
		return nil, err
	}
	return portconfs, nil
}

func (c *NetworkClient) GetPortConf(ctx context.Context, id string) (*PortConf, error) {
	var portconfs []PortConf
	err := c.do(ctx, "GET", c.restPathWithID("portconf", id), nil, &portconfs)
	if err != nil {
		return nil, err
	}
	if len(portconfs) == 0 {
		return nil, ErrNotFound
	}
	return &portconfs[0], nil
}

func (c *NetworkClient) CreatePortConf(ctx context.Context, portconf *PortConf) (*PortConf, error) {
	if err := portconf.Validate(); err != nil {
		return nil, err
	}
	var portconfs []PortConf
	endpoint := c.restPath("portconf")
	err := c.do(ctx, "POST", endpoint, portconf, &portconfs)
	if err != nil {
		return nil, err
	}
	if len(portconfs) == 0 {
		return nil, &EmptyResponseError{Operation: "create", Resource: "port profile", Endpoint: endpoint}
	}
	return &portconfs[0], nil
}

// UpdatePortConf updates an existing port profile.
// Note: The UniFi API sometimes returns an empty response on successful updates,
// so this method falls back to GetPortConf to ensure the updated resource is returned.
func (c *NetworkClient) UpdatePortConf(ctx context.Context, id string, portconf *PortConf) (*PortConf, error) {
	if err := portconf.Validate(); err != nil {
		return nil, err
	}
	var portconfs []PortConf
	err := c.do(ctx, "PUT", c.restPathWithID("portconf", id), portconf, &portconfs)
	if err != nil {
		return nil, err
	}
	if len(portconfs) == 0 {
		return c.GetPortConf(ctx, id)
	}
	return &portconfs[0], nil
}

func (c *NetworkClient) DeletePortConf(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("portconf", id), nil, nil)
}

// Routing CRUD operations

func (c *NetworkClient) ListRoutes(ctx context.Context) ([]Routing, error) {
	var routes []Routing
	err := c.do(ctx, "GET", c.restPath("routing"), nil, &routes)
	if err != nil {
		return nil, err
	}
	return routes, nil
}

func (c *NetworkClient) GetRoute(ctx context.Context, id string) (*Routing, error) {
	var routes []Routing
	err := c.do(ctx, "GET", c.restPathWithID("routing", id), nil, &routes)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, ErrNotFound
	}
	return &routes[0], nil
}

func (c *NetworkClient) CreateRoute(ctx context.Context, route *Routing) (*Routing, error) {
	if err := route.Validate(); err != nil {
		return nil, err
	}
	var routes []Routing
	endpoint := c.restPath("routing")
	err := c.do(ctx, "POST", endpoint, route, &routes)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, &EmptyResponseError{Operation: "create", Resource: "route", Endpoint: endpoint}
	}
	return &routes[0], nil
}

func (c *NetworkClient) UpdateRoute(ctx context.Context, id string, route *Routing) (*Routing, error) {
	if err := route.Validate(); err != nil {
		return nil, err
	}
	var routes []Routing
	endpoint := c.restPathWithID("routing", id)
	err := c.do(ctx, "PUT", endpoint, route, &routes)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, &EmptyResponseError{Operation: "update", Resource: "route", Endpoint: endpoint}
	}
	return &routes[0], nil
}

func (c *NetworkClient) DeleteRoute(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("routing", id), nil, nil)
}

// UserGroup CRUD operations

func (c *NetworkClient) ListUserGroups(ctx context.Context) ([]UserGroup, error) {
	var groups []UserGroup
	err := c.do(ctx, "GET", c.restPath("usergroup"), nil, &groups)
	if err != nil {
		return nil, err
	}
	return groups, nil
}

func (c *NetworkClient) GetUserGroup(ctx context.Context, id string) (*UserGroup, error) {
	var groups []UserGroup
	err := c.do(ctx, "GET", c.restPathWithID("usergroup", id), nil, &groups)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, ErrNotFound
	}
	return &groups[0], nil
}

func (c *NetworkClient) CreateUserGroup(ctx context.Context, group *UserGroup) (*UserGroup, error) {
	if err := group.Validate(); err != nil {
		return nil, err
	}
	var groups []UserGroup
	endpoint := c.restPath("usergroup")
	err := c.do(ctx, "POST", endpoint, group, &groups)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, &EmptyResponseError{Operation: "create", Resource: "user group", Endpoint: endpoint}
	}
	return &groups[0], nil
}

func (c *NetworkClient) UpdateUserGroup(ctx context.Context, id string, group *UserGroup) (*UserGroup, error) {
	if err := group.Validate(); err != nil {
		return nil, err
	}
	var groups []UserGroup
	endpoint := c.restPathWithID("usergroup", id)
	err := c.do(ctx, "PUT", endpoint, group, &groups)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, &EmptyResponseError{Operation: "update", Resource: "user group", Endpoint: endpoint}
	}
	return &groups[0], nil
}

func (c *NetworkClient) DeleteUserGroup(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("usergroup", id), nil, nil)
}

// RADIUSProfile CRUD operations

func (c *NetworkClient) ListRADIUSProfiles(ctx context.Context) ([]RADIUSProfile, error) {
	var profiles []RADIUSProfile
	err := c.do(ctx, "GET", c.restPath("radiusprofile"), nil, &profiles)
	if err != nil {
		return nil, err
	}
	return profiles, nil
}

func (c *NetworkClient) GetRADIUSProfile(ctx context.Context, id string) (*RADIUSProfile, error) {
	var profiles []RADIUSProfile
	err := c.do(ctx, "GET", c.restPathWithID("radiusprofile", id), nil, &profiles)
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return nil, ErrNotFound
	}
	return &profiles[0], nil
}

func (c *NetworkClient) CreateRADIUSProfile(ctx context.Context, profile *RADIUSProfile) (*RADIUSProfile, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	var profiles []RADIUSProfile
	endpoint := c.restPath("radiusprofile")
	err := c.do(ctx, "POST", endpoint, profile, &profiles)
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return nil, &EmptyResponseError{Operation: "create", Resource: "RADIUS profile", Endpoint: endpoint}
	}
	return &profiles[0], nil
}

func (c *NetworkClient) UpdateRADIUSProfile(ctx context.Context, id string, profile *RADIUSProfile) (*RADIUSProfile, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	var profiles []RADIUSProfile
	endpoint := c.restPathWithID("radiusprofile", id)
	err := c.do(ctx, "PUT", endpoint, profile, &profiles)
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return nil, &EmptyResponseError{Operation: "update", Resource: "RADIUS profile", Endpoint: endpoint}
	}
	return &profiles[0], nil
}

func (c *NetworkClient) DeleteRADIUSProfile(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("radiusprofile", id), nil, nil)
}

// DynamicDNS CRUD operations

func (c *NetworkClient) ListDynamicDNS(ctx context.Context) ([]DynamicDNS, error) {
	var configs []DynamicDNS
	err := c.do(ctx, "GET", c.restPath("dynamicdns"), nil, &configs)
	if err != nil {
		return nil, err
	}
	return configs, nil
}

func (c *NetworkClient) GetDynamicDNS(ctx context.Context, id string) (*DynamicDNS, error) {
	var configs []DynamicDNS
	err := c.do(ctx, "GET", c.restPathWithID("dynamicdns", id), nil, &configs)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, ErrNotFound
	}
	return &configs[0], nil
}

func (c *NetworkClient) CreateDynamicDNS(ctx context.Context, config *DynamicDNS) (*DynamicDNS, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	var configs []DynamicDNS
	endpoint := c.restPath("dynamicdns")
	err := c.do(ctx, "POST", endpoint, config, &configs)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, &EmptyResponseError{Operation: "create", Resource: "dynamic DNS config", Endpoint: endpoint}
	}
	return &configs[0], nil
}

func (c *NetworkClient) UpdateDynamicDNS(ctx context.Context, id string, config *DynamicDNS) (*DynamicDNS, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	var configs []DynamicDNS
	endpoint := c.restPathWithID("dynamicdns", id)
	err := c.do(ctx, "PUT", endpoint, config, &configs)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, &EmptyResponseError{Operation: "update", Resource: "dynamic DNS config", Endpoint: endpoint}
	}
	return &configs[0], nil
}

func (c *NetworkClient) DeleteDynamicDNS(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("dynamicdns", id), nil, nil)
}

// Device operations (for port overrides, LED settings, etc.)

// GetDeviceByMAC retrieves a device by its MAC address using the stat/device endpoint.
// This returns full device state including port_overrides.
func (c *NetworkClient) GetDeviceByMAC(ctx context.Context, mac string) (*DeviceConfig, error) {
	var devices []DeviceConfig
	path := "/proxy/network/api/s/" + url.PathEscape(c.Site) + "/stat/device/" + url.PathEscape(mac)
	err := c.do(ctx, "GET", path, nil, &devices)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, ErrNotFound
	}
	return &devices[0], nil
}

// UpdateDevice updates a device's configuration (port_overrides, name, LED settings, etc.).
// The device ID is required. Only fields that are set will be updated.
func (c *NetworkClient) UpdateDevice(ctx context.Context, id string, device *DeviceConfig) (*DeviceConfig, error) {
	if err := device.Validate(); err != nil {
		return nil, err
	}
	var devices []DeviceConfig
	endpoint := c.restPathWithID("device", id)
	err := c.do(ctx, "PUT", endpoint, device, &devices)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		if device.MAC != "" {
			return c.GetDeviceByMAC(ctx, device.MAC)
		}
		return nil, &EmptyResponseError{Operation: "update", Resource: "device", Endpoint: endpoint}
	}
	return &devices[0], nil
}

// FirewallPolicy CRUD operations (v2 API)

func (c *NetworkClient) ListFirewallPolicies(ctx context.Context) ([]FirewallPolicy, error) {
	var policies []FirewallPolicy
	err := c.doV2(ctx, "GET", c.v2Path("firewall-policies"), nil, &policies)
	if err != nil {
		return nil, err
	}
	return policies, nil
}

func (c *NetworkClient) GetFirewallPolicy(ctx context.Context, id string) (*FirewallPolicy, error) {
	var policy FirewallPolicy
	err := c.doV2(ctx, "GET", c.v2PathWithID("firewall-policies", id), nil, &policy)
	if err != nil {
		return nil, err
	}
	if policy.ID == "" {
		return nil, ErrNotFound
	}
	return &policy, nil
}

func (c *NetworkClient) CreateFirewallPolicy(ctx context.Context, policy *FirewallPolicy) (*FirewallPolicy, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	var result FirewallPolicy
	err := c.doV2(ctx, "POST", c.v2Path("firewall-policies"), policy, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) UpdateFirewallPolicy(ctx context.Context, id string, policy *FirewallPolicy) (*FirewallPolicy, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	var result FirewallPolicy
	err := c.doV2(ctx, "PUT", c.v2PathWithID("firewall-policies", id), policy, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) DeleteFirewallPolicy(ctx context.Context, id string) error {
	return c.doV2(ctx, "DELETE", c.v2PathWithID("firewall-policies", id), nil, nil)
}

// FirewallZone CRUD operations (v2 API)

func (c *NetworkClient) ListFirewallZones(ctx context.Context) ([]FirewallZone, error) {
	var zones []FirewallZone
	err := c.doV2(ctx, "GET", c.v2Path("firewall/zone"), nil, &zones)
	if err != nil {
		return nil, err
	}
	return zones, nil
}

// GetFirewallZone retrieves a firewall zone by ID.
// Some controller versions don't support GET by ID (return 405 Method Not Allowed),
// so this method falls back to listing all zones and filtering by ID.
func (c *NetworkClient) GetFirewallZone(ctx context.Context, id string) (*FirewallZone, error) {
	var zone FirewallZone
	err := c.doV2(ctx, "GET", c.v2PathWithID("firewall/zone", id), nil, &zone)
	if err != nil {
		if errors.Is(err, ErrMethodNotAllowed) {
			return c.getFirewallZoneByList(ctx, id)
		}
		return nil, err
	}
	if zone.ID == "" {
		return nil, ErrNotFound
	}
	return &zone, nil
}

func (c *NetworkClient) getFirewallZoneByList(ctx context.Context, id string) (*FirewallZone, error) {
	zones, err := c.ListFirewallZones(ctx)
	if err != nil {
		return nil, err
	}
	for i := range zones {
		if zones[i].ID == id {
			return &zones[i], nil
		}
	}
	return nil, ErrNotFound
}

func (c *NetworkClient) CreateFirewallZone(ctx context.Context, zone *FirewallZoneCreateRequest) (*FirewallZone, error) {
	if err := zone.Validate(); err != nil {
		return nil, err
	}
	var result FirewallZone
	err := c.doV2(ctx, "POST", c.v2Path("firewall/zone"), zone, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) UpdateFirewallZone(ctx context.Context, id string, zone *FirewallZoneUpdateRequest) (*FirewallZone, error) {
	if zone.ID == "" {
		zone.ID = id
	}
	if err := zone.Validate(); err != nil {
		return nil, err
	}
	var result FirewallZone
	err := c.doV2(ctx, "PUT", c.v2PathWithID("firewall/zone", id), zone, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) DeleteFirewallZone(ctx context.Context, id string) error {
	return c.doV2(ctx, "DELETE", c.v2PathWithID("firewall/zone", id), nil, nil)
}

// StaticDNS CRUD operations (v2 API)

func (c *NetworkClient) ListStaticDNS(ctx context.Context) ([]StaticDNS, error) {
	var records []StaticDNS
	err := c.doV2(ctx, "GET", c.v2Path("static-dns"), nil, &records)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetStaticDNS retrieves a static DNS record by ID.
// Some controller versions don't support GET by ID (return 405 Method Not Allowed),
// so this method falls back to listing all records and filtering by ID.
func (c *NetworkClient) GetStaticDNS(ctx context.Context, id string) (*StaticDNS, error) {
	var record StaticDNS
	err := c.doV2(ctx, "GET", c.v2PathWithID("static-dns", id), nil, &record)
	if err != nil {
		if errors.Is(err, ErrMethodNotAllowed) {
			return c.getStaticDNSByList(ctx, id)
		}
		return nil, err
	}
	if record.ID == "" {
		return nil, ErrNotFound
	}
	return &record, nil
}

func (c *NetworkClient) getStaticDNSByList(ctx context.Context, id string) (*StaticDNS, error) {
	records, err := c.ListStaticDNS(ctx)
	if err != nil {
		return nil, err
	}
	for i := range records {
		if records[i].ID == id {
			return &records[i], nil
		}
	}
	return nil, ErrNotFound
}

func (c *NetworkClient) CreateStaticDNS(ctx context.Context, record *StaticDNS) (*StaticDNS, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	var result StaticDNS
	err := c.doV2(ctx, "POST", c.v2Path("static-dns"), record, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) UpdateStaticDNS(ctx context.Context, id string, record *StaticDNS) (*StaticDNS, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	var result StaticDNS
	err := c.doV2(ctx, "PUT", c.v2PathWithID("static-dns", id), record, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) DeleteStaticDNS(ctx context.Context, id string) error {
	return c.doV2(ctx, "DELETE", c.v2PathWithID("static-dns", id), nil, nil)
}

// Client operations (v2 API, read-only)

func (c *NetworkClient) ListActiveClients(ctx context.Context) ([]Client, error) {
	var clients []Client
	err := c.doV2(ctx, "GET", c.v2Path("clients/active"), nil, &clients)
	if err != nil {
		return nil, err
	}
	return clients, nil
}

// Device operations (v2 API, read-only)

func (c *NetworkClient) ListDevices(ctx context.Context) (*DeviceList, error) {
	var devices DeviceList
	err := c.doV2(ctx, "GET", c.v2Path("device"), nil, &devices)
	if err != nil {
		return nil, err
	}
	return &devices, nil
}

func (c *NetworkClient) ListAPGroups(ctx context.Context) ([]APGroup, error) {
	var groups []APGroup
	err := c.doV2(ctx, "GET", c.v2Path("apgroups"), nil, &groups)
	if err != nil {
		return nil, err
	}
	return groups, nil
}

// TrafficRule CRUD operations (v2 API)

func (c *NetworkClient) ListTrafficRules(ctx context.Context) ([]TrafficRule, error) {
	var rules []TrafficRule
	err := c.doV2(ctx, "GET", c.v2Path("trafficrules"), nil, &rules)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

// GetTrafficRule retrieves a traffic rule by ID.
// Some controller versions don't support GET by ID (return 405 Method Not Allowed),
// so this method falls back to listing all rules and filtering by ID.
func (c *NetworkClient) GetTrafficRule(ctx context.Context, id string) (*TrafficRule, error) {
	var rule TrafficRule
	err := c.doV2(ctx, "GET", c.v2PathWithID("trafficrules", id), nil, &rule)
	if err != nil {
		if errors.Is(err, ErrMethodNotAllowed) {
			return c.getTrafficRuleByList(ctx, id)
		}
		return nil, err
	}
	if rule.ID == "" {
		return nil, ErrNotFound
	}
	return &rule, nil
}

func (c *NetworkClient) getTrafficRuleByList(ctx context.Context, id string) (*TrafficRule, error) {
	rules, err := c.ListTrafficRules(ctx)
	if err != nil {
		return nil, err
	}
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i], nil
		}
	}
	return nil, ErrNotFound
}

func (c *NetworkClient) CreateTrafficRule(ctx context.Context, rule *TrafficRule) (*TrafficRule, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	var result TrafficRule
	err := c.doV2(ctx, "POST", c.v2Path("trafficrules"), rule, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) UpdateTrafficRule(ctx context.Context, id string, rule *TrafficRule) (*TrafficRule, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	var result TrafficRule
	err := c.doV2(ctx, "PUT", c.v2PathWithID("trafficrules", id), rule, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) DeleteTrafficRule(ctx context.Context, id string) error {
	return c.doV2(ctx, "DELETE", c.v2PathWithID("trafficrules", id), nil, nil)
}

// TrafficRoute CRUD operations (v2 API)

func (c *NetworkClient) ListTrafficRoutes(ctx context.Context) ([]TrafficRoute, error) {
	var routes []TrafficRoute
	err := c.doV2(ctx, "GET", c.v2Path("trafficroutes"), nil, &routes)
	if err != nil {
		return nil, err
	}
	return routes, nil
}

// GetTrafficRoute retrieves a traffic route by ID.
// Some controller versions don't support GET by ID (return 405 Method Not Allowed),
// so this method falls back to listing all routes and filtering by ID.
func (c *NetworkClient) GetTrafficRoute(ctx context.Context, id string) (*TrafficRoute, error) {
	var route TrafficRoute
	err := c.doV2(ctx, "GET", c.v2PathWithID("trafficroutes", id), nil, &route)
	if err != nil {
		if errors.Is(err, ErrMethodNotAllowed) {
			return c.getTrafficRouteByList(ctx, id)
		}
		return nil, err
	}
	if route.ID == "" {
		return nil, ErrNotFound
	}
	return &route, nil
}

func (c *NetworkClient) getTrafficRouteByList(ctx context.Context, id string) (*TrafficRoute, error) {
	routes, err := c.ListTrafficRoutes(ctx)
	if err != nil {
		return nil, err
	}
	for i := range routes {
		if routes[i].ID == id {
			return &routes[i], nil
		}
	}
	return nil, ErrNotFound
}

func (c *NetworkClient) CreateTrafficRoute(ctx context.Context, route *TrafficRoute) (*TrafficRoute, error) {
	if err := route.Validate(); err != nil {
		return nil, err
	}
	var result TrafficRoute
	err := c.doV2(ctx, "POST", c.v2Path("trafficroutes"), route, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) UpdateTrafficRoute(ctx context.Context, id string, route *TrafficRoute) (*TrafficRoute, error) {
	if err := route.Validate(); err != nil {
		return nil, err
	}
	var result TrafficRoute
	err := c.doV2(ctx, "PUT", c.v2PathWithID("trafficroutes", id), route, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) DeleteTrafficRoute(ctx context.Context, id string) error {
	return c.doV2(ctx, "DELETE", c.v2PathWithID("trafficroutes", id), nil, nil)
}

// NatRule CRUD operations (v2 API)

func (c *NetworkClient) ListNatRules(ctx context.Context) ([]NatRule, error) {
	var rules []NatRule
	err := c.doV2(ctx, "GET", c.v2Path("nat"), nil, &rules)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

func (c *NetworkClient) GetNatRule(ctx context.Context, id string) (*NatRule, error) {
	var rule NatRule
	err := c.doV2(ctx, "GET", c.v2PathWithID("nat", id), nil, &rule)
	if err != nil {
		return nil, err
	}
	if rule.ID == "" {
		return nil, ErrNotFound
	}
	return &rule, nil
}

func (c *NetworkClient) CreateNatRule(ctx context.Context, rule *NatRule) (*NatRule, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	var result NatRule
	err := c.doV2(ctx, "POST", c.v2Path("nat"), rule, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) UpdateNatRule(ctx context.Context, id string, rule *NatRule) (*NatRule, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	var result NatRule
	err := c.doV2(ctx, "PUT", c.v2PathWithID("nat", id), rule, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *NetworkClient) DeleteNatRule(ctx context.Context, id string) error {
	return c.doV2(ctx, "DELETE", c.v2PathWithID("nat", id), nil, nil)
}

// AclRule operations (v2 API, read-only)

func (c *NetworkClient) ListAclRules(ctx context.Context) ([]AclRule, error) {
	var rules []AclRule
	err := c.doV2(ctx, "GET", c.v2Path("acl-rules"), nil, &rules)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

// QosRule operations (v2 API, read-only)

func (c *NetworkClient) ListQosRules(ctx context.Context) ([]QosRule, error) {
	var rules []QosRule
	err := c.doV2(ctx, "GET", c.v2Path("qos-rules"), nil, &rules)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

// ContentFiltering operations (v2 API, read-only)

func (c *NetworkClient) GetContentFiltering(ctx context.Context) (*ContentFiltering, error) {
	var configs []ContentFiltering
	err := c.doV2(ctx, "GET", c.v2Path("content-filtering"), nil, &configs)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, ErrNotFound
	}
	return &configs[0], nil
}

// VPN operations (v2 API, read-only)

func (c *NetworkClient) ListVpnConnections(ctx context.Context) ([]VpnConnection, error) {
	var result VpnConnectionList
	err := c.doV2(ctx, "GET", c.v2Path("vpn/connections"), nil, &result)
	if err != nil {
		return nil, err
	}
	return result.Connections, nil
}

// WAN SLA operations (v2 API, read-only)

func (c *NetworkClient) ListWanSlas(ctx context.Context) ([]WanSla, error) {
	var slas []WanSla
	err := c.doV2(ctx, "GET", c.v2Path("wan-slas"), nil, &slas)
	if err != nil {
		return nil, err
	}
	return slas, nil
}
