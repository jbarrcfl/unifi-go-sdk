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
	IsLoggedIn() bool

	ListNetworks(ctx context.Context) ([]Network, error)
	GetNetwork(ctx context.Context, id string) (*Network, error)
	CreateNetwork(ctx context.Context, network *Network) (*Network, error)
	UpdateNetwork(ctx context.Context, id string, network *Network) (*Network, error)
	DeleteNetwork(ctx context.Context, id string) error

	ListFirewallRules(ctx context.Context) ([]FirewallRule, error)
	GetFirewallRule(ctx context.Context, id string) (*FirewallRule, error)
	CreateFirewallRule(ctx context.Context, rule *FirewallRule) (*FirewallRule, error)
	UpdateFirewallRule(ctx context.Context, id string, rule *FirewallRule) (*FirewallRule, error)
	DeleteFirewallRule(ctx context.Context, id string) error

	ListFirewallGroups(ctx context.Context) ([]FirewallGroup, error)
	GetFirewallGroup(ctx context.Context, id string) (*FirewallGroup, error)
	CreateFirewallGroup(ctx context.Context, group *FirewallGroup) (*FirewallGroup, error)
	UpdateFirewallGroup(ctx context.Context, id string, group *FirewallGroup) (*FirewallGroup, error)
	DeleteFirewallGroup(ctx context.Context, id string) error

	ListPortForwards(ctx context.Context) ([]PortForward, error)
	GetPortForward(ctx context.Context, id string) (*PortForward, error)
	CreatePortForward(ctx context.Context, forward *PortForward) (*PortForward, error)
	UpdatePortForward(ctx context.Context, id string, forward *PortForward) (*PortForward, error)
	DeletePortForward(ctx context.Context, id string) error

	ListWLANs(ctx context.Context) ([]WLANConf, error)
	GetWLAN(ctx context.Context, id string) (*WLANConf, error)
	CreateWLAN(ctx context.Context, wlan *WLANConf) (*WLANConf, error)
	UpdateWLAN(ctx context.Context, id string, wlan *WLANConf) (*WLANConf, error)
	DeleteWLAN(ctx context.Context, id string) error

	ListPortConfs(ctx context.Context) ([]PortConf, error)
	GetPortConf(ctx context.Context, id string) (*PortConf, error)
	CreatePortConf(ctx context.Context, portconf *PortConf) (*PortConf, error)
	UpdatePortConf(ctx context.Context, id string, portconf *PortConf) (*PortConf, error)
	DeletePortConf(ctx context.Context, id string) error

	ListRoutes(ctx context.Context) ([]Routing, error)
	GetRoute(ctx context.Context, id string) (*Routing, error)
	CreateRoute(ctx context.Context, route *Routing) (*Routing, error)
	UpdateRoute(ctx context.Context, id string, route *Routing) (*Routing, error)
	DeleteRoute(ctx context.Context, id string) error

	ListUserGroups(ctx context.Context) ([]UserGroup, error)
	GetUserGroup(ctx context.Context, id string) (*UserGroup, error)
	CreateUserGroup(ctx context.Context, group *UserGroup) (*UserGroup, error)
	UpdateUserGroup(ctx context.Context, id string, group *UserGroup) (*UserGroup, error)
	DeleteUserGroup(ctx context.Context, id string) error

	ListRADIUSProfiles(ctx context.Context) ([]RADIUSProfile, error)
	GetRADIUSProfile(ctx context.Context, id string) (*RADIUSProfile, error)
	CreateRADIUSProfile(ctx context.Context, profile *RADIUSProfile) (*RADIUSProfile, error)
	UpdateRADIUSProfile(ctx context.Context, id string, profile *RADIUSProfile) (*RADIUSProfile, error)
	DeleteRADIUSProfile(ctx context.Context, id string) error

	ListDynamicDNS(ctx context.Context) ([]DynamicDNS, error)
	GetDynamicDNS(ctx context.Context, id string) (*DynamicDNS, error)
	CreateDynamicDNS(ctx context.Context, config *DynamicDNS) (*DynamicDNS, error)
	UpdateDynamicDNS(ctx context.Context, id string, config *DynamicDNS) (*DynamicDNS, error)
	DeleteDynamicDNS(ctx context.Context, id string) error
}

var _ NetworkManager = (*NetworkClient)(nil)

// NetworkClient is a client for the UniFi Network API.
// It uses session-based authentication (username/password) and provides
// full CRUD operations for network configuration.
//
// # Session Management
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
type NetworkClient struct {
	BaseURL    string
	Site       string
	HTTPClient *http.Client
	Logger     Logger

	username     string
	password     string
	maxRetries   int
	maxRetryWait time.Duration
	mu           sync.RWMutex
	loggedIn     bool
}

// NetworkClientConfig contains configuration options for creating a NetworkClient.
type NetworkClientConfig struct {
	BaseURL            string
	Site               string
	Username           string
	Password           string
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
	if cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("username and password are required")
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

	return &NetworkClient{
		BaseURL:      cfg.BaseURL,
		Site:         site,
		Logger:       cfg.Logger,
		username:     cfg.Username,
		password:     cfg.Password,
		maxRetries:   maxRetries,
		maxRetryWait: maxRetryWait,
		HTTPClient: &http.Client{
			Timeout:   timeout,
			Jar:       jar,
			Transport: transport,
		},
	}, nil
}

func (c *NetworkClient) Login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

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
		return c.parseErrorResponse(resp.StatusCode, respBody)
	}

	c.loggedIn = true
	return nil
}

func (c *NetworkClient) Logout(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.loggedIn {
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

	c.loggedIn = false
	return nil
}

// IsLoggedIn returns whether Login has been called successfully.
// Note: This only reflects local state. The server-side session may have
// expired independently. See NetworkClient documentation for details.
func (c *NetworkClient) IsLoggedIn() bool {
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

func (c *NetworkClient) do(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	c.mu.RLock()
	loggedIn := c.loggedIn
	c.mu.RUnlock()

	if !loggedIn {
		return fmt.Errorf("not logged in: call Login() first")
	}

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling request body: %w", err)
		}
	}

	var lastErr error
	maxAttempts := c.maxRetries + 1

	for attempt := 0; attempt < maxAttempts; attempt++ {
		lastErr = c.doOnce(ctx, method, path, bodyBytes, result)
		if lastErr == nil {
			return nil
		}

		if !isRetryable(lastErr) {
			return lastErr
		}

		if attempt >= maxAttempts-1 {
			break
		}

		wait := time.Duration(0)
		var apiErr *APIError
		if errors.As(lastErr, &apiErr) && apiErr.StatusCode == 429 {
			wait = parseRetryAfterHeader(apiErr.RetryAfterHeader)
			if wait == 0 {
				wait = parseRetryAfterBody(apiErr.Message)
			}
		}
		wait = applyBackoffWithJitter(wait, attempt, c.maxRetryWait)

		if c.Logger != nil {
			c.Logger.Printf("retrying in %v (attempt %d/%d)", wait, attempt+1, c.maxRetries)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}

	return lastErr
}

func (c *NetworkClient) doOnce(ctx context.Context, method, path string, bodyBytes []byte, result interface{}) error {
	reqURL := c.BaseURL + path

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.Logger != nil {
		c.Logger.Printf("-> %s %s", method, reqURL)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		if c.Logger != nil {
			c.Logger.Printf("<- error: %v", err)
		}
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if c.Logger != nil {
		c.Logger.Printf("<- %d %s", resp.StatusCode, resp.Status)
	}

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return c.parseErrorResponse(resp.StatusCode, respBody)
	}

	var apiResp networkAPIResponse
	limitedBody := io.LimitReader(resp.Body, maxResponseBodySize)
	if err := json.NewDecoder(limitedBody).Decode(&apiResp); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if apiResp.Meta.RC != "ok" {
		return &APIError{
			StatusCode: resp.StatusCode,
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

func (c *NetworkClient) parseErrorResponse(statusCode int, body []byte) error {
	return &APIError{
		StatusCode: statusCode,
		Message:    string(body),
		Err:        sentinelForStatusCode(statusCode),
	}
}

func (c *NetworkClient) restPath(endpoint string) string {
	return "/proxy/network/api/s/" + url.PathEscape(c.Site) + "/rest/" + endpoint
}

func (c *NetworkClient) restPathWithID(endpoint, id string) string {
	return c.restPath(endpoint) + "/" + url.PathEscape(id)
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

func (c *NetworkClient) UpdatePortConf(ctx context.Context, id string, portconf *PortConf) (*PortConf, error) {
	var portconfs []PortConf
	endpoint := c.restPathWithID("portconf", id)
	err := c.do(ctx, "PUT", endpoint, portconf, &portconfs)
	if err != nil {
		return nil, err
	}
	if len(portconfs) == 0 {
		return nil, &EmptyResponseError{Operation: "update", Resource: "port profile", Endpoint: endpoint}
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
