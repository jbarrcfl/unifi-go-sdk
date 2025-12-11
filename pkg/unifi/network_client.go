package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"
)

type NetworkClient struct {
	BaseURL    string
	Site       string
	HTTPClient *http.Client

	username string
	password string
	mu       sync.RWMutex
	loggedIn bool
}

type NetworkClientConfig struct {
	BaseURL            string
	Site               string
	Username           string
	Password           string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

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
		BaseURL:  cfg.BaseURL,
		Site:     site,
		username: cfg.Username,
		password: cfg.Password,
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

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(respBody),
			Err:        ErrUnauthorized,
		}
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

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing logout request: %w", err)
	}
	defer resp.Body.Close()

	c.loggedIn = false
	return nil
}

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

	reqURL := c.BaseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return c.parseErrorResponse(resp.StatusCode, respBody)
	}

	if result != nil {
		var apiResp networkAPIResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}

		if apiResp.Meta.RC != "ok" {
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    apiResp.Meta.Msg,
			}
		}

		if err := json.Unmarshal(apiResp.Data, result); err != nil {
			return fmt.Errorf("unmarshaling response data: %w", err)
		}
	}

	return nil
}

func (c *NetworkClient) parseErrorResponse(statusCode int, body []byte) error {
	var sentinel error
	switch statusCode {
	case 400:
		sentinel = ErrBadRequest
	case 401:
		sentinel = ErrUnauthorized
	case 403:
		sentinel = ErrForbidden
	case 404:
		sentinel = ErrNotFound
	case 429:
		sentinel = ErrRateLimited
	case 500:
		sentinel = ErrServerError
	case 502:
		sentinel = ErrBadGateway
	}

	apiErr := &APIError{
		StatusCode: statusCode,
		Message:    string(body),
	}
	if sentinel != nil {
		apiErr.Err = sentinel
	}
	return apiErr
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
	err := c.do(ctx, "POST", c.restPath("networkconf"), network, &networks)
	if err != nil {
		return nil, err
	}
	if len(networks) == 0 {
		return nil, fmt.Errorf("no network returned from create")
	}
	return &networks[0], nil
}

func (c *NetworkClient) UpdateNetwork(ctx context.Context, id string, network *Network) (*Network, error) {
	var networks []Network
	err := c.do(ctx, "PUT", c.restPathWithID("networkconf", id), network, &networks)
	if err != nil {
		return nil, err
	}
	if len(networks) == 0 {
		return nil, fmt.Errorf("no network returned from update")
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
	err := c.do(ctx, "POST", c.restPath("firewallrule"), rule, &rules)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no firewall rule returned from create")
	}
	return &rules[0], nil
}

func (c *NetworkClient) UpdateFirewallRule(ctx context.Context, id string, rule *FirewallRule) (*FirewallRule, error) {
	var rules []FirewallRule
	err := c.do(ctx, "PUT", c.restPathWithID("firewallrule", id), rule, &rules)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no firewall rule returned from update")
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
	err := c.do(ctx, "POST", c.restPath("firewallgroup"), group, &groups)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("no firewall group returned from create")
	}
	return &groups[0], nil
}

func (c *NetworkClient) UpdateFirewallGroup(ctx context.Context, id string, group *FirewallGroup) (*FirewallGroup, error) {
	var groups []FirewallGroup
	err := c.do(ctx, "PUT", c.restPathWithID("firewallgroup", id), group, &groups)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("no firewall group returned from update")
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
	err := c.do(ctx, "POST", c.restPath("portforward"), forward, &forwards)
	if err != nil {
		return nil, err
	}
	if len(forwards) == 0 {
		return nil, fmt.Errorf("no port forward returned from create")
	}
	return &forwards[0], nil
}

func (c *NetworkClient) UpdatePortForward(ctx context.Context, id string, forward *PortForward) (*PortForward, error) {
	var forwards []PortForward
	err := c.do(ctx, "PUT", c.restPathWithID("portforward", id), forward, &forwards)
	if err != nil {
		return nil, err
	}
	if len(forwards) == 0 {
		return nil, fmt.Errorf("no port forward returned from update")
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
	err := c.do(ctx, "POST", c.restPath("wlanconf"), wlan, &wlans)
	if err != nil {
		return nil, err
	}
	if len(wlans) == 0 {
		return nil, fmt.Errorf("no WLAN returned from create")
	}
	return &wlans[0], nil
}

func (c *NetworkClient) UpdateWLAN(ctx context.Context, id string, wlan *WLANConf) (*WLANConf, error) {
	var wlans []WLANConf
	err := c.do(ctx, "PUT", c.restPathWithID("wlanconf", id), wlan, &wlans)
	if err != nil {
		return nil, err
	}
	if len(wlans) == 0 {
		return nil, fmt.Errorf("no WLAN returned from update")
	}
	return &wlans[0], nil
}

func (c *NetworkClient) DeleteWLAN(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", c.restPathWithID("wlanconf", id), nil, nil)
}
