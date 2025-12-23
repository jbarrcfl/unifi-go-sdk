package unifi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// SiteManager defines the interface for the UniFi Site Manager API.
// This cloud-based API provides read-only access to hosts, sites, and devices.
type SiteManager interface {
	ListHosts(ctx context.Context, opts *ListHostsOptions) (*ListHostsResponse, error)
	ListAllHosts(ctx context.Context) ([]Host, error)
	GetHost(ctx context.Context, id string) (*GetHostResponse, error)
	ListSites(ctx context.Context, opts *ListSitesOptions) (*ListSitesResponse, error)
	ListAllSites(ctx context.Context) ([]Site, error)
	ListDevices(ctx context.Context, opts *ListDevicesOptions) (*ListDevicesResponse, error)
	ListAllDevices(ctx context.Context) ([]HostDevices, error)
}

var _ SiteManager = (*SiteManagerClient)(nil)

// SiteManagerClient is a client for the UniFi Site Manager API.
// It handles authentication, pagination, and rate limit retry with exponential backoff.
type SiteManagerClient struct {
	BaseURL      string
	APIKey       string
	HTTPClient   *http.Client
	Logger       Logger
	maxRetries   int
	maxRetryWait time.Duration
}

// SiteManagerClientConfig contains configuration options for creating a SiteManagerClient.
//
// Note: Unlike NetworkClientConfig, InsecureSkipVerify is intentionally not supported
// because the Site Manager API is hosted at api.ui.com with valid TLS certificates.
// For proxy or testing scenarios, configure a custom HTTP client with the desired
// transport settings.
type SiteManagerClientConfig struct {
	APIKey       string
	BaseURL      string
	Timeout      time.Duration
	MaxRetries   *int          // nil = default (3), 0 = no retries
	MaxRetryWait time.Duration
	Logger       Logger
}

const (
	defaultBaseURL      = "https://api.ui.com"
	defaultRetries      = 3
	defaultMaxRetryWait = 60 * time.Second
)

// NewSiteManagerClient creates a new Site Manager API client with the given configuration.
func NewSiteManagerClient(cfg SiteManagerClientConfig) (*SiteManagerClient, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("APIKey is required")
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	maxRetries := defaultRetries
	if cfg.MaxRetries != nil {
		maxRetries = *cfg.MaxRetries
	}

	maxRetryWait := cfg.MaxRetryWait
	if maxRetryWait == 0 {
		maxRetryWait = defaultMaxRetryWait
	}

	return &SiteManagerClient{
		BaseURL:      baseURL,
		APIKey:       cfg.APIKey,
		HTTPClient:   &http.Client{Timeout: timeout},
		Logger:       cfg.Logger,
		maxRetries:   maxRetries,
		maxRetryWait: maxRetryWait,
	}, nil
}

func (c *SiteManagerClient) do(ctx context.Context, method, path string, result any) error {
	return executeWithRetry(ctx, c.Logger, c.maxRetries, c.maxRetryWait, func() error {
		return c.doOnce(ctx, method, path, result)
	})
}

func (c *SiteManagerClient) doOnce(ctx context.Context, method, path string, result any) error {
	reqURL := c.BaseURL + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("X-API-KEY", c.APIKey)
	req.Header.Set("Accept", "application/json")

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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return &APIError{
			StatusCode:       resp.StatusCode,
			Message:          string(body),
			RetryAfterHeader: resp.Header.Get("Retry-After"),
			Err:              sentinelForStatusCode(resp.StatusCode),
		}
	}

	if result != nil {
		limitedBody := io.LimitReader(resp.Body, maxResponseBodySize)
		if err := json.NewDecoder(limitedBody).Decode(result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}


func (c *SiteManagerClient) ListHosts(ctx context.Context, opts *ListHostsOptions) (*ListHostsResponse, error) {
	var response struct {
		Data           []Host  `json:"data"`
		HTTPStatusCode int     `json:"httpStatusCode"`
		TraceID        string  `json:"traceId"`
		NextToken      *string `json:"nextToken,omitempty"`
	}

	path := "/v1/hosts"
	params := url.Values{}
	if opts != nil {
		if opts.PageSize > 0 {
			params.Set("pageSize", strconv.Itoa(opts.PageSize))
		}
		if opts.NextToken != "" {
			params.Set("nextToken", opts.NextToken)
		}
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	err := c.do(ctx, "GET", path, &response)
	if err != nil {
		return nil, err
	}

	result := &ListHostsResponse{
		Hosts:   response.Data,
		TraceID: response.TraceID,
	}
	if response.NextToken != nil {
		result.NextToken = *response.NextToken
	}

	return result, nil
}

func (c *SiteManagerClient) ListAllHosts(ctx context.Context) ([]Host, error) {
	var allHosts []Host
	var nextToken string

	for {
		opts := &ListHostsOptions{NextToken: nextToken}
		resp, err := c.ListHosts(ctx, opts)
		if err != nil {
			return nil, err
		}

		allHosts = append(allHosts, resp.Hosts...)

		if resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}

	return allHosts, nil
}

func (c *SiteManagerClient) GetHost(ctx context.Context, id string) (*GetHostResponse, error) {
	var response struct {
		Data           Host   `json:"data"`
		HTTPStatusCode int    `json:"httpStatusCode"`
		TraceID        string `json:"traceId"`
	}

	err := c.do(ctx, "GET", "/v1/hosts/"+url.PathEscape(id), &response)
	if err != nil {
		return nil, err
	}

	return &GetHostResponse{
		Host:    &response.Data,
		TraceID: response.TraceID,
	}, nil
}

func (c *SiteManagerClient) ListSites(ctx context.Context, opts *ListSitesOptions) (*ListSitesResponse, error) {
	var response struct {
		Data           []Site  `json:"data"`
		HTTPStatusCode int     `json:"httpStatusCode"`
		TraceID        string  `json:"traceId"`
		NextToken      *string `json:"nextToken,omitempty"`
	}

	path := "/v1/sites"
	params := url.Values{}
	if opts != nil {
		if opts.PageSize > 0 {
			params.Set("pageSize", strconv.Itoa(opts.PageSize))
		}
		if opts.NextToken != "" {
			params.Set("nextToken", opts.NextToken)
		}
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	err := c.do(ctx, "GET", path, &response)
	if err != nil {
		return nil, err
	}

	result := &ListSitesResponse{
		Sites:   response.Data,
		TraceID: response.TraceID,
	}
	if response.NextToken != nil {
		result.NextToken = *response.NextToken
	}

	return result, nil
}

func (c *SiteManagerClient) ListAllSites(ctx context.Context) ([]Site, error) {
	var allSites []Site
	var nextToken string

	for {
		opts := &ListSitesOptions{NextToken: nextToken}
		resp, err := c.ListSites(ctx, opts)
		if err != nil {
			return nil, err
		}

		allSites = append(allSites, resp.Sites...)

		if resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}

	return allSites, nil
}

func (c *SiteManagerClient) ListDevices(ctx context.Context, opts *ListDevicesOptions) (*ListDevicesResponse, error) {
	var response struct {
		Data           []HostDevices `json:"data"`
		HTTPStatusCode int           `json:"httpStatusCode"`
		TraceID        string        `json:"traceId"`
		NextToken      *string       `json:"nextToken,omitempty"`
	}

	path := "/v1/devices"
	params := url.Values{}
	if opts != nil {
		if opts.PageSize > 0 {
			params.Set("pageSize", strconv.Itoa(opts.PageSize))
		}
		if opts.NextToken != "" {
			params.Set("nextToken", opts.NextToken)
		}
		for _, hostID := range opts.HostIDs {
			params.Add("hostIds", hostID)
		}
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	err := c.do(ctx, "GET", path, &response)
	if err != nil {
		return nil, err
	}

	result := &ListDevicesResponse{
		HostDevices: response.Data,
		TraceID:     response.TraceID,
	}
	if response.NextToken != nil {
		result.NextToken = *response.NextToken
	}

	return result, nil
}

func (c *SiteManagerClient) ListAllDevices(ctx context.Context) ([]HostDevices, error) {
	var allHostDevices []HostDevices
	var nextToken string

	for {
		opts := &ListDevicesOptions{NextToken: nextToken}
		resp, err := c.ListDevices(ctx, opts)
		if err != nil {
			return nil, err
		}

		allHostDevices = append(allHostDevices, resp.HostDevices...)

		if resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}

	return allHostDevices, nil
}
