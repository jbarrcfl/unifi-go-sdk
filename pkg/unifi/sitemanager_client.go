package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
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
type SiteManagerClientConfig struct {
	APIKey       string
	BaseURL      string
	Timeout      time.Duration
	MaxRetries   *int          // nil = default (3), 0 = no retries
	MaxRetryWait time.Duration
	Logger       Logger
}

const (
	defaultBaseURL       = "https://api.ui.com"
	defaultRetries       = 3
	defaultTimeout       = 30 * time.Second
	defaultMaxRetryWait  = 60 * time.Second
	maxErrorBodySize     = 64 * 1024       // 64KB for error responses
	maxResponseBodySize  = 10 * 1024 * 1024 // 10MB for success responses
	baseBackoff          = 1 * time.Second
	maxBackoff           = 30 * time.Second
	jitterFraction       = 0.5
)

var retryAfterRegex = regexp.MustCompile(`retry after ([\d.]+)s`)

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

func (c *SiteManagerClient) do(ctx context.Context, method, path string, result interface{}) error {
	var lastErr error
	maxAttempts := c.maxRetries + 1

	for attempt := 0; attempt < maxAttempts; attempt++ {
		lastErr = c.doOnce(ctx, method, path, result)
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

func isRetryable(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case 429, 502, 503, 504:
			return true
		}
		return false
	}
	return isNetworkError(err)
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

func applyBackoffWithJitter(serverWait time.Duration, attempt int, maxWait time.Duration) time.Duration {
	var wait time.Duration
	if serverWait > 0 {
		wait = serverWait
	} else {
		backoff := baseBackoff << attempt
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		jitter := time.Duration(float64(backoff) * jitterFraction * rand.Float64())
		wait = backoff + jitter
	}
	if wait > maxWait {
		wait = maxWait
	}
	return wait
}

func (c *SiteManagerClient) doOnce(ctx context.Context, method, path string, result interface{}) error {
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

func parseRetryAfterHeader(header string) time.Duration {
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil {
		return time.Duration(secs) * time.Second
	}
	if secs, err := strconv.ParseFloat(header, 64); err == nil {
		return time.Duration(secs * float64(time.Second))
	}
	if t, err := http.ParseTime(header); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
		return 0
	}
	return 0
}

func parseRetryAfterBody(msg string) time.Duration {
	matches := retryAfterRegex.FindStringSubmatch(msg)
	if len(matches) == 2 {
		if secs, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return time.Duration(secs * float64(time.Second))
		}
	}
	return 0
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
