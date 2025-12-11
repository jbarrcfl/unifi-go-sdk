package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

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

type SiteManagerClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
	MaxRetries int
}

const (
	defaultBaseURL      = "https://api.ui.com"
	defaultRetries      = 3
	defaultRetryWait    = 5 * time.Second
	defaultTimeout      = 30 * time.Second
	maxErrorBodySize    = 64 * 1024
)

var retryAfterRegex = regexp.MustCompile(`retry after ([\d.]+)s`)

func NewSiteManagerClient(apiKey string) *SiteManagerClient {
	return &SiteManagerClient{
		BaseURL:    defaultBaseURL,
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: defaultTimeout},
		MaxRetries: defaultRetries,
	}
}

func (c *SiteManagerClient) do(ctx context.Context, method, path string, result interface{}) error {
	var lastErr error
	maxAttempts := c.MaxRetries + 1

	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := c.doOnce(ctx, method, path, result)
		if err == nil {
			return nil
		}

		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 429 && attempt < maxAttempts-1 {
			wait := parseRetryAfterHeader(apiErr.RetryAfterHeader)
			if wait == 0 {
				wait = parseRetryAfterBody(apiErr.Message)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
				lastErr = err
				continue
			}
		}

		return err
	}

	return lastErr
}

func (c *SiteManagerClient) doOnce(ctx context.Context, method, path string, result interface{}) error {
	reqURL := c.BaseURL + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("X-API-KEY", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		msg := string(body)

		var sentinel error
		switch resp.StatusCode {
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
			StatusCode:       resp.StatusCode,
			Message:          msg,
			RetryAfterHeader: resp.Header.Get("Retry-After"),
		}
		if sentinel != nil {
			apiErr.Err = sentinel
		}
		return apiErr
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
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
	return 0
}

func parseRetryAfterBody(msg string) time.Duration {
	matches := retryAfterRegex.FindStringSubmatch(msg)
	if len(matches) == 2 {
		if secs, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return time.Duration(secs * float64(time.Second))
		}
	}
	return defaultRetryWait
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

	err := c.do(ctx, "GET", "/v1/hosts/"+id, &response)
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
