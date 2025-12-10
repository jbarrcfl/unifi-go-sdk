package unifi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

const (
	defaultBaseURL = "https://api.ui.com"
)

func NewClient(apiKey string) *Client {
	return &Client{
		baseURL:    defaultBaseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

func (c *Client) do(ctx context.Context, method, path string, result interface{}) error {
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		msg := string(body)

		var sentinel error
		switch resp.StatusCode {
		case 400:
			sentinel = ErrBadRequest
		case 401:
			sentinel = ErrUnauthorized
		case 429:
			sentinel = ErrRateLimited
		case 500:
			sentinel = ErrServerError
		case 502:
			sentinel = ErrBadGateway
		}

		if sentinel != nil {
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    msg,
				Err:        sentinel,
			}
		}

		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    msg,
		}
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}

func (c *Client) ListHosts(ctx context.Context, opts *ListHostsOptions) (*ListHostsResponse, error) {
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

func (c *Client) ListAllHosts(ctx context.Context) ([]Host, error) {
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

func (c *Client) GetHost(ctx context.Context, id string) (*GetHostResponse, error) {
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
