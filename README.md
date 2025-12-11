# UniFi Go SDK

[![CI](https://github.com/resnickio/unifi-go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/resnickio/unifi-go-sdk/actions/workflows/ci.yml)

Go SDK for the [UniFi Site Manager API](https://developer.ui.com/site-manager-api/gettingstarted).

## Purpose

This SDK is designed to support a Terraform provider for UniFi infrastructure management. Architectural decisions—such as reactive rate limiting, typed responses with pointer fields for nullable values, and sentinel errors—reflect Terraform provider requirements. While the SDK can be used standalone, its primary goal is enabling declarative infrastructure-as-code for UniFi deployments.

## Installation

```bash
go get github.com/resnickio/unifi-go-sdk
```

## Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/resnickio/unifi-go-sdk/pkg/unifi"
)

func main() {
    client := unifi.NewSiteManagerClient("your-api-key")

    // List all hosts
    hosts, err := client.ListAllHosts(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    for _, host := range hosts {
        fmt.Printf("Host: %s (%s)\n", host.ID, host.Type)
    }

    // Get a specific host
    resp, err := client.GetHost(context.Background(), "host-id")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Host: %s\n", resp.Host.ID)

    // List all sites
    sites, err := client.ListAllSites(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    for _, site := range sites {
        fmt.Printf("Site: %s (%s)\n", site.SiteID, site.Meta.Name)
    }
}
```

## API Methods

| Method | Description |
|--------|-------------|
| `ListHosts(ctx, opts)` | List hosts with pagination |
| `ListAllHosts(ctx)` | List all hosts (handles pagination) |
| `GetHost(ctx, id)` | Get a single host by ID |
| `ListSites(ctx, opts)` | List sites with pagination |
| `ListAllSites(ctx)` | List all sites (handles pagination) |
| `ListDevices(ctx, opts)` | List devices grouped by host |
| `ListAllDevices(ctx)` | List all devices (handles pagination) |

## Error Handling

The SDK provides sentinel errors for common HTTP status codes:

```go
resp, err := client.GetHost(ctx, "invalid-id")
if errors.Is(err, unifi.ErrNotFound) {
    // Handle 404
}
if errors.Is(err, unifi.ErrUnauthorized) {
    // Handle 401
}
```

Available errors:
- `ErrBadRequest` (400)
- `ErrUnauthorized` (401)
- `ErrForbidden` (403)
- `ErrNotFound` (404)
- `ErrRateLimited` (429)
- `ErrServerError` (500)
- `ErrBadGateway` (502)

For detailed error information, use `errors.As`:

```go
var apiErr *unifi.APIError
if errors.As(err, &apiErr) {
    fmt.Printf("Status: %d, Message: %s\n", apiErr.StatusCode, apiErr.Message)
}
```

## Rate Limiting

The SDK automatically retries requests that receive a 429 (rate limited) response. By default, it will retry up to 3 times with exponential backoff and jitter to prevent thundering herd issues.

The retry delay is calculated as:
1. Parse `Retry-After` header (supports integer seconds, fractional seconds, and HTTP-date format)
2. Fall back to parsing delay from response body
3. If server specifies a delay, use it exactly (no modification)
4. Otherwise, apply exponential backoff (1s, 2s, 4s...) with up to 50% jitter, capped at 30s

```go
client := unifi.NewSiteManagerClient("your-api-key")
client.MaxRetries = 5 // increase retries
client.MaxRetries = 0 // disable retries
```

## Timeouts

The default HTTP client has a 30 second timeout. You can customize this:

```go
client := unifi.NewSiteManagerClient("your-api-key")
client.HTTPClient = &http.Client{
    Timeout: 60 * time.Second,
}
```

## API Key

Get your API key from the [UniFi Site Manager](https://unifi.ui.com).

## Status

**Site Manager API** (cloud): Complete. All v1 read-only endpoints implemented.

**Network API** (local controller): In progress. Session-based authentication and CRUD operations for networks, firewall rules, firewall groups, port forwards, and WLANs are implemented. See [#1](https://github.com/resnickio/unifi-go-sdk/issues/1) for tracking.

## Model Provenance

Models in this SDK are hand-written based on:
- **Site Manager API**: [Ubiquiti developer documentation](https://developer.ui.com/site-manager-api/gettingstarted) and observed API responses
- **Network API**: Observed responses from the UniFi Network Application REST API (`/proxy/network/api/s/{site}/rest/*`)

No official OpenAPI specification exists for the Site Manager API. The Network API has an OpenAPI spec at `/proxy/network/api-docs/integration.json`, but we use the legacy REST API for write operations which is not covered by that spec.

## License

MIT
