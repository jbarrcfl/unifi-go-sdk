# UniFi Go SDK

[![CI](https://github.com/resnickio/unifi-go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/resnickio/unifi-go-sdk/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/resnickio/unifi-go-sdk)](https://goreportcard.com/report/github.com/resnickio/unifi-go-sdk)
[![Go Reference](https://pkg.go.dev/badge/github.com/resnickio/unifi-go-sdk.svg)](https://pkg.go.dev/github.com/resnickio/unifi-go-sdk)

Go SDK for the [UniFi Site Manager API](https://developer.ui.com/site-manager-api/gettingstarted).

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
    client := unifi.NewClient("your-api-key")

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

The SDK automatically retries requests that receive a 429 (rate limited) response. By default, it will retry up to 3 times, using the retry delay specified by the API.

```go
client := unifi.NewClient("your-api-key")
client.MaxRetries = 5 // increase retries
client.MaxRetries = 0 // disable retries
```

## Custom HTTP Client

You can customize the HTTP client for timeouts or proxies:

```go
client := unifi.NewClient("your-api-key")
client.HTTPClient = &http.Client{
    Timeout: 30 * time.Second,
}
```

## API Key

Get your API key from the [UniFi Site Manager](https://unifi.ui.com).

## License

MIT
