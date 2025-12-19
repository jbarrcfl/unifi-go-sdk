# UniFi Go SDK

[![CI](https://github.com/resnickio/unifi-go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/resnickio/unifi-go-sdk/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/resnickio/unifi-go-sdk.svg)](https://pkg.go.dev/github.com/resnickio/unifi-go-sdk)
[![Go Report Card](https://goreportcard.com/badge/github.com/resnickio/unifi-go-sdk)](https://goreportcard.com/report/github.com/resnickio/unifi-go-sdk)
[![Known Vulnerabilities](https://snyk.io/test/github/resnickio/unifi-go-sdk/badge.svg)](https://snyk.io/test/github/resnickio/unifi-go-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Go SDK for UniFi APIs:
- **Site Manager API** - Cloud-based API for managing hosts, sites, and devices across your UniFi deployment
- **Network API** - Local controller API for managing networks, firewall rules, WLANs, and more

## Purpose

This SDK is designed to support a Terraform provider for UniFi infrastructure management. Architectural decisions—such as reactive rate limiting, typed responses with pointer fields for nullable values, and sentinel errors—reflect Terraform provider requirements. While the SDK can be used standalone, its primary goal is enabling declarative infrastructure-as-code for UniFi deployments.

## Installation

```bash
go get github.com/resnickio/unifi-go-sdk
```

## Site Manager API Usage

The Site Manager API is a cloud-based API for read-only access to hosts, sites, and devices.

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/resnickio/unifi-go-sdk/pkg/unifi"
)

func main() {
    client, err := unifi.NewSiteManagerClient(unifi.SiteManagerClientConfig{
        APIKey: "your-api-key",
    })
    if err != nil {
        log.Fatal(err)
    }

    // List all hosts
    hosts, err := client.ListAllHosts(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    for _, host := range hosts {
        fmt.Printf("Host: %s (%s)\n", host.ID, host.Type)
    }

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

### Site Manager Methods

| Method | Description |
|--------|-------------|
| `ListHosts(ctx, opts)` | List hosts with pagination |
| `ListAllHosts(ctx)` | List all hosts (handles pagination) |
| `GetHost(ctx, id)` | Get a single host by ID |
| `ListSites(ctx, opts)` | List sites with pagination |
| `ListAllSites(ctx)` | List all sites (handles pagination) |
| `ListDevices(ctx, opts)` | List devices grouped by host |
| `ListAllDevices(ctx)` | List all devices (handles pagination) |

#### Manual Pagination

For fine-grained control over pagination, use the `List*` methods with options:

```go
var allHosts []unifi.Host
var nextPage *string

for {
    hosts, err := client.ListHosts(ctx, unifi.ListHostsOptions{
        PageToken: nextPage,
        PageSize:  100,
    })
    if err != nil {
        log.Fatal(err)
    }
    allHosts = append(allHosts, hosts.Data...)

    if hosts.NextPage == nil {
        break
    }
    nextPage = hosts.NextPage
}
```

Get your API key from the [UniFi Site Manager](https://unifi.ui.com).

## Network API Usage

The Network API connects directly to a UniFi controller for full CRUD operations on network configuration. It supports two authentication methods:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/resnickio/unifi-go-sdk/pkg/unifi"
)

func main() {
    // Option 1: API key authentication (preferred - avoids login rate limits)
    client, err := unifi.NewNetworkClient(unifi.NetworkClientConfig{
        BaseURL:            "https://192.168.1.1",
        APIKey:             "your-api-key",
        InsecureSkipVerify: true, // for self-signed certs
    })

    // Option 2: Username/password authentication
    // client, err := unifi.NewNetworkClient(unifi.NetworkClientConfig{
    //     BaseURL:            "https://192.168.1.1",
    //     Username:           "admin",
    //     Password:           "password",
    //     InsecureSkipVerify: true,
    // })
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Login is a no-op with API key auth, but safe to call either way
    if err := client.Login(ctx); err != nil {
        log.Fatal(err)
    }
    defer client.Logout(ctx)

    // List networks
    networks, err := client.ListNetworks(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Found %d networks\n", len(networks))

    // Create a firewall rule
    enabled := true
    rule, err := client.CreateFirewallRule(ctx, &unifi.FirewallRule{
        Name:    "Block IOT to LAN",
        Enabled: &enabled,
        Action:  "drop",
        Ruleset: "LAN_IN",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Created rule: %s\n", rule.ID)
}
```

### Network Methods

#### Legacy REST API (full CRUD)

| Resource | Methods |
|----------|---------|
| Networks | `ListNetworks`, `GetNetwork`, `CreateNetwork`, `UpdateNetwork`, `DeleteNetwork` |
| Firewall Rules | `ListFirewallRules`, `GetFirewallRule`, `CreateFirewallRule`, `UpdateFirewallRule`, `DeleteFirewallRule` |
| Firewall Groups | `ListFirewallGroups`, `GetFirewallGroup`, `CreateFirewallGroup`, `UpdateFirewallGroup`, `DeleteFirewallGroup` |
| Port Forwards | `ListPortForwards`, `GetPortForward`, `CreatePortForward`, `UpdatePortForward`, `DeletePortForward` |
| WLANs | `ListWLANs`, `GetWLAN`, `CreateWLAN`, `UpdateWLAN`, `DeleteWLAN` |
| Port Profiles | `ListPortConfs`, `GetPortConf`, `CreatePortConf`, `UpdatePortConf`, `DeletePortConf` |
| Static Routes | `ListRoutes`, `GetRoute`, `CreateRoute`, `UpdateRoute`, `DeleteRoute` |
| User Groups | `ListUserGroups`, `GetUserGroup`, `CreateUserGroup`, `UpdateUserGroup`, `DeleteUserGroup` |
| RADIUS Profiles | `ListRADIUSProfiles`, `GetRADIUSProfile`, `CreateRADIUSProfile`, `UpdateRADIUSProfile`, `DeleteRADIUSProfile` |
| Dynamic DNS | `ListDynamicDNS`, `GetDynamicDNS`, `CreateDynamicDNS`, `UpdateDynamicDNS`, `DeleteDynamicDNS` |

#### v2 API (zone-based firewall, modern features)

| Resource | Methods |
|----------|---------|
| Firewall Policies | `ListFirewallPolicies`, `GetFirewallPolicy`, `CreateFirewallPolicy`, `UpdateFirewallPolicy`, `DeleteFirewallPolicy` |
| Firewall Zones | `ListFirewallZones`, `GetFirewallZone`, `CreateFirewallZone`, `UpdateFirewallZone`, `DeleteFirewallZone` |
| Static DNS | `ListStaticDNS`, `GetStaticDNS`, `CreateStaticDNS`, `UpdateStaticDNS`, `DeleteStaticDNS` |
| Traffic Rules | `ListTrafficRules`, `GetTrafficRule`, `CreateTrafficRule`, `UpdateTrafficRule`, `DeleteTrafficRule` |
| Traffic Routes | `ListTrafficRoutes`, `GetTrafficRoute`, `CreateTrafficRoute`, `UpdateTrafficRoute`, `DeleteTrafficRoute` |
| NAT Rules | `ListNatRules`, `GetNatRule`, `CreateNatRule`, `UpdateNatRule`, `DeleteNatRule` |
| Active Clients | `ListActiveClients` (read-only) |
| Network Devices | `ListNetworkDevices` (read-only) |
| ACL Rules | `ListAclRules` (read-only) |
| QoS Rules | `ListQosRules` (read-only) |
| Content Filtering | `GetContentFiltering` (read-only) |
| VPN Connections | `ListVpnConnections` (read-only) |
| WAN SLAs | `ListWanSlas` (read-only) |

### Network API Examples

#### Create a VLAN Network

```go
enabled := true
vlan := 100
dhcpEnabled := true
network, err := client.CreateNetwork(ctx, &unifi.Network{
    Name:         "IoT Network",
    Purpose:      "corporate",
    Enabled:      &enabled,
    VLAN:         &vlan,
    VLANEnabled:  &enabled,
    IPSubnet:     "10.0.100.1/24",
    DHCPDEnabled: &dhcpEnabled,
    DHCPDStart:   "10.0.100.100",
    DHCPDStop:    "10.0.100.254",
})
```

#### Create a Wireless Network (SSID)

```go
enabled := true
wlan, err := client.CreateWLAN(ctx, &unifi.WLANConf{
    Name:        "Guest WiFi",
    Enabled:     &enabled,
    Security:    "wpapsk",
    WPAMode:     "wpa2",
    XPassphrase: "guest-password-here",
    IsGuest:     &enabled,
})
```

#### Create a Port Forward

```go
enabled := true
forward, err := client.CreatePortForward(ctx, &unifi.PortForward{
    Name:    "Web Server",
    Enabled: &enabled,
    Proto:   "tcp",
    DstPort: "443",
    Fwd:     "192.168.1.100",
    FwdPort: "443",
})
```

#### Create a Static Route

```go
enabled := true
route, err := client.CreateRoute(ctx, &unifi.Routing{
    Name:               "VPN Route",
    Enabled:            &enabled,
    StaticRouteNetwork: "10.10.0.0/16",
    StaticRouteNexthop: "192.168.1.254",
})
```

#### Create a Firewall Group

```go
group, err := client.CreateFirewallGroup(ctx, &unifi.FirewallGroup{
    Name:         "Blocked IPs",
    GroupType:    "address-group",
    GroupMembers: []string{"1.2.3.4", "5.6.7.8"},
})
```

#### Create a Port Profile

```go
enabled := true
profile, err := client.CreatePortConf(ctx, &unifi.PortConf{
    Name:            "Trunk Ports",
    Forward:         "all",
    NativeNetworkID: "default-network-id",
    TaggedNetworks:  []string{"vlan100-id", "vlan200-id"},
    Dot1XCtrl:       "force_authorized",
    PortSecurityEnabled: &enabled,
})
```

#### Create a Firewall Policy (v2 API) with Builder

For complex structs like `FirewallPolicy`, use the fluent builder API:

```go
policy := unifi.NewFirewallPolicyBuilder().
    Name("Block IoT to LAN").
    Action("DROP").
    Protocol("all").
    Logging(true).
    SourceFrom(
        unifi.NewPolicyEndpointBuilder().
            ZoneID("iot-zone-id").
            MatchingTarget("ANY"),
    ).
    DestinationFrom(
        unifi.NewPolicyEndpointBuilder().
            ZoneID("lan-zone-id").
            Port("22").
            PortMatchingType("SPECIFIC"),
    ).
    Build()

created, err := client.CreateFirewallPolicy(ctx, &policy)
```

Builders provide sensible defaults (e.g., `Enabled=true`, `IPVersion=IPv4`) and support method chaining for readable configuration. Available builders:
- `NewFirewallPolicyBuilder()` - Zone-based firewall policies
- `NewPolicyEndpointBuilder()` - Source/destination endpoint configuration
- `NewPolicyScheduleBuilder()` - Time-based scheduling with `Always()` and `Custom()` helpers

### Interfaces for Mocking

Both clients implement interfaces for easy mocking in tests:

```go
var _ unifi.SiteManager = (*unifi.SiteManagerClient)(nil)
var _ unifi.NetworkManager = (*unifi.NetworkClient)(nil)
```

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
- `ErrMethodNotAllowed` (405)
- `ErrConflict` (409)
- `ErrRateLimited` (429)
- `ErrServerError` (500)
- `ErrBadGateway` (502)
- `ErrServiceUnavail` (503)
- `ErrGatewayTimeout` (504)
- `ErrEmptyResponse` (API returned success with empty data)

For detailed error information, use `errors.As`:

```go
var apiErr *unifi.APIError
if errors.As(err, &apiErr) {
    fmt.Printf("Status: %d, Message: %s\n", apiErr.StatusCode, apiErr.Message)
}
```

## Retry Logic

Both clients automatically retry transient errors (502, 503, 504) and rate limit responses (429). By default, they retry up to 3 times with exponential backoff and jitter to prevent thundering herd issues.

Both clients parse `Retry-After` headers from 429 responses:
1. Parse `Retry-After` header (supports integer seconds, fractional seconds, and HTTP-date format)
2. Fall back to parsing delay from response body
3. If server specifies a delay, use it exactly
4. Otherwise, apply exponential backoff (1s, 2s, 4s...) with 0-50% additional jitter, capped at 60s

`MaxRetries` is `*int` — omit for default (3), or use the `IntPtr` helper to override (including `0` for no retries).

```go
// Customize retries
client, _ := unifi.NewSiteManagerClient(unifi.SiteManagerClientConfig{
    APIKey:       "your-api-key",
    MaxRetries:   unifi.IntPtr(5),      // default: 3 (nil), use 0 for no retries
    MaxRetryWait: 120 * time.Second,    // custom max wait (default: 60s)
})
```

## Timeouts

The default HTTP client has a 30 second timeout. You can customize this:

```go
client, _ := unifi.NewSiteManagerClient(unifi.SiteManagerClientConfig{
    APIKey:  "your-api-key",
    Timeout: 60 * time.Second,
})
```

For per-request timeouts, use context:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

hosts, err := client.ListAllHosts(ctx)
if errors.Is(err, context.DeadlineExceeded) {
    // Handle timeout
}
```

## Debug Logging

Both clients support optional debug logging. Set the `Logger` field to receive request/response logs:

```go
// Site Manager with logging
client, _ := unifi.NewSiteManagerClient(unifi.SiteManagerClientConfig{
    APIKey: "your-api-key",
    Logger: unifi.NewStdLogger(),
})

// Network Client with logging
client, _ := unifi.NewNetworkClient(unifi.NetworkClientConfig{
    BaseURL: "https://192.168.1.1",
    APIKey:  "your-api-key",
    Logger:  unifi.NewStdLogger(),
})

// Or implement your own Logger interface
type Logger interface {
    Printf(format string, v ...any)
}

// Example: structured JSON logger
type JSONLogger struct{}

func (l *JSONLogger) Printf(format string, v ...any) {
    msg := fmt.Sprintf(format, v...)
    json.NewEncoder(os.Stderr).Encode(map[string]string{
        "level": "debug",
        "msg":   msg,
    })
}
```

Log output format:
```
[unifi] 2024/01/15 10:30:00 -> GET https://api.ui.com/v1/hosts
[unifi] 2024/01/15 10:30:01 <- 200 OK
```

## Rate Limits

The Site Manager API has the following rate limits:
- **v1 endpoints**: 10,000 requests per minute
- **EA (Early Access) endpoints**: 100 requests per minute

The SDK automatically handles rate limit responses (429) by respecting `Retry-After` headers and retrying with exponential backoff. No manual rate limiting is required.

## Status

| API | Status | Description |
|-----|--------|-------------|
| Site Manager | Complete | All v1 read-only endpoints (hosts, sites, devices) |
| Network | Complete | API key or session auth, networks, firewall rules/groups, port forwards, WLANs, port profiles, routes, user groups, RADIUS, DDNS |

## OpenAPI Specifications

This repository includes comprehensive OpenAPI 3.0 specifications in the `openapi/` directory:

| Spec | Description |
|------|-------------|
| `unifi-sitemanager-api.yaml` | Site Manager cloud API - hosts, sites, devices |
| `unifi-network-api.yaml` | Network controller API - Policy Engine v2 + legacy REST |

### Network API Coverage

The Network API spec documents two API versions:

**v2 API** (Policy Engine - zone-based firewall):
- Firewall policies, zones, traffic rules, traffic routes
- NAT rules, static DNS, ACL rules, QoS rules
- Active clients, devices, VPN connections

**Legacy REST API** (full CRUD):
- Networks, firewall groups, WLANs, port forwards
- Static routes, port profiles, user groups
- RADIUS profiles, dynamic DNS

### Using the Specs

The OpenAPI specs serve as the source of truth for API contracts. When implementing new endpoints:

1. Consult the relevant spec for endpoint paths and schemas
2. Use schema definitions to derive Go struct fields
3. For undocumented endpoints, use browser automation to capture live API responses

### Spec Provenance

These specifications were derived from live API responses captured via Playwright browser automation against a UniFi Dream Machine SE running Network 9.5.21. They document endpoints not covered by Ubiquiti's official Integration API spec.

## License

MIT

## Development

This SDK was developed with AI assistance. If you encounter bugs or have feature requests, please [open an issue](https://github.com/resnickio/unifi-go-sdk/issues).
