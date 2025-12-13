# UniFi Go SDK

Go SDK for UniFi APIs (Site Manager and Network).

## Structure

- `pkg/unifi/` - SDK package
  - `sitemanager_client.go` - Cloud API client
  - `sitemanager_models.go` - Cloud API models
  - `network_client.go` - Controller API client
  - `network_models.go` - Controller API models
  - `errors.go` - Sentinel errors
  - `logger.go` - Logger interface and StdLogger
- `openapi/` - OpenAPI specifications (source of truth for API contracts)
  - `unifi-sitemanager-api.yaml` - Site Manager cloud API spec
  - `unifi-network-api.yaml` - Network controller API spec (v2 + legacy REST)
- `cmd/example/` - Test harness (requires `UNIFI_API_KEY` env var)
- `cmd/validate/` - API drift detection tool (requires `UNIFI_API_KEY` env var)

## API Documentation

- Site Manager API: https://developer.ui.com/site-manager-api/gettingstarted
- Network API:
  - Legacy REST: `/proxy/network/api/s/{site}/rest/*`
  - v2 API: `/proxy/network/v2/api/site/{site}/*`

## UniFi API Landscape

Two distinct APIs, both implemented:

1. **Site Manager API** (cloud)
   - Base: `https://api.ui.com/v1/`
   - Auth: API key via `X-API-KEY` header
   - Read-only: hosts, sites, devices
   - Rate limits: 10K req/min (v1), 100 req/min (EA endpoints)

2. **Network API** (local controller)
   - Legacy REST Base: `https://<controller>/proxy/network/api/s/{site}/rest/`
   - v2 API Base: `https://<controller>/proxy/network/v2/api/site/{site}/`
   - Auth: Session-based (username/password → cookie)
   - Legacy REST CRUD: networks, firewall rules/groups, port forwards, WLANs, port profiles, routes, user groups, RADIUS, DDNS
   - v2 API CRUD: firewall policies (zone-based), firewall zones, static DNS, traffic rules, traffic routes, NAT rules
   - v2 API Read-only: active clients, network devices, ACL rules, QoS rules, content filtering, VPN connections, WAN SLAs

## Build & Test

```bash
go build ./...
go test -v -race ./pkg/...
```

## Run Example

```bash
UNIFI_API_KEY=your-key go run cmd/example/main.go
```

## Downstream Usage

This SDK is intended to support a Terraform provider. Prioritize type safety with pointers for nullable JSON fields.

## SDK Features

- `SiteManagerClient` - Cloud API with automatic pagination, rate limit retry with exponential backoff + jitter
- `NetworkClient` - Controller API with session-based auth, full CRUD operations, retry with exponential backoff + jitter
- Sentinel errors for common HTTP status codes
- Configurable retry logic (MaxRetries, MaxRetryWait) on both clients
- Configurable debug logging via Logger interface
- 30s default HTTP timeout

## Architecture Decisions

- **OpenAPI-driven development**: The `openapi/` directory contains authoritative API specifications. When adding new endpoints or models, consult these specs first. They were derived from live API responses via Playwright browser automation.
- **Reactive rate limiting over proactive**: Terraform's sequential execution model rarely hits limits. Reactive retry with exponential backoff + jitter adapts automatically.
- **Interface-first**: `SiteManager` and `NetworkManager` interfaces enable mocking without test dependencies on real API.
- **Session-based auth for Network API**: The official Integration API is read-only. Legacy REST API with cookie auth supports writes.

## Preferences

- **OpenAPI-first development**: When implementing new API endpoints:
  1. Read the relevant OpenAPI spec (`openapi/*.yaml`) to understand the endpoint contract
  2. Use schema definitions to generate Go struct fields with correct types and JSON tags
  3. For Policy Engine v2 endpoints, reference `unifi-network-api.yaml` schemas like `FirewallPolicy`, `FirewallZone`, `PolicyEndpoint`
  4. For legacy REST endpoints, reference schemas like `Network`, `FirewallGroup`, `Wlan`, `PortForward`
  5. To discover new/undocumented endpoints, use Playwright to capture API responses from the UniFi UI
- **Context7 MCP**: When generating code that uses external libraries, or when needing up-to-date API documentation, configuration examples, or setup steps for any library/framework, automatically use Context7 MCP tools (`resolve-library-id` then `get-library-docs`) to fetch current documentation. Do not rely solely on training data for library APIs.
- **Playwright MCP**: Use Playwright MCP tools for browser automation tasks: testing web UIs, scraping dynamic content, filling forms, taking screenshots, or interacting with web applications. Prefer `browser_snapshot` over screenshots for actionable page state. Use `browser_fill_form` for multiple fields, `browser_click`/`browser_type` for interactions, and `browser_evaluate` for custom JavaScript. Always call `browser_close` when finished. Use `browser_evaluate` with `fetch()` to capture API responses from authenticated sessions.
- **Commits**: Do not include Claude Code citations or co-author tags
- **Code style**: Minimal comments, no inline comments unless truly necessary
- **Go idioms**: Prefer exported fields over setter methods for simplicity. Skip helper functions (like `IsNotFound()`) - use standard `errors.Is()` patterns instead
- **Testing**: Use `httptest` for mocking. Export struct fields to allow test configuration
- **CI**: Keep simple - build and test only. Avoid paid services (Codecov, etc.) unless explicitly requested
- **Over-engineering**: Avoid. Don't add abstractions, helpers, or features beyond what's requested
- **Error handling**: Limit response body reads to prevent memory exhaustion (64KB for errors, 10MB for success responses)
- **File naming**: Use `{api}_client.go`, `{api}_models.go` pattern (e.g., `sitemanager_client.go`, `network_client.go`)

## Status

Both APIs complete:

**Site Manager API**
- `ListHosts`, `ListAllHosts`, `GetHost`
- `ListSites`, `ListAllSites`
- `ListDevices`, `ListAllDevices`

**Network API (Legacy REST)**
- `Login`, `Logout`, `IsLoggedIn`
- Networks: `List`, `Get`, `Create`, `Update`, `Delete`
- Firewall Rules: `List`, `Get`, `Create`, `Update`, `Delete`
- Firewall Groups: `List`, `Get`, `Create`, `Update`, `Delete`
- Port Forwards: `List`, `Get`, `Create`, `Update`, `Delete`
- WLANs: `List`, `Get`, `Create`, `Update`, `Delete`
- Port Profiles: `List`, `Get`, `Create`, `Update`, `Delete`
- Static Routes: `List`, `Get`, `Create`, `Update`, `Delete`
- User Groups: `List`, `Get`, `Create`, `Update`, `Delete`
- RADIUS Profiles: `List`, `Get`, `Create`, `Update`, `Delete`
- Dynamic DNS: `List`, `Get`, `Create`, `Update`, `Delete`

**Network API (v2)**
- Firewall Policies: `List`, `Get`, `Create`, `Update`, `Delete`
- Firewall Zones: `List`, `Get`, `Create`, `Update`, `Delete`
- Static DNS: `List`, `Get`, `Create`, `Update`, `Delete`
- Traffic Rules: `List`, `Get`, `Create`, `Update`, `Delete`
- Traffic Routes: `List`, `Get`, `Create`, `Update`, `Delete`
- NAT Rules: `List`, `Get`, `Create`, `Update`, `Delete`
- Active Clients: `ListActiveClients` (read-only)
- Network Devices: `ListNetworkDevices` (read-only)
- ACL Rules: `ListAclRules` (read-only)
- QoS Rules: `ListQosRules` (read-only)
- Content Filtering: `GetContentFiltering` (read-only)
- VPN Connections: `ListVpnConnections` (read-only)
- WAN SLAs: `ListWanSlas` (read-only)

## Related Projects

Reference for patterns and lessons learned (not for copying code):

- **lexfrei/go-unifi**: Uses oapi-codegen with self-authored OpenAPI specs. Interesting patterns: reality testing, middleware via RoundTripper.
- **Existing Terraform providers**: paultyng/terraform-provider-unifi (abandoned), ubiquiti-community fork (maintenance-only), filipowm/unifi (has data loss bugs). Validates the need for our own SDK.
