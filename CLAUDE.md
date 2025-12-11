# UniFi Go SDK

Go SDK for UniFi APIs (Site Manager and Network).

## Structure

- `pkg/unifi/` - SDK package
  - `sitemanager_client.go` - Cloud API client
  - `sitemanager_models.go` - Cloud API models
  - `network_client.go` - Controller API client
  - `network_models.go` - Controller API models
  - `errors.go` - Sentinel errors
- `cmd/example/` - Test harness (requires `UNIFI_API_KEY` env var)
- `cmd/validate/` - API drift detection tool (requires `UNIFI_API_KEY` env var)

## API Documentation

- Site Manager API: https://developer.ui.com/site-manager-api/gettingstarted
- Network API: Legacy REST at `/proxy/network/api/s/{site}/rest/*`

## UniFi API Landscape

Two distinct APIs, both implemented:

1. **Site Manager API** (cloud)
   - Base: `https://api.ui.com/v1/`
   - Auth: API key via `X-API-KEY` header
   - Read-only: hosts, sites, devices
   - Rate limits: 10K req/min (v1), 100 req/min (EA endpoints)

2. **Network API** (local controller)
   - Base: `https://<controller>/proxy/network/api/s/{site}/rest/`
   - Auth: Session-based (username/password → cookie)
   - Full CRUD: networks, firewall rules/groups, port forwards, WLANs, port profiles, routes, user groups, RADIUS, DDNS

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
- `NetworkClient` - Controller API with session-based auth, full CRUD operations
- Sentinel errors for common HTTP status codes
- 30s default HTTP timeout

## Architecture Decisions

- **Reactive rate limiting over proactive**: Terraform's sequential execution model rarely hits limits. Reactive retry with exponential backoff + jitter adapts automatically.
- **Hand-written types**: No official OpenAPI specs cover our use cases. Models derived from API docs and observed responses.
- **Interface-first**: `SiteManager` and `NetworkManager` interfaces enable mocking without test dependencies on real API.
- **Session-based auth for Network API**: The official Integration API is read-only. Legacy REST API with cookie auth supports writes.

## Preferences

- **Commits**: Do not include Claude Code citations or co-author tags
- **Code style**: Minimal comments, no inline comments unless truly necessary
- **Go idioms**: Prefer exported fields over setter methods for simplicity. Skip helper functions (like `IsNotFound()`) - use standard `errors.Is()` patterns instead
- **Testing**: Use `httptest` for mocking. Export struct fields to allow test configuration
- **CI**: Keep simple - build and test only. Avoid paid services (Codecov, etc.) unless explicitly requested
- **Over-engineering**: Avoid. Don't add abstractions, helpers, or features beyond what's requested
- **Error handling**: Limit error body reads to prevent memory exhaustion (64KB max)
- **File naming**: Use `{api}_client.go`, `{api}_models.go` pattern (e.g., `sitemanager_client.go`, `network_client.go`)

## Status

Both APIs complete:

**Site Manager API**
- `ListHosts`, `ListAllHosts`, `GetHost`
- `ListSites`, `ListAllSites`
- `ListDevices`, `ListAllDevices`

**Network API**
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

## Related Projects

Reference for patterns and lessons learned (not for copying code):

- **lexfrei/go-unifi**: Uses oapi-codegen with self-authored OpenAPI specs. Interesting patterns: reality testing, middleware via RoundTripper.
- **Existing Terraform providers**: paultyng/terraform-provider-unifi (abandoned), ubiquiti-community fork (maintenance-only), filipowm/unifi (has data loss bugs). Validates the need for our own SDK.
