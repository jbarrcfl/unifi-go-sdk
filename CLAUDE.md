# UniFi Go SDK

Go SDK for the UniFi Site Manager API.

## Structure

- `pkg/unifi/` - SDK package (client, models, errors)
- `cmd/example/` - Test harness (requires `UNIFI_API_KEY` env var)
- `cmd/validate/` - API drift detection tool (requires `UNIFI_API_KEY` env var)

## API Documentation

- Site Manager API: https://developer.ui.com/site-manager-api/gettingstarted
- Network API: OpenAPI spec available at `https://<controller>/proxy/network/api-docs/integration.json`

## UniFi API Landscape

Two distinct APIs:

1. **Site Manager API** (current focus)
   - Base: `https://api.ui.com/v1/`
   - Auth: API key via `X-API-KEY` header
   - No official OpenAPI spec—we work from Ubiquiti's docs
   - Rate limits: 10K req/min (v1), 100 req/min (EA endpoints)
   - Currently read-only, write endpoints coming later

2. **Network API** (future)
   - Base: `https://<controller>/proxy/network/api/`
   - Auth: Cookie-based session from `/api/auth/login`
   - OpenAPI spec exists on controller
   - This is what existing Terraform providers use for firewall rules, networks, etc.

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

- `SiteManagerClient` interface for mockability in downstream tests
- Automatic pagination with `ListAll*` methods
- Reactive rate limiting: retry on 429 with `Retry-After` header support
- 30s default HTTP timeout
- Sentinel errors for common HTTP status codes

## Architecture Decisions

- **Reactive rate limiting over proactive**: Terraform's sequential execution model rarely hits 10K/min limits. Reactive retry is simpler and adapts to server-side changes automatically.
- **Hand-written types over code generation**: Site Manager has no OpenAPI spec. For Network API (future), we'll evaluate generating from the controller's spec.
- **Interface-first**: `SiteManagerClient` interface enables mocking without test dependencies on real API.

## Preferences

- **Commits**: Do not include Claude Code citations or co-author tags
- **Code style**: Minimal comments, no inline comments unless truly necessary
- **Go idioms**: Prefer exported fields over setter methods for simplicity. Skip helper functions (like `IsNotFound()`) - use standard `errors.Is()` patterns instead
- **Testing**: Use `httptest` for mocking. Export struct fields to allow test configuration
- **CI**: Keep simple - build and test only. Avoid paid services (Codecov, etc.) unless explicitly requested
- **Over-engineering**: Avoid. Don't add abstractions, helpers, or features beyond what's requested
- **Error handling**: Limit error body reads to prevent memory exhaustion (64KB max)

## Related Projects

- **lexfrei/go-unifi**: Similar SDK using oapi-codegen with self-authored OpenAPI specs. We're not copying their code but can learn from their patterns (reality testing, middleware via RoundTripper).
- **Existing Terraform providers**: paultyng/terraform-provider-unifi (abandoned), ubiquiti-community fork (maintenance-only), filipowm/unifi (has data loss bugs). This validates building our own SDK.
