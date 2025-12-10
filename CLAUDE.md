# UniFi Go SDK

Go SDK for the UniFi Site Manager API.

## Structure

- `pkg/unifi/` - SDK package (client, models, errors)
- `cmd/example/` - Test harness (requires `UNIFI_API_KEY` env var)

## API Documentation

- Site Manager: https://developer.ui.com/site-manager-api/gettingstarted

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

- Automatic pagination with `ListAll*` methods
- Automatic retry on 429 (rate limit) with `Retry-After` header support
- 30s default HTTP timeout
- Sentinel errors for common HTTP status codes

## Preferences

- **Commits**: Do not include Claude Code citations or co-author tags
- **Code style**: Minimal comments, no inline comments unless truly necessary
- **Go idioms**: Prefer exported fields over setter methods for simplicity. Skip helper functions (like `IsNotFound()`) - use standard `errors.Is()` patterns instead
- **Testing**: Use `httptest` for mocking. Export struct fields to allow test configuration
- **CI**: Keep simple - build and test only. Avoid paid services (Codecov, etc.) unless explicitly requested
- **Over-engineering**: Avoid. Don't add abstractions, helpers, or features beyond what's requested
- **Error handling**: Limit error body reads to prevent memory exhaustion (64KB max)
