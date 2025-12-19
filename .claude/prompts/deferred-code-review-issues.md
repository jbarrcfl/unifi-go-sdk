# Deferred Code Review Issues

These issues were identified during a code review but deferred due to being breaking changes or requiring significant refactoring effort.

## 1. Rename `IsLoggedIn()` to `HasLocalSession()`

**File:** `pkg/unifi/network_client.go`
**Type:** Breaking change

The method `IsLoggedIn()` is misleading because:
- With API key auth, it always returns `true` even though no login occurred
- It only reflects local state, not server-side session validity

**Proposed change:** Rename to `HasLocalSession()` with updated documentation explaining it returns `true` when either:
- API key authentication is configured, or
- A session cookie exists from a previous `Login()` call

**Migration:** This is a breaking change requiring a major version bump or deprecation period.

---

## ~~2. Add Builder Pattern for Complex Structs~~ (RESOLVED)

**Status:** Resolved - December 2025

Builder pattern implemented in `pkg/unifi/builders.go` for:
- `FirewallPolicyBuilder` - Fluent API for FirewallPolicy with defaults (Enabled=true, IPVersion=IPv4)
- `PolicyEndpointBuilder` - Fluent API for source/destination endpoints
- `PolicyScheduleBuilder` - Fluent API for schedules with `Always()` and `Custom()` helpers

Example usage:
```go
policy := unifi.NewFirewallPolicyBuilder().
    Name("Block IoT to LAN").
    Action("DROP").
    SourceFrom(unifi.NewPolicyEndpointBuilder().ZoneID("iot-zone-id")).
    DestinationFrom(unifi.NewPolicyEndpointBuilder().ZoneID("lan-zone-id")).
    Build()
```

**Future consideration:** Add builders for `Network`, `WLANConf`, `TrafficRule` if needed

---

## ~~3. Refactor Network Struct into Nested Types~~ (RESOLVED)

**Status:** Resolved - December 2025

The Network struct has been refactored into nested types using Go struct embedding:
- `NetworkVLAN` - VLAN configuration (3 fields)
- `NetworkDHCP` - DHCP configuration with sub-types for Gateway, DNS, Boot, NTP (24 fields)
- `NetworkWAN` - WAN configuration with sub-types for IPv6, QoS, LoadBalance, VLAN (26 fields)
- `NetworkIPv6` - IPv6 settings (2 fields)
- `NetworkMulticast` - IGMP/multicast settings (4 fields)
- `NetworkAccess` - Access and NAT settings (9 fields)
- `NetworkRouting` - Routing and firewall zone config (4 fields)

JSON serialization remains flat (API-compatible) due to Go struct embedding.
Each nested type has its own `Validate()` method.

---

## 4. Rename Read-Only Methods for Consistency

**File:** `pkg/unifi/network_client.go`
**Type:** Breaking change

Current naming is inconsistent:
- `ListActiveClients` - resource name is "Clients"
- `ListNetworkDevices` - resource name is "Devices"

**Options:**
1. Rename to `ListClients`, `ListDevices` (matches other methods)
2. Rename to `ListActiveClients`, `ListDevices` (remove "Network" prefix)

**Impact:** Breaking change, minor.

---

## ~~5. Fix Comment Style Inconsistencies~~ (RESOLVED)

**Status:** Resolved - December 2025

Audit confirmed all Go files follow consistent comment conventions:
- All godoc comments start with item name and end with periods
- All comments use `// ` with space after
- Capitalization is consistent throughout

---

## Implementation Notes

When addressing these issues:

1. **Breaking changes (1, 4):** Consider a v2 release or deprecation warnings
2. ~~**New features (2):** Can be added without breaking existing code~~ (RESOLVED)
3. ~~**Style fixes (5):** Low priority, do opportunistically~~ (RESOLVED)
4. ~~**Network struct refactoring (3):**~~ (RESOLVED)

Run the full test suite after each change:
```bash
go build ./...
go test -v -race ./pkg/...
```
