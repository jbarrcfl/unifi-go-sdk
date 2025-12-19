package unifi

// FirewallPolicyBuilder provides a fluent API for constructing FirewallPolicy structs.
type FirewallPolicyBuilder struct {
	policy FirewallPolicy
}

// NewFirewallPolicyBuilder creates a new builder with sensible defaults.
func NewFirewallPolicyBuilder() *FirewallPolicyBuilder {
	return &FirewallPolicyBuilder{
		policy: FirewallPolicy{
			Enabled:   BoolPtr(true),
			IPVersion: "IPv4",
		},
	}
}

// Name sets the policy name (required).
func (b *FirewallPolicyBuilder) Name(name string) *FirewallPolicyBuilder {
	b.policy.Name = name
	return b
}

// Action sets the policy action (ACCEPT, DROP, REJECT).
func (b *FirewallPolicyBuilder) Action(action string) *FirewallPolicyBuilder {
	b.policy.Action = action
	return b
}

// Enabled sets whether the policy is enabled.
func (b *FirewallPolicyBuilder) Enabled(enabled bool) *FirewallPolicyBuilder {
	b.policy.Enabled = BoolPtr(enabled)
	return b
}

// Protocol sets the protocol (all, tcp, udp, tcp_udp, icmp).
func (b *FirewallPolicyBuilder) Protocol(protocol string) *FirewallPolicyBuilder {
	b.policy.Protocol = protocol
	return b
}

// IPVersion sets the IP version (IPv4, IPv6, BOTH).
func (b *FirewallPolicyBuilder) IPVersion(version string) *FirewallPolicyBuilder {
	b.policy.IPVersion = version
	return b
}

// Index sets the policy ordering index.
func (b *FirewallPolicyBuilder) Index(index int) *FirewallPolicyBuilder {
	b.policy.Index = IntPtr(index)
	return b
}

// Logging enables or disables logging for matched traffic.
func (b *FirewallPolicyBuilder) Logging(enabled bool) *FirewallPolicyBuilder {
	b.policy.Logging = BoolPtr(enabled)
	return b
}

// ConnectionStateType sets the connection state matching type.
func (b *FirewallPolicyBuilder) ConnectionStateType(stateType string) *FirewallPolicyBuilder {
	b.policy.ConnectionStateType = stateType
	return b
}

// ConnectionStates sets the connection states to match.
func (b *FirewallPolicyBuilder) ConnectionStates(states ...string) *FirewallPolicyBuilder {
	b.policy.ConnectionStates = states
	return b
}

// CreateAllowRespond enables automatic response rule creation.
func (b *FirewallPolicyBuilder) CreateAllowRespond(enabled bool) *FirewallPolicyBuilder {
	b.policy.CreateAllowRespond = BoolPtr(enabled)
	return b
}

// MatchIPSec sets whether to match IPSec traffic.
func (b *FirewallPolicyBuilder) MatchIPSec(enabled bool) *FirewallPolicyBuilder {
	b.policy.MatchIPSec = BoolPtr(enabled)
	return b
}

// MatchOppositeProtocol sets whether to match the opposite protocol.
func (b *FirewallPolicyBuilder) MatchOppositeProtocol(enabled bool) *FirewallPolicyBuilder {
	b.policy.MatchOppositeProtocol = BoolPtr(enabled)
	return b
}

// ICMPTypename sets the ICMP type name for IPv4.
func (b *FirewallPolicyBuilder) ICMPTypename(typename string) *FirewallPolicyBuilder {
	b.policy.ICMPTypename = typename
	return b
}

// ICMPV6Typename sets the ICMP type name for IPv6.
func (b *FirewallPolicyBuilder) ICMPV6Typename(typename string) *FirewallPolicyBuilder {
	b.policy.ICMPV6Typename = typename
	return b
}

// Schedule sets the policy schedule using a PolicySchedule struct.
func (b *FirewallPolicyBuilder) Schedule(schedule *PolicySchedule) *FirewallPolicyBuilder {
	b.policy.Schedule = schedule
	return b
}

// ScheduleFrom sets the policy schedule using a builder.
func (b *FirewallPolicyBuilder) ScheduleFrom(sb *PolicyScheduleBuilder) *FirewallPolicyBuilder {
	schedule := sb.Build()
	b.policy.Schedule = &schedule
	return b
}

// Source sets the source endpoint using a PolicyEndpoint struct.
func (b *FirewallPolicyBuilder) Source(source *PolicyEndpoint) *FirewallPolicyBuilder {
	b.policy.Source = source
	return b
}

// SourceFrom sets the source endpoint using a builder.
func (b *FirewallPolicyBuilder) SourceFrom(eb *PolicyEndpointBuilder) *FirewallPolicyBuilder {
	endpoint := eb.Build()
	b.policy.Source = &endpoint
	return b
}

// Destination sets the destination endpoint using a PolicyEndpoint struct.
func (b *FirewallPolicyBuilder) Destination(dest *PolicyEndpoint) *FirewallPolicyBuilder {
	b.policy.Destination = dest
	return b
}

// DestinationFrom sets the destination endpoint using a builder.
func (b *FirewallPolicyBuilder) DestinationFrom(eb *PolicyEndpointBuilder) *FirewallPolicyBuilder {
	endpoint := eb.Build()
	b.policy.Destination = &endpoint
	return b
}

// Build returns the constructed FirewallPolicy.
func (b *FirewallPolicyBuilder) Build() FirewallPolicy {
	return b.policy
}

// PolicyEndpointBuilder provides a fluent API for constructing PolicyEndpoint structs.
type PolicyEndpointBuilder struct {
	endpoint PolicyEndpoint
}

// NewPolicyEndpointBuilder creates a new builder for policy endpoints.
func NewPolicyEndpointBuilder() *PolicyEndpointBuilder {
	return &PolicyEndpointBuilder{}
}

// ZoneID sets the zone ID for zone-based matching.
func (b *PolicyEndpointBuilder) ZoneID(id string) *PolicyEndpointBuilder {
	b.endpoint.ZoneID = id
	return b
}

// MatchingTarget sets the matching target type (ANY, IP, NETWORK, DOMAIN, REGION, PORT_GROUP, ADDRESS_GROUP).
func (b *PolicyEndpointBuilder) MatchingTarget(target string) *PolicyEndpointBuilder {
	b.endpoint.MatchingTarget = target
	return b
}

// MatchingTargetType sets the matching target type (SPECIFIC, OBJECT).
func (b *PolicyEndpointBuilder) MatchingTargetType(targetType string) *PolicyEndpointBuilder {
	b.endpoint.MatchingTargetType = targetType
	return b
}

// IPs sets the IP addresses to match.
func (b *PolicyEndpointBuilder) IPs(ips ...string) *PolicyEndpointBuilder {
	b.endpoint.IPs = ips
	return b
}

// MAC sets the MAC address to match.
func (b *PolicyEndpointBuilder) MAC(mac string) *PolicyEndpointBuilder {
	b.endpoint.MAC = mac
	return b
}

// MatchMAC enables or disables MAC address matching.
func (b *PolicyEndpointBuilder) MatchMAC(enabled bool) *PolicyEndpointBuilder {
	b.endpoint.MatchMAC = BoolPtr(enabled)
	return b
}

// MatchOppositeIPs sets whether to match opposite IPs.
func (b *PolicyEndpointBuilder) MatchOppositeIPs(enabled bool) *PolicyEndpointBuilder {
	b.endpoint.MatchOppositeIPs = BoolPtr(enabled)
	return b
}

// Port sets the port or port range to match.
func (b *PolicyEndpointBuilder) Port(port string) *PolicyEndpointBuilder {
	b.endpoint.Port = port
	return b
}

// PortMatchingType sets the port matching type (ANY, SPECIFIC).
func (b *PolicyEndpointBuilder) PortMatchingType(matchType string) *PolicyEndpointBuilder {
	b.endpoint.PortMatchingType = matchType
	return b
}

// MatchOppositePorts sets whether to match opposite ports.
func (b *PolicyEndpointBuilder) MatchOppositePorts(enabled bool) *PolicyEndpointBuilder {
	b.endpoint.MatchOppositePorts = BoolPtr(enabled)
	return b
}

// NetworkID sets the network ID for network-based matching.
func (b *PolicyEndpointBuilder) NetworkID(id string) *PolicyEndpointBuilder {
	b.endpoint.NetworkID = id
	return b
}

// ClientMACs sets the client MAC addresses to match.
func (b *PolicyEndpointBuilder) ClientMACs(macs ...string) *PolicyEndpointBuilder {
	b.endpoint.ClientMACs = macs
	return b
}

// Build returns the constructed PolicyEndpoint.
func (b *PolicyEndpointBuilder) Build() PolicyEndpoint {
	return b.endpoint
}

// PolicyScheduleBuilder provides a fluent API for constructing PolicySchedule structs.
type PolicyScheduleBuilder struct {
	schedule PolicySchedule
}

// NewPolicyScheduleBuilder creates a new builder for policy schedules.
func NewPolicyScheduleBuilder() *PolicyScheduleBuilder {
	return &PolicyScheduleBuilder{}
}

// Mode sets the schedule mode (ALWAYS, CUSTOM).
func (b *PolicyScheduleBuilder) Mode(mode string) *PolicyScheduleBuilder {
	b.schedule.Mode = mode
	return b
}

// Always sets the schedule to always active.
func (b *PolicyScheduleBuilder) Always() *PolicyScheduleBuilder {
	b.schedule.Mode = "ALWAYS"
	return b
}

// Custom sets the schedule to custom mode with specified time range and days.
func (b *PolicyScheduleBuilder) Custom(startTime, endTime string, days ...string) *PolicyScheduleBuilder {
	b.schedule.Mode = "CUSTOM"
	b.schedule.TimeRangeStart = startTime
	b.schedule.TimeRangeEnd = endTime
	b.schedule.DaysOfWeek = days
	return b
}

// TimeRange sets the time range for the schedule.
func (b *PolicyScheduleBuilder) TimeRange(start, end string) *PolicyScheduleBuilder {
	b.schedule.TimeRangeStart = start
	b.schedule.TimeRangeEnd = end
	return b
}

// DaysOfWeek sets the days when the schedule is active.
func (b *PolicyScheduleBuilder) DaysOfWeek(days ...string) *PolicyScheduleBuilder {
	b.schedule.DaysOfWeek = days
	return b
}

// Build returns the constructed PolicySchedule.
func (b *PolicyScheduleBuilder) Build() PolicySchedule {
	return b.schedule
}
