package unifi

import (
	"encoding/json"
	"testing"
)

func TestFirewallPolicyBuilder(t *testing.T) {
	t.Run("basic policy", func(t *testing.T) {
		policy := NewFirewallPolicyBuilder().
			Name("Block IoT to LAN").
			Action("DROP").
			Protocol("all").
			Build()

		if policy.Name != "Block IoT to LAN" {
			t.Errorf("expected name 'Block IoT to LAN', got %q", policy.Name)
		}
		if policy.Action != "DROP" {
			t.Errorf("expected action 'DROP', got %q", policy.Action)
		}
		if policy.Protocol != "all" {
			t.Errorf("expected protocol 'all', got %q", policy.Protocol)
		}
		if policy.Enabled == nil || !*policy.Enabled {
			t.Error("expected enabled to be true by default")
		}
		if policy.IPVersion != "IPv4" {
			t.Errorf("expected IP version 'IPv4' by default, got %q", policy.IPVersion)
		}
	})

	t.Run("policy with endpoints using structs", func(t *testing.T) {
		source := &PolicyEndpoint{ZoneID: "iot-zone-id"}
		dest := &PolicyEndpoint{ZoneID: "lan-zone-id"}

		policy := NewFirewallPolicyBuilder().
			Name("Zone Policy").
			Action("ACCEPT").
			Source(source).
			Destination(dest).
			Build()

		if policy.Source == nil || policy.Source.ZoneID != "iot-zone-id" {
			t.Error("expected source zone ID to be set")
		}
		if policy.Destination == nil || policy.Destination.ZoneID != "lan-zone-id" {
			t.Error("expected destination zone ID to be set")
		}
	})

	t.Run("policy with endpoints using builders", func(t *testing.T) {
		policy := NewFirewallPolicyBuilder().
			Name("Complex Policy").
			Action("DROP").
			SourceFrom(
				NewPolicyEndpointBuilder().
					ZoneID("external").
					MatchingTarget("IP").
					IPs("192.168.1.0/24", "10.0.0.0/8"),
			).
			DestinationFrom(
				NewPolicyEndpointBuilder().
					ZoneID("internal").
					Port("443").
					PortMatchingType("SPECIFIC"),
			).
			Build()

		if policy.Source == nil {
			t.Fatal("expected source to be set")
		}
		if policy.Source.ZoneID != "external" {
			t.Errorf("expected source zone 'external', got %q", policy.Source.ZoneID)
		}
		if len(policy.Source.IPs) != 2 {
			t.Errorf("expected 2 source IPs, got %d", len(policy.Source.IPs))
		}
		if policy.Destination == nil {
			t.Fatal("expected destination to be set")
		}
		if policy.Destination.Port != "443" {
			t.Errorf("expected destination port '443', got %q", policy.Destination.Port)
		}
	})

	t.Run("policy with schedule", func(t *testing.T) {
		policy := NewFirewallPolicyBuilder().
			Name("Scheduled Policy").
			Action("DROP").
			ScheduleFrom(
				NewPolicyScheduleBuilder().
					Custom("08:00", "17:00", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"),
			).
			Build()

		if policy.Schedule == nil {
			t.Fatal("expected schedule to be set")
		}
		if policy.Schedule.Mode != "CUSTOM" {
			t.Errorf("expected mode 'CUSTOM', got %q", policy.Schedule.Mode)
		}
		if policy.Schedule.TimeRangeStart != "08:00" {
			t.Errorf("expected start time '08:00', got %q", policy.Schedule.TimeRangeStart)
		}
		if len(policy.Schedule.DaysOfWeek) != 5 {
			t.Errorf("expected 5 days, got %d", len(policy.Schedule.DaysOfWeek))
		}
	})

	t.Run("all options", func(t *testing.T) {
		policy := NewFirewallPolicyBuilder().
			Name("Full Policy").
			Action("REJECT").
			Enabled(false).
			Protocol("tcp").
			IPVersion("BOTH").
			Index(10).
			Logging(true).
			ConnectionStateType("CUSTOM").
			ConnectionStates("NEW", "ESTABLISHED").
			CreateAllowRespond(true).
			MatchIPSec(false).
			MatchOppositeProtocol(true).
			ICMPTypename("echo-request").
			ICMPV6Typename("echo-request").
			Build()

		if *policy.Enabled {
			t.Error("expected enabled to be false")
		}
		if *policy.Index != 10 {
			t.Errorf("expected index 10, got %d", *policy.Index)
		}
		if !*policy.Logging {
			t.Error("expected logging to be true")
		}
		if len(policy.ConnectionStates) != 2 {
			t.Errorf("expected 2 connection states, got %d", len(policy.ConnectionStates))
		}
	})

	t.Run("JSON serialization", func(t *testing.T) {
		policy := NewFirewallPolicyBuilder().
			Name("JSON Test").
			Action("DROP").
			SourceFrom(NewPolicyEndpointBuilder().ZoneID("external")).
			Build()

		data, err := json.Marshal(policy)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var decoded FirewallPolicy
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if decoded.Name != policy.Name {
			t.Errorf("expected name %q, got %q", policy.Name, decoded.Name)
		}
		if decoded.Source == nil || decoded.Source.ZoneID != "external" {
			t.Error("expected source zone to survive round-trip")
		}
	})
}

func TestPolicyEndpointBuilder(t *testing.T) {
	t.Run("zone-based", func(t *testing.T) {
		endpoint := NewPolicyEndpointBuilder().
			ZoneID("internal-zone").
			Build()

		if endpoint.ZoneID != "internal-zone" {
			t.Errorf("expected zone ID 'internal-zone', got %q", endpoint.ZoneID)
		}
	})

	t.Run("IP-based", func(t *testing.T) {
		endpoint := NewPolicyEndpointBuilder().
			MatchingTarget("IP").
			MatchingTargetType("SPECIFIC").
			IPs("192.168.1.100", "192.168.1.101").
			Build()

		if endpoint.MatchingTarget != "IP" {
			t.Errorf("expected matching target 'IP', got %q", endpoint.MatchingTarget)
		}
		if len(endpoint.IPs) != 2 {
			t.Errorf("expected 2 IPs, got %d", len(endpoint.IPs))
		}
	})

	t.Run("port-based", func(t *testing.T) {
		endpoint := NewPolicyEndpointBuilder().
			Port("80-443").
			PortMatchingType("SPECIFIC").
			Build()

		if endpoint.Port != "80-443" {
			t.Errorf("expected port '80-443', got %q", endpoint.Port)
		}
		if endpoint.PortMatchingType != "SPECIFIC" {
			t.Errorf("expected port matching type 'SPECIFIC', got %q", endpoint.PortMatchingType)
		}
	})

	t.Run("MAC-based", func(t *testing.T) {
		endpoint := NewPolicyEndpointBuilder().
			MAC("00:11:22:33:44:55").
			MatchMAC(true).
			ClientMACs("aa:bb:cc:dd:ee:ff").
			Build()

		if endpoint.MAC != "00:11:22:33:44:55" {
			t.Errorf("expected MAC '00:11:22:33:44:55', got %q", endpoint.MAC)
		}
		if endpoint.MatchMAC == nil || !*endpoint.MatchMAC {
			t.Error("expected MatchMAC to be true")
		}
		if len(endpoint.ClientMACs) != 1 {
			t.Errorf("expected 1 client MAC, got %d", len(endpoint.ClientMACs))
		}
	})

	t.Run("network-based", func(t *testing.T) {
		endpoint := NewPolicyEndpointBuilder().
			NetworkID("network-123").
			MatchingTarget("NETWORK").
			Build()

		if endpoint.NetworkID != "network-123" {
			t.Errorf("expected network ID 'network-123', got %q", endpoint.NetworkID)
		}
	})
}

func TestPolicyScheduleBuilder(t *testing.T) {
	t.Run("always mode", func(t *testing.T) {
		schedule := NewPolicyScheduleBuilder().
			Always().
			Build()

		if schedule.Mode != "ALWAYS" {
			t.Errorf("expected mode 'ALWAYS', got %q", schedule.Mode)
		}
	})

	t.Run("custom mode with helper", func(t *testing.T) {
		schedule := NewPolicyScheduleBuilder().
			Custom("09:00", "18:00", "MONDAY", "FRIDAY").
			Build()

		if schedule.Mode != "CUSTOM" {
			t.Errorf("expected mode 'CUSTOM', got %q", schedule.Mode)
		}
		if schedule.TimeRangeStart != "09:00" {
			t.Errorf("expected start '09:00', got %q", schedule.TimeRangeStart)
		}
		if schedule.TimeRangeEnd != "18:00" {
			t.Errorf("expected end '18:00', got %q", schedule.TimeRangeEnd)
		}
		if len(schedule.DaysOfWeek) != 2 {
			t.Errorf("expected 2 days, got %d", len(schedule.DaysOfWeek))
		}
	})

	t.Run("custom mode with individual methods", func(t *testing.T) {
		schedule := NewPolicyScheduleBuilder().
			Mode("CUSTOM").
			TimeRange("00:00", "06:00").
			DaysOfWeek("SATURDAY", "SUNDAY").
			Build()

		if schedule.Mode != "CUSTOM" {
			t.Errorf("expected mode 'CUSTOM', got %q", schedule.Mode)
		}
		if schedule.TimeRangeStart != "00:00" {
			t.Errorf("expected start '00:00', got %q", schedule.TimeRangeStart)
		}
	})
}

func TestBuilderChaining(t *testing.T) {
	policy := NewFirewallPolicyBuilder().
		Name("Chaining Test").
		Action("DROP").
		Protocol("tcp").
		IPVersion("IPv4").
		Index(5).
		Logging(true).
		Enabled(true).
		SourceFrom(
			NewPolicyEndpointBuilder().
				ZoneID("external").
				MatchingTarget("IP").
				IPs("10.0.0.0/8"),
		).
		DestinationFrom(
			NewPolicyEndpointBuilder().
				ZoneID("internal").
				Port("22").
				PortMatchingType("SPECIFIC"),
		).
		ScheduleFrom(
			NewPolicyScheduleBuilder().
				Custom("22:00", "06:00", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"),
		).
		Build()

	if policy.Name != "Chaining Test" {
		t.Errorf("unexpected name: %q", policy.Name)
	}
	if policy.Source == nil || policy.Source.ZoneID != "external" {
		t.Error("source not set correctly")
	}
	if policy.Destination == nil || policy.Destination.Port != "22" {
		t.Error("destination not set correctly")
	}
	if policy.Schedule == nil || policy.Schedule.Mode != "CUSTOM" {
		t.Error("schedule not set correctly")
	}
}
