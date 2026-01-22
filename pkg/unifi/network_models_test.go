package unifi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUserGroupValidate(t *testing.T) {
	tests := []struct {
		name    string
		group   UserGroup
		wantErr string
	}{
		{"valid", UserGroup{Name: "Test"}, ""},
		{"missing name", UserGroup{}, "name is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.group.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestFirewallZoneCreateRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		req     FirewallZoneCreateRequest
		wantErr string
	}{
		{"valid", FirewallZoneCreateRequest{Name: "Test", NetworkIDs: []string{}}, ""},
		{"valid with networks", FirewallZoneCreateRequest{Name: "Test", NetworkIDs: []string{"net1"}}, ""},
		{"missing name", FirewallZoneCreateRequest{NetworkIDs: []string{}}, "name is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestFirewallZoneUpdateRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		req     FirewallZoneUpdateRequest
		wantErr string
	}{
		{"valid", FirewallZoneUpdateRequest{ID: "123", Name: "Test", NetworkIDs: []string{}}, ""},
		{"missing id", FirewallZoneUpdateRequest{Name: "Test", NetworkIDs: []string{}}, "id is required"},
		{"missing name", FirewallZoneUpdateRequest{ID: "123", NetworkIDs: []string{}}, "name is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestFirewallGroupValidate(t *testing.T) {
	tests := []struct {
		name    string
		group   FirewallGroup
		wantErr string
	}{
		{"valid address-group", FirewallGroup{Name: "Test", GroupType: "address-group", GroupMembers: []string{"192.168.1.1"}}, ""},
		{"valid port-group", FirewallGroup{Name: "Test", GroupType: "port-group", GroupMembers: []string{"80"}}, ""},
		{"valid ipv6-address-group", FirewallGroup{Name: "Test", GroupType: "ipv6-address-group", GroupMembers: []string{"::1"}}, ""},
		{"valid name only", FirewallGroup{Name: "Test"}, ""},
		{"missing name", FirewallGroup{GroupType: "address-group", GroupMembers: []string{"192.168.1.1"}}, "name is required"},
		{"invalid group_type", FirewallGroup{Name: "Test", GroupType: "invalid", GroupMembers: []string{"192.168.1.1"}}, "group_type must be one of"},
		{"empty group_members with group_type", FirewallGroup{Name: "Test", GroupType: "address-group"}, "group_members cannot be empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.group.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestRoutingValidate(t *testing.T) {
	tests := []struct {
		name    string
		route   Routing
		wantErr string
	}{
		{"valid", Routing{Name: "Test", Type: "static-route", StaticRouteNetwork: "10.0.0.0/8", StaticRouteNexthop: "192.168.1.1"}, ""},
		{"missing name", Routing{}, "name is required"},
		{"invalid type", Routing{Name: "Test", Type: "invalid"}, "type must be one of"},
		{"invalid static-route_type", Routing{Name: "Test", StaticRouteType: "invalid"}, "static-route_type must be one of"},
		{"invalid static-route_network", Routing{Name: "Test", StaticRouteNetwork: "invalid"}, "must be a valid CIDR"},
		{"invalid static-route_nexthop", Routing{Name: "Test", StaticRouteNexthop: "invalid"}, "must be a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.route.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestDynamicDNSValidate(t *testing.T) {
	tests := []struct {
		name    string
		ddns    DynamicDNS
		wantErr string
	}{
		{"valid", DynamicDNS{Service: "cloudflare", HostName: "example.com"}, ""},
		{"missing service", DynamicDNS{HostName: "example.com"}, "service is required"},
		{"invalid service", DynamicDNS{Service: "invalid", HostName: "example.com"}, "service must be one of"},
		{"missing hostname", DynamicDNS{Service: "cloudflare"}, "host_name is required"},
		{"invalid interface", DynamicDNS{Service: "cloudflare", HostName: "example.com", Interface: "invalid"}, "interface must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ddns.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNatRuleValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    NatRule
		wantErr string
	}{
		{"valid MASQUERADE", NatRule{Type: "MASQUERADE"}, ""},
		{"valid DNAT", NatRule{Type: "DNAT", TranslatedIP: "192.168.1.1"}, ""},
		{"valid SNAT", NatRule{Type: "SNAT", TranslatedIP: "192.168.1.1"}, ""},
		{"missing type", NatRule{}, "type is required"},
		{"invalid type", NatRule{Type: "invalid"}, "type must be one of"},
		{"invalid protocol", NatRule{Type: "MASQUERADE", Protocol: "invalid"}, "protocol must be one of"},
		{"invalid source_address", NatRule{Type: "MASQUERADE", SourceAddress: "invalid"}, "source_address must be a valid IP or CIDR"},
		{"invalid source_port", NatRule{Type: "MASQUERADE", SourcePort: "invalid"}, "source_port must be a valid port"},
		{"invalid translated_ip", NatRule{Type: "DNAT", TranslatedIP: "invalid"}, "translated_ip must be a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestPortForwardValidate(t *testing.T) {
	tests := []struct {
		name    string
		pf      PortForward
		wantErr string
	}{
		{"valid", PortForward{Name: "Test", Proto: "tcp", DstPort: "80", Fwd: "192.168.1.1", FwdPort: "8080"}, ""},
		{"missing name", PortForward{}, "name is required"},
		{"invalid proto", PortForward{Name: "Test", Proto: "invalid"}, "proto must be one of"},
		{"invalid pfwd_interface", PortForward{Name: "Test", PfwdInterface: "invalid"}, "pfwd_interface must be one of"},
		{"invalid dst_port", PortForward{Name: "Test", DstPort: "invalid"}, "dst_port must be a valid port"},
		{"invalid fwd_port", PortForward{Name: "Test", FwdPort: "invalid"}, "fwd_port must be a valid port"},
		{"invalid fwd", PortForward{Name: "Test", Fwd: "invalid"}, "fwd must be a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pf.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestStaticDNSValidate(t *testing.T) {
	port := 80
	zeroPort := 0
	invalidPort := 70000
	tests := []struct {
		name    string
		dns     StaticDNS
		wantErr string
	}{
		{"valid", StaticDNS{Key: "example.com", Value: "192.168.1.1", RecordType: "A"}, ""},
		{"missing key", StaticDNS{Value: "192.168.1.1"}, "key is required"},
		{"missing value", StaticDNS{Key: "example.com"}, "value is required"},
		{"invalid record_type", StaticDNS{Key: "example.com", Value: "192.168.1.1", RecordType: "INVALID"}, "record_type must be one of"},
		{"valid port", StaticDNS{Key: "example.com", Value: "192.168.1.1", Port: &port}, ""},
		{"zero port valid", StaticDNS{Key: "example.com", Value: "192.168.1.1", Port: &zeroPort}, ""},
		{"invalid port", StaticDNS{Key: "example.com", Value: "192.168.1.1", Port: &invalidPort}, "port must be between 1 and 65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dns.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestRADIUSProfileValidate(t *testing.T) {
	validPort := 1812
	invalidPort := 0
	tests := []struct {
		name    string
		profile RADIUSProfile
		wantErr string
	}{
		{"valid", RADIUSProfile{Name: "Test"}, ""},
		{"missing name", RADIUSProfile{}, "name is required"},
		{"invalid vlan_wlan_mode", RADIUSProfile{Name: "Test", VlanWlanMode: "invalid"}, "vlan_wlan_mode must be one of"},
		{"valid auth_server", RADIUSProfile{Name: "Test", AuthServers: []RADIUSServer{{IP: "192.168.1.1", Port: &validPort}}}, ""},
		{"invalid auth_server ip", RADIUSProfile{Name: "Test", AuthServers: []RADIUSServer{{IP: "invalid"}}}, "auth_servers[0].ip must be a valid IP"},
		{"invalid auth_server port", RADIUSProfile{Name: "Test", AuthServers: []RADIUSServer{{IP: "192.168.1.1", Port: &invalidPort}}}, "auth_servers[0].port must be between 1 and 65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.profile.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestFirewallRuleValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    FirewallRule
		wantErr string
	}{
		{"valid", FirewallRule{Name: "Test", Action: "accept", Ruleset: "WAN_IN"}, ""},
		{"missing name", FirewallRule{}, "name is required"},
		{"invalid action", FirewallRule{Name: "Test", Action: "invalid"}, "action must be one of"},
		{"invalid ruleset", FirewallRule{Name: "Test", Ruleset: "invalid"}, "ruleset must be a valid ruleset"},
		{"invalid protocol", FirewallRule{Name: "Test", Protocol: "invalid_proto"}, "protocol must be a valid protocol"},
		{"invalid src_address", FirewallRule{Name: "Test", SrcAddress: "invalid"}, "src_address must be a valid IP or CIDR"},
		{"invalid dst_port", FirewallRule{Name: "Test", DstPort: "invalid"}, "dst_port must be a valid port"},
		{"invalid src_mac_address", FirewallRule{Name: "Test", SrcMACAddress: "invalid"}, "src_mac_address must be a valid MAC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestFirewallPolicyValidate(t *testing.T) {
	tests := []struct {
		name    string
		policy  FirewallPolicy
		wantErr string
	}{
		{"valid", FirewallPolicy{Name: "Test", Action: "ALLOW"}, ""},
		{"missing name", FirewallPolicy{}, "name is required"},
		{"invalid action", FirewallPolicy{Name: "Test", Action: "invalid"}, "action must be one of"},
		{"invalid protocol", FirewallPolicy{Name: "Test", Protocol: "invalid"}, "protocol must be one of"},
		{"invalid ip_version", FirewallPolicy{Name: "Test", IPVersion: "invalid"}, "ip_version must be one of"},
		{"invalid connection_state_type", FirewallPolicy{Name: "Test", ConnectionStateType: "invalid"}, "connection_state_type must be one of"},
		{"valid connection_state_type ALL", FirewallPolicy{Name: "Test", ConnectionStateType: "ALL"}, ""},
		{"valid connection_state_type CUSTOM", FirewallPolicy{Name: "Test", ConnectionStateType: "CUSTOM"}, ""},
		{
			"source validation error propagates",
			FirewallPolicy{
				Name:   "Test",
				Source: &PolicyEndpoint{MatchingTarget: "INVALID"},
			},
			"matching_target must be one of",
		},
		{
			"destination validation error propagates",
			FirewallPolicy{
				Name:        "Test",
				Destination: &PolicyEndpoint{Port: "invalid-port"},
			},
			"port must be a valid port",
		},
		{
			"schedule validation error propagates",
			FirewallPolicy{
				Name:     "Test",
				Schedule: &PolicySchedule{Mode: "INVALID"},
			},
			"mode must be one of",
		},
		{
			"all valid fields comprehensive",
			FirewallPolicy{
				Name:                "Full Policy",
				Action:              "BLOCK",
				Protocol:            "tcp",
				IPVersion:           "BOTH",
				ConnectionStateType: "CUSTOM",
				Source:              &PolicyEndpoint{ZoneID: "zone1", MatchingTarget: "ANY"},
				Destination:         &PolicyEndpoint{ZoneID: "zone2", Port: "443", PortMatchingType: "SPECIFIC"},
				Schedule:            &PolicySchedule{Mode: "ALWAYS"},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestTrafficRuleValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    TrafficRule
		wantErr string
	}{
		{"valid", TrafficRule{Name: "Test", Action: "BLOCK"}, ""},
		{"missing name", TrafficRule{Action: "BLOCK"}, "name is required"},
		{"invalid action", TrafficRule{Name: "Test", Action: "invalid"}, "action must be one of"},
		{"invalid matching_target", TrafficRule{Name: "Test", MatchingTarget: "invalid"}, "matching_target must be one of"},
		{"invalid ip_addresses", TrafficRule{Name: "Test", IPAddresses: []string{"invalid"}}, "ip_addresses[0] must be a valid IP or CIDR"},
		{"valid ip_addresses", TrafficRule{Name: "Test", IPAddresses: []string{"192.168.1.0/24"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestTrafficRouteValidate(t *testing.T) {
	tests := []struct {
		name    string
		route   TrafficRoute
		wantErr string
	}{
		{"valid", TrafficRoute{Name: "Test"}, ""},
		{"missing name", TrafficRoute{}, "name is required"},
		{"invalid matching_target", TrafficRoute{Name: "Test", MatchingTarget: "invalid"}, "matching_target must be one of"},
		{"invalid ip_addresses", TrafficRoute{Name: "Test", IPAddresses: []string{"invalid"}}, "ip_addresses[0] must be a valid IP or CIDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.route.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestPortConfValidate(t *testing.T) {
	tests := []struct {
		name    string
		conf    PortConf
		wantErr string
	}{
		{"valid", PortConf{Name: "Test", Forward: "all"}, ""},
		{"missing name", PortConf{}, "name is required"},
		{"invalid forward", PortConf{Name: "Test", Forward: "invalid"}, "forward must be one of"},
		{"invalid dot1x_ctrl", PortConf{Name: "Test", Dot1xCtrl: "invalid"}, "dot1x_ctrl must be one of"},
		{"invalid op_mode", PortConf{Name: "Test", OpMode: "invalid"}, "op_mode must be one of"},
		{"invalid poe_mode", PortConf{Name: "Test", PoeMode: "invalid"}, "poe_mode must be one of"},
		{"invalid mac", PortConf{Name: "Test", PortSecurityMacAddress: []string{"invalid"}}, "port_security_mac_address[0] must be a valid MAC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.conf.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestWLANConfValidate(t *testing.T) {
	tests := []struct {
		name    string
		wlan    WLANConf
		wantErr string
	}{
		{"valid", WLANConf{Name: "Test", Security: "wpapsk"}, ""},
		{"missing name", WLANConf{}, "name is required"},
		{"invalid security", WLANConf{Name: "Test", Security: "invalid"}, "security must be one of"},
		{"invalid wpa_mode", WLANConf{Name: "Test", WPAMode: "invalid"}, "wpa_mode must be one of"},
		{"invalid wpa_enc", WLANConf{Name: "Test", WPAEnc: "invalid"}, "wpa_enc must be one of"},
		{"invalid wlan_band", WLANConf{Name: "Test", WLANBand: "invalid"}, "wlan_band must be one of"},
		{"invalid mac_filter_policy", WLANConf{Name: "Test", MacFilterPolicy: "invalid"}, "mac_filter_policy must be one of"},
		{"invalid mac_filter_list", WLANConf{Name: "Test", MacFilterList: []string{"invalid"}}, "mac_filter_list[0] must be a valid MAC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.wlan.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkValidate(t *testing.T) {
	tests := []struct {
		name    string
		network Network
		wantErr string
	}{
		{"valid", Network{Name: "Test", Purpose: "corporate"}, ""},
		{"missing name", Network{}, "name is required"},
		{"invalid purpose", Network{Name: "Test", Purpose: "invalid"}, "purpose must be one of"},
		{"invalid networkgroup", Network{Name: "Test", NetworkRouting: NetworkRouting{NetworkGroup: "invalid"}}, "networkgroup must be one of"},
		{"invalid wan_type", Network{Name: "Test", NetworkWAN: NetworkWAN{WANType: "invalid"}}, "wan_type must be one of"},
		{"invalid ip_subnet", Network{Name: "Test", NetworkVLAN: NetworkVLAN{IPSubnet: "invalid"}}, "ip_subnet must be a valid CIDR"},
		{"invalid dhcpd_start", Network{Name: "Test", NetworkDHCP: NetworkDHCP{DHCPDStart: "invalid"}}, "dhcpd_start must be a valid IP"},
		{"invalid wan_gateway", Network{Name: "Test", NetworkWAN: NetworkWAN{WANGateway: "invalid"}}, "wan_gateway must be a valid IP"},
		{"valid cidr", Network{Name: "Test", NetworkVLAN: NetworkVLAN{IPSubnet: "192.168.1.0/24"}}, ""},
		{"valid dhcp", Network{Name: "Test", NetworkDHCP: NetworkDHCP{DHCPDStart: "192.168.1.100", DHCPDStop: "192.168.1.200"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.network.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkDHCPGatewayValidate(t *testing.T) {
	tests := []struct {
		name    string
		gateway NetworkDHCPGateway
		wantErr string
	}{
		{"valid empty", NetworkDHCPGateway{}, ""},
		{"valid gateway", NetworkDHCPGateway{DHCPDGateway: "192.168.1.1"}, ""},
		{"invalid gateway", NetworkDHCPGateway{DHCPDGateway: "not-an-ip"}, "dhcpd_gateway must be a valid IP address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.gateway.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkDHCPDNSValidate(t *testing.T) {
	tests := []struct {
		name    string
		dns     NetworkDHCPDNS
		wantErr string
	}{
		{"valid empty", NetworkDHCPDNS{}, ""},
		{"valid dns1", NetworkDHCPDNS{DHCPDDns1: "8.8.8.8"}, ""},
		{"valid all dns", NetworkDHCPDNS{DHCPDDns1: "8.8.8.8", DHCPDDns2: "8.8.4.4", DHCPDDns3: "1.1.1.1", DHCPDDns4: "1.0.0.1"}, ""},
		{"invalid dns1", NetworkDHCPDNS{DHCPDDns1: "invalid"}, "dhcpd_dns_1 must be a valid IP address"},
		{"invalid dns2", NetworkDHCPDNS{DHCPDDns2: "invalid"}, "dhcpd_dns_2 must be a valid IP address"},
		{"invalid dns3", NetworkDHCPDNS{DHCPDDns3: "invalid"}, "dhcpd_dns_3 must be a valid IP address"},
		{"invalid dns4", NetworkDHCPDNS{DHCPDDns4: "invalid"}, "dhcpd_dns_4 must be a valid IP address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dns.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkWANIPv6Validate(t *testing.T) {
	tests := []struct {
		name    string
		wan     NetworkWANIPv6
		wantErr string
	}{
		{"valid empty", NetworkWANIPv6{}, ""},
		{"valid disabled", NetworkWANIPv6{WANTypeV6: "disabled"}, ""},
		{"valid dhcpv6", NetworkWANIPv6{WANTypeV6: "dhcpv6"}, ""},
		{"valid static", NetworkWANIPv6{WANTypeV6: "static"}, ""},
		{"valid autoconf", NetworkWANIPv6{WANTypeV6: "autoconf"}, ""},
		{"invalid type", NetworkWANIPv6{WANTypeV6: "invalid"}, "wan_type_v6 must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.wan.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkWANLoadBalanceValidate(t *testing.T) {
	tests := []struct {
		name    string
		wan     NetworkWANLoadBalance
		wantErr string
	}{
		{"valid empty", NetworkWANLoadBalance{}, ""},
		{"valid failover-only", NetworkWANLoadBalance{WANLoadBalanceType: "failover-only"}, ""},
		{"valid weighted", NetworkWANLoadBalance{WANLoadBalanceType: "weighted"}, ""},
		{"invalid type", NetworkWANLoadBalance{WANLoadBalanceType: "invalid"}, "wan_load_balance_type must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.wan.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkWANQoSValidate(t *testing.T) {
	qos := NetworkWANQoS{WANEgressQOS: "normal"}
	if err := qos.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestNetworkWANVLANValidate(t *testing.T) {
	vlan := NetworkWANVLAN{WANVLANEnabled: BoolPtr(true), WANVLAN: IntPtr(100)}
	if err := vlan.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestPolicyEndpointValidate(t *testing.T) {
	tests := []struct {
		name     string
		endpoint PolicyEndpoint
		wantErr  string
	}{
		{"valid empty", PolicyEndpoint{}, ""},
		{"valid matching target ANY", PolicyEndpoint{MatchingTarget: "ANY"}, ""},
		{"valid matching target IP", PolicyEndpoint{MatchingTarget: "IP"}, ""},
		{"valid matching target NETWORK", PolicyEndpoint{MatchingTarget: "NETWORK"}, ""},
		{"invalid matching target", PolicyEndpoint{MatchingTarget: "INVALID"}, "matching_target must be one of"},
		{"valid matching target type SPECIFIC", PolicyEndpoint{MatchingTargetType: "SPECIFIC"}, ""},
		{"valid matching target type OBJECT", PolicyEndpoint{MatchingTargetType: "OBJECT"}, ""},
		{"invalid matching target type", PolicyEndpoint{MatchingTargetType: "INVALID"}, "matching_target_type must be one of"},
		{"valid port matching type ANY", PolicyEndpoint{PortMatchingType: "ANY"}, ""},
		{"valid port matching type SPECIFIC", PolicyEndpoint{PortMatchingType: "SPECIFIC"}, ""},
		{"invalid port matching type", PolicyEndpoint{PortMatchingType: "INVALID"}, "port_matching_type must be one of"},
		{"valid IPs", PolicyEndpoint{IPs: []string{"192.168.1.1", "10.0.0.0/8"}}, ""},
		{"invalid IP", PolicyEndpoint{IPs: []string{"invalid"}}, "must be a valid IP address or CIDR"},
		{"valid port", PolicyEndpoint{Port: "443"}, ""},
		{"valid port range", PolicyEndpoint{Port: "80-443"}, ""},
		{"invalid port", PolicyEndpoint{Port: "invalid"}, "port must be a valid port or port range"},
		{"valid MAC", PolicyEndpoint{MAC: "00:11:22:33:44:55"}, ""},
		{"invalid MAC", PolicyEndpoint{MAC: "invalid"}, "mac must be a valid MAC address"},
		{"valid client MACs", PolicyEndpoint{ClientMACs: []string{"00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"}}, ""},
		{"invalid client MAC", PolicyEndpoint{ClientMACs: []string{"invalid"}}, "client_mac \"invalid\" must be a valid MAC address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.endpoint.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestPolicyScheduleValidate(t *testing.T) {
	tests := []struct {
		name     string
		schedule PolicySchedule
		wantErr  string
	}{
		{"valid empty", PolicySchedule{}, ""},
		{"valid mode ALWAYS", PolicySchedule{Mode: "ALWAYS"}, ""},
		{"valid mode CUSTOM", PolicySchedule{Mode: "CUSTOM"}, ""},
		{"invalid mode", PolicySchedule{Mode: "INVALID"}, "mode must be one of"},
		{"valid time range start", PolicySchedule{TimeRangeStart: "08:00"}, ""},
		{"valid time range end", PolicySchedule{TimeRangeEnd: "17:00"}, ""},
		{"invalid time range start", PolicySchedule{TimeRangeStart: "invalid"}, "time_range_start must be in HH:MM format"},
		{"invalid time range end", PolicySchedule{TimeRangeEnd: "25:00"}, "time_range_end must be in HH:MM format"},
		{"valid days", PolicySchedule{DaysOfWeek: []string{"MONDAY", "FRIDAY"}}, ""},
		{"valid all days", PolicySchedule{DaysOfWeek: []string{"MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"}}, ""},
		{"invalid day", PolicySchedule{DaysOfWeek: []string{"INVALID"}}, "day \"INVALID\" must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.schedule.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func checkError(t *testing.T, err error, wantErr string) {
	t.Helper()
	if wantErr == "" {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Errorf("expected error containing %q, got nil", wantErr)
		return
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("expected error containing %q, got %q", wantErr, err.Error())
	}
}

func TestNetworkJSONRoundTrip(t *testing.T) {
	original := Network{
		Name:              "TestNet",
		Purpose:           "corporate",
		SettingPreference: "auto",
		GatewayType:       "default",
		NetworkVLAN: NetworkVLAN{
			VLAN:        IntPtr(100),
			VLANEnabled: BoolPtr(true),
			IPSubnet:    "192.168.1.0/24",
		},
		NetworkDHCP: NetworkDHCP{
			DHCPDEnabled: BoolPtr(true),
			DHCPDStart:   "192.168.1.100",
			DHCPDStop:    "192.168.1.200",
			NetworkDHCPDNS: NetworkDHCPDNS{
				DHCPDDNSEnabled: BoolPtr(true),
				DHCPDDns1:       "8.8.8.8",
			},
		},
		NetworkWAN: NetworkWAN{
			WANType:    "dhcp",
			WANGateway: "192.168.1.1",
		},
		NetworkRouting: NetworkRouting{
			NetworkGroup: "LAN",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map error: %v", err)
	}

	flatFields := []string{
		"name", "purpose", "setting_preference", "gateway_type",
		"vlan", "vlan_enabled", "ip_subnet",
		"dhcpd_enabled", "dhcpd_start", "dhcpd_stop",
		"dhcpd_dns_enabled", "dhcpd_dns_1",
		"wan_type", "wan_gateway",
		"networkgroup",
	}
	for _, field := range flatFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("field %q should be at top level in JSON", field)
		}
	}

	var decoded Network
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Name != original.Name {
		t.Errorf("Name mismatch: got %q, want %q", decoded.Name, original.Name)
	}
	if decoded.IPSubnet != original.IPSubnet {
		t.Errorf("IPSubnet mismatch: got %q, want %q", decoded.IPSubnet, original.IPSubnet)
	}
	if decoded.DHCPDStart != original.DHCPDStart {
		t.Errorf("DHCPDStart mismatch: got %q, want %q", decoded.DHCPDStart, original.DHCPDStart)
	}
	if decoded.WANType != original.WANType {
		t.Errorf("WANType mismatch: got %q, want %q", decoded.WANType, original.WANType)
	}
	if decoded.NetworkGroup != original.NetworkGroup {
		t.Errorf("NetworkGroup mismatch: got %q, want %q", decoded.NetworkGroup, original.NetworkGroup)
	}
}

func TestNetworkVLANValidate(t *testing.T) {
	tests := []struct {
		name    string
		vlan    NetworkVLAN
		wantErr string
	}{
		{"valid empty", NetworkVLAN{}, ""},
		{"valid cidr", NetworkVLAN{IPSubnet: "192.168.1.0/24"}, ""},
		{"invalid cidr", NetworkVLAN{IPSubnet: "invalid"}, "ip_subnet must be a valid CIDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.vlan.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkDHCPValidate(t *testing.T) {
	tests := []struct {
		name    string
		dhcp    NetworkDHCP
		wantErr string
	}{
		{"valid empty", NetworkDHCP{}, ""},
		{"valid ips", NetworkDHCP{DHCPDStart: "192.168.1.100", DHCPDStop: "192.168.1.200"}, ""},
		{"invalid start", NetworkDHCP{DHCPDStart: "invalid"}, "dhcpd_start must be a valid IP"},
		{"invalid stop", NetworkDHCP{DHCPDStop: "invalid"}, "dhcpd_stop must be a valid IP"},
		{"invalid gateway", NetworkDHCP{NetworkDHCPGateway: NetworkDHCPGateway{DHCPDGateway: "invalid"}}, "dhcpd_gateway must be a valid IP"},
		{"invalid dns1", NetworkDHCP{NetworkDHCPDNS: NetworkDHCPDNS{DHCPDDns1: "invalid"}}, "dhcpd_dns_1 must be a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dhcp.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkWANValidate(t *testing.T) {
	tests := []struct {
		name    string
		wan     NetworkWAN
		wantErr string
	}{
		{"valid empty", NetworkWAN{}, ""},
		{"valid wan_type", NetworkWAN{WANType: "dhcp"}, ""},
		{"invalid wan_type", NetworkWAN{WANType: "invalid"}, "wan_type must be one of"},
		{"invalid wan_ip", NetworkWAN{WANIP: "invalid"}, "wan_ip must be a valid IP"},
		{"invalid wan_gateway", NetworkWAN{WANGateway: "invalid"}, "wan_gateway must be a valid IP"},
		{"invalid wan_netmask", NetworkWAN{WANNetmask: "invalid"}, "wan_netmask must be a valid IP"},
		{"invalid wan_type_v6", NetworkWAN{NetworkWANIPv6: NetworkWANIPv6{WANTypeV6: "invalid"}}, "wan_type_v6 must be one of"},
		{"invalid load_balance_type", NetworkWAN{NetworkWANLoadBalance: NetworkWANLoadBalance{WANLoadBalanceType: "invalid"}}, "wan_load_balance_type must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.wan.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkRoutingValidate(t *testing.T) {
	tests := []struct {
		name    string
		routing NetworkRouting
		wantErr string
	}{
		{"valid empty", NetworkRouting{}, ""},
		{"valid networkgroup", NetworkRouting{NetworkGroup: "LAN"}, ""},
		{"invalid networkgroup", NetworkRouting{NetworkGroup: "invalid"}, "networkgroup must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.routing.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkDHCPBootValidate(t *testing.T) {
	tests := []struct {
		name    string
		boot    NetworkDHCPBoot
		wantErr string
	}{
		{"valid empty", NetworkDHCPBoot{}, ""},
		{"valid boot server", NetworkDHCPBoot{DHCPDBootServer: "192.168.1.1"}, ""},
		{"valid tftp server", NetworkDHCPBoot{DHCPDTFTPServer: "10.0.0.1"}, ""},
		{"invalid boot server", NetworkDHCPBoot{DHCPDBootServer: "not-an-ip"}, "dhcpd_boot_server must be a valid IP"},
		{"invalid tftp server", NetworkDHCPBoot{DHCPDTFTPServer: "bad"}, "dhcpd_tftp_server must be a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.boot.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkDHCPNTPValidate(t *testing.T) {
	tests := []struct {
		name    string
		ntp     NetworkDHCPNTP
		wantErr string
	}{
		{"valid empty", NetworkDHCPNTP{}, ""},
		{"valid ntp1", NetworkDHCPNTP{DHCPDNtp1: "192.168.1.1"}, ""},
		{"valid ntp2", NetworkDHCPNTP{DHCPDNtp2: "10.0.0.1"}, ""},
		{"invalid ntp1", NetworkDHCPNTP{DHCPDNtp1: "not-an-ip"}, "dhcpd_ntp_1 must be a valid IP"},
		{"invalid ntp2", NetworkDHCPNTP{DHCPDNtp2: "bad"}, "dhcpd_ntp_2 must be a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ntp.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkIPv6Validate(t *testing.T) {
	ipv6 := NetworkIPv6{IPv6SettingPreference: "auto"}
	if err := ipv6.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestNetworkMulticastValidate(t *testing.T) {
	mc := NetworkMulticast{DomainName: "example.local"}
	if err := mc.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestNetworkAccessValidate(t *testing.T) {
	tests := []struct {
		name    string
		access  NetworkAccess
		wantErr string
	}{
		{"valid empty", NetworkAccess{}, ""},
		{"valid IPs", NetworkAccess{NATOutboundIPAddresses: []string{"192.168.1.1", "10.0.0.1"}}, ""},
		{"invalid IP", NetworkAccess{NATOutboundIPAddresses: []string{"not-an-ip"}}, "invalid IP"},
		{"mixed valid and invalid", NetworkAccess{NATOutboundIPAddresses: []string{"192.168.1.1", "bad"}}, "invalid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.access.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestPortOverrideValidate(t *testing.T) {
	portIdx := 1
	tests := []struct {
		name    string
		po      PortOverride
		wantErr string
	}{
		{"valid", PortOverride{PortIdx: &portIdx, Name: "Port 1"}, ""},
		{"valid with profile", PortOverride{PortIdx: &portIdx, PortconfID: "abc123", SettingPreference: "manual"}, ""},
		{"missing port_idx", PortOverride{Name: "Port 1"}, "port_idx is required"},
		{"invalid setting_preference", PortOverride{PortIdx: &portIdx, SettingPreference: "invalid"}, "setting_preference must be one of"},
		{"invalid poe_mode", PortOverride{PortIdx: &portIdx, PoeMode: "invalid"}, "poe_mode must be one of"},
		{"valid poe_mode auto", PortOverride{PortIdx: &portIdx, PoeMode: "auto"}, ""},
		{"valid poe_mode off", PortOverride{PortIdx: &portIdx, PoeMode: "off"}, ""},
		{"valid poe_mode pasv24", PortOverride{PortIdx: &portIdx, PoeMode: "pasv24"}, ""},
		{"valid poe_mode passthrough", PortOverride{PortIdx: &portIdx, PoeMode: "passthrough"}, ""},
		{"invalid op_mode", PortOverride{PortIdx: &portIdx, OpMode: "invalid"}, "op_mode must be one of"},
		{"valid op_mode switch", PortOverride{PortIdx: &portIdx, OpMode: "switch"}, ""},
		{"valid op_mode mirror", PortOverride{PortIdx: &portIdx, OpMode: "mirror"}, ""},
		{"valid op_mode aggregate", PortOverride{PortIdx: &portIdx, OpMode: "aggregate"}, ""},
		{"invalid forward", PortOverride{PortIdx: &portIdx, Forward: "invalid"}, "forward must be one of"},
		{"valid forward all", PortOverride{PortIdx: &portIdx, Forward: "all"}, ""},
		{"valid forward native", PortOverride{PortIdx: &portIdx, Forward: "native"}, ""},
		{"valid forward customize", PortOverride{PortIdx: &portIdx, Forward: "customize"}, ""},
		{"valid forward disabled", PortOverride{PortIdx: &portIdx, Forward: "disabled"}, ""},
		{"invalid tagged_vlan_mgmt", PortOverride{PortIdx: &portIdx, TaggedVlanMgmt: "invalid"}, "tagged_vlan_mgmt must be one of"},
		{"valid tagged_vlan_mgmt auto", PortOverride{PortIdx: &portIdx, TaggedVlanMgmt: "auto"}, ""},
		{"valid tagged_vlan_mgmt block_all", PortOverride{PortIdx: &portIdx, TaggedVlanMgmt: "block_all"}, ""},
		{"invalid mac", PortOverride{PortIdx: &portIdx, PortSecurityMacAddress: []string{"invalid"}}, "port_security_mac_address[0] must be a valid MAC"},
		{"valid mac", PortOverride{PortIdx: &portIdx, PortSecurityMacAddress: []string{"aa:bb:cc:dd:ee:ff"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.po.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestDeviceConfigValidate(t *testing.T) {
	portIdx := 1
	tests := []struct {
		name    string
		device  DeviceConfig
		wantErr string
	}{
		{"valid empty", DeviceConfig{}, ""},
		{"valid with name", DeviceConfig{Name: "My Switch"}, ""},
		{"invalid led_override", DeviceConfig{LedOverride: "invalid"}, "led_override must be one of"},
		{"valid led_override default", DeviceConfig{LedOverride: "default"}, ""},
		{"valid led_override on", DeviceConfig{LedOverride: "on"}, ""},
		{"valid led_override off", DeviceConfig{LedOverride: "off"}, ""},
		{"valid port_overrides", DeviceConfig{PortOverrides: []PortOverride{{PortIdx: &portIdx}}}, ""},
		{"invalid port_override", DeviceConfig{PortOverrides: []PortOverride{{Name: "Port 1"}}}, "port_overrides[0]: portoverride: port_idx is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.device.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}
