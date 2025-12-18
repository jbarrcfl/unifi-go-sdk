package unifi

import "encoding/json"

// WANProviderCapabilities describes ISP bandwidth capabilities for a WAN network.
type WANProviderCapabilities struct {
	DownloadKilobitsPerSecond *int `json:"download_kilobits_per_second,omitempty"`
	UploadKilobitsPerSecond   *int `json:"upload_kilobits_per_second,omitempty"`
}

// QoSProfile describes Quality of Service settings for a port profile.
type QoSProfile struct {
	QoSPolicies    []json.RawMessage `json:"qos_policies,omitempty"`
	QoSProfileMode string            `json:"qos_profile_mode,omitempty"`
}

// Network represents a UniFi network/VLAN configuration.
// This corresponds to the networkconf REST endpoint.
//
// Field value reference:
//   - Purpose: "corporate", "guest", "wan", "vlan-only", "vpn-client", "remote-user-vpn"
//   - NetworkGroup: "LAN", "WAN", "WAN2"
//   - WANType: "dhcp", "static", "pppoe", "disabled"
//   - WANTypeV6: "disabled", "dhcpv6", "static", "autoconf"
//   - SettingPreference: "auto", "manual"
//   - GatewayType: "default", "switch"
//   - WANLoadBalanceType: "failover-only", "weighted"
type Network struct {
	ID                          string   `json:"_id,omitempty"`
	SiteID                      string   `json:"site_id,omitempty"`
	Name                        string   `json:"name"`
	Purpose                     string   `json:"purpose,omitempty"`
	Enabled                     *bool    `json:"enabled,omitempty"`
	VLAN                        *int     `json:"vlan,omitempty"`
	VLANEnabled                 *bool    `json:"vlan_enabled,omitempty"`
	IPSubnet                    string   `json:"ip_subnet,omitempty"`
	NetworkGroup                string   `json:"networkgroup,omitempty"`
	DHCPDEnabled                *bool    `json:"dhcpd_enabled,omitempty"`
	DHCPDStart                  string   `json:"dhcpd_start,omitempty"`
	DHCPDStop                   string   `json:"dhcpd_stop,omitempty"`
	DHCPDLeasetime              *int     `json:"dhcpd_leasetime,omitempty"`
	DHCPDGatewayEnabled         *bool    `json:"dhcpd_gateway_enabled,omitempty"`
	DHCPDGateway                string   `json:"dhcpd_gateway,omitempty"`
	DHCPDDNSEnabled             *bool    `json:"dhcpd_dns_enabled,omitempty"`
	DHCPDDns1                   string   `json:"dhcpd_dns_1,omitempty"`
	DHCPDDns2                   string   `json:"dhcpd_dns_2,omitempty"`
	DHCPDDns3                   string   `json:"dhcpd_dns_3,omitempty"`
	DHCPDDns4                   string   `json:"dhcpd_dns_4,omitempty"`
	DHCPRelayEnabled            *bool    `json:"dhcp_relay_enabled,omitempty"`
	DHCPDTimeOffsetEnabled      *bool    `json:"dhcpd_time_offset_enabled,omitempty"`
	DHCPDBootEnabled            *bool    `json:"dhcpd_boot_enabled,omitempty"`
	DHCPDBootServer             string   `json:"dhcpd_boot_server,omitempty"`
	DHCPDBootFilename           string   `json:"dhcpd_boot_filename,omitempty"`
	DHCPDTFTPServer             string   `json:"dhcpd_tftp_server,omitempty"`
	DHCPDUnifiController        string   `json:"dhcpd_unifi_controller,omitempty"`
	DHCPDWPADUrl                string   `json:"dhcpd_wpad_url,omitempty"`
	DHCPDNTPEnabled             *bool    `json:"dhcpd_ntp_enabled,omitempty"`
	DHCPDNtp1                   string   `json:"dhcpd_ntp_1,omitempty"`
	DHCPDNtp2                   string   `json:"dhcpd_ntp_2,omitempty"`
	DHCPGuardingEnabled         *bool    `json:"dhcpguard_enabled,omitempty"`
	DomainName                  string   `json:"domain_name,omitempty"`
	IGMPSnooping                *bool    `json:"igmp_snooping,omitempty"`
	IGMPProxyUpstream           *bool    `json:"igmp_proxy_upstream,omitempty"`
	IGMPProxyFor                string   `json:"igmp_proxy_for,omitempty"`
	InternetAccessEnabled       *bool    `json:"internet_access_enabled,omitempty"`
	IntraNetworkAccessEnabled   *bool    `json:"intra_network_access_enabled,omitempty"`
	IsNAT                       *bool    `json:"is_nat,omitempty"`
	LteLANEnabled               *bool    `json:"lte_lan_enabled,omitempty"`
	MDNSEnabled                 *bool    `json:"mdns_enabled,omitempty"`
	MACOverrideEnabled          *bool    `json:"mac_override_enabled,omitempty"`
	NATOutboundIPAddresses      []string `json:"nat_outbound_ip_addresses,omitempty"`
	PptpcServerEnabled          *bool    `json:"pptpc_server_enabled,omitempty"`
	SettingPreference           string   `json:"setting_preference,omitempty"`
	UpnpLANEnabled              *bool    `json:"upnp_lan_enabled,omitempty"`
	ReportWANEvent              *bool    `json:"report_wan_event,omitempty"`
	RoutingTableID              *int     `json:"routing_table_id,omitempty"`
	SingleNetworkLAN            string   `json:"single_network_lan,omitempty"`
	FirewallZoneID              string   `json:"firewall_zone_id,omitempty"`
	WAN                         string   `json:"wan,omitempty"`
	WANDHCPCos                  *int     `json:"wan_dhcp_cos,omitempty"`
	WANDHCPOptions              []json.RawMessage `json:"wan_dhcp_options,omitempty"`
	WANDHCPv6Cos                *int     `json:"wan_dhcpv6_cos,omitempty"`
	WANDHCPv6PDSizeAuto         *bool    `json:"wan_dhcpv6_pd_size_auto,omitempty"`
	WANDNSPreference            string   `json:"wan_dns_preference,omitempty"`
	WANDsliteRemoteHost         string   `json:"wan_dslite_remote_host,omitempty"`
	WANDsliteRemoteHostAuto     *bool    `json:"wan_dslite_remote_host_auto,omitempty"`
	WANEgressQOS                string   `json:"wan_egress_qos,omitempty"`
	WANFailoverPriority         *int     `json:"wan_failover_priority,omitempty"`
	WANGateway                  string   `json:"wan_gateway,omitempty"`
	WANIP                       string   `json:"wan_ip,omitempty"`
	WANIPAliases                []string `json:"wan_ip_aliases,omitempty"`
	WANIPv6DNS1                 string   `json:"wan_ipv6_dns1,omitempty"`
	WANIPv6DNS2                 string   `json:"wan_ipv6_dns2,omitempty"`
	WANIPv6DNSPreference        string   `json:"wan_ipv6_dns_preference,omitempty"`
	WANLoadBalanceType          string   `json:"wan_load_balance_type,omitempty"`
	WANLoadBalanceWeight        *int     `json:"wan_load_balance_weight,omitempty"`
	WANNetmask                  string   `json:"wan_netmask,omitempty"`
	WANNetworkGroup             string   `json:"wan_networkgroup,omitempty"`
	WANProviderCapabilities     *WANProviderCapabilities `json:"wan_provider_capabilities,omitempty"`
	WANSmartQEnabled            *bool    `json:"wan_smartq_enabled,omitempty"`
	WANType                     string   `json:"wan_type,omitempty"`
	WANTypeV6                   string   `json:"wan_type_v6,omitempty"`
	WANVLANEnabled              *bool    `json:"wan_vlan_enabled,omitempty"`
	WANVLAN                     *int     `json:"wan_vlan,omitempty"`
	AutoScaleEnabled            *bool    `json:"auto_scale_enabled,omitempty"`
	GatewayType                 string   `json:"gateway_type,omitempty"`
	GatewayDevice               string   `json:"gateway_device,omitempty"`
	IPv6SettingPreference       string   `json:"ipv6_setting_preference,omitempty"`
	IPv6WANDelegationType       string   `json:"ipv6_wan_delegation_type,omitempty"`
	AttrHiddenID                string   `json:"attr_hidden_id,omitempty"`
	AttrNoDelete                *bool    `json:"attr_no_delete,omitempty"`
}

// FirewallRule represents a UniFi firewall rule.
//
// Field value reference:
//   - Action: "accept", "drop", "reject"
//   - Ruleset: "WAN_IN", "WAN_OUT", "WAN_LOCAL", "LAN_IN", "LAN_OUT", "LAN_LOCAL",
//     "GUEST_IN", "GUEST_OUT", "GUEST_LOCAL", "WANv6_IN", "WANv6_OUT", "WANv6_LOCAL",
//     "LANv6_IN", "LANv6_OUT", "LANv6_LOCAL", "GUESTv6_IN", "GUESTv6_OUT", "GUESTv6_LOCAL"
//   - Protocol: "all", "tcp", "udp", "tcp_udp", "icmp", "ah", "ax.25", "dccp", "ddp",
//     "egp", "eigrp", "encap", "esp", "etherip", "fc", "ggp", "gre", "hip", "hmp",
//     "icmpv6", "idpr-cmtp", "idrp", "igmp", "igp", "ip", "ipcomp", "ipencap", "ipip",
//     "ipv6", "ipv6-frag", "ipv6-icmp", "ipv6-nonxt", "ipv6-opts", "ipv6-route",
//     "isis", "iso-tp4", "l2tp", "manet", "mobility-header", "mpls-in-ip", "ospf",
//     "pim", "pup", "rdp", "rohc", "rspf", "rsvp", "sctp", "shim6", "skip", "st",
//     "udplite", "vmtp", "vrrp", "wesp", "xns-idp", "xtp"
//   - IPSec: "match-ipsec", "match-none", ""
//   - SrcNetworkConfType/DstNetworkConfType: "ADDRv4", "NETv4"
type FirewallRule struct {
	ID                  string   `json:"_id,omitempty"`
	SiteID              string   `json:"site_id,omitempty"`
	Name                string   `json:"name"`
	Enabled             *bool    `json:"enabled,omitempty"`
	RuleIndex           *int     `json:"rule_index,omitempty"`
	Ruleset             string   `json:"ruleset,omitempty"`
	Action              string   `json:"action,omitempty"`
	Protocol            string   `json:"protocol,omitempty"`
	ProtocolMatchExcepted *bool  `json:"protocol_match_excepted,omitempty"`
	ProtocolV6          string   `json:"protocol_v6,omitempty"`
	ICMPTypename        string   `json:"icmp_typename,omitempty"`
	ICMPv6Typename      string   `json:"icmp_v6_typename,omitempty"`
	Logging             *bool    `json:"logging,omitempty"`
	StateEstablished    *bool    `json:"state_established,omitempty"`
	StateInvalid        *bool    `json:"state_invalid,omitempty"`
	StateNew            *bool    `json:"state_new,omitempty"`
	StateRelated        *bool    `json:"state_related,omitempty"`
	IPSec               string   `json:"ipsec,omitempty"`
	SrcFirewallGroupIDs []string `json:"src_firewallgroup_ids,omitempty"`
	SrcMACAddress       string   `json:"src_mac_address,omitempty"`
	SrcAddress          string   `json:"src_address,omitempty"`
	SrcNetworkConfID    string   `json:"src_networkconf_id,omitempty"`
	SrcNetworkConfType  string   `json:"src_networkconf_type,omitempty"`
	SrcPort             string   `json:"src_port,omitempty"`
	DstFirewallGroupIDs []string `json:"dst_firewallgroup_ids,omitempty"`
	DstAddress          string   `json:"dst_address,omitempty"`
	DstNetworkConfID    string   `json:"dst_networkconf_id,omitempty"`
	DstNetworkConfType  string   `json:"dst_networkconf_type,omitempty"`
	DstPort             string   `json:"dst_port,omitempty"`
}

// FirewallGroup represents a UniFi firewall group (IP group, port group, or IPv6 group).
//
// Field value reference:
//   - GroupType: "address-group", "port-group", "ipv6-address-group"
type FirewallGroup struct {
	ID          string   `json:"_id,omitempty"`
	SiteID      string   `json:"site_id,omitempty"`
	Name        string   `json:"name"`
	GroupType   string   `json:"group_type,omitempty"`
	GroupMembers []string `json:"group_members,omitempty"`
}

// PortForward represents a UniFi port forwarding rule.
//
// Field value reference:
//   - Proto: "tcp", "udp", "tcp_udp"
//   - PfwdInterface: "wan", "wan2", "both"
type PortForward struct {
	ID                 string   `json:"_id,omitempty"`
	SiteID             string   `json:"site_id,omitempty"`
	Name               string   `json:"name"`
	Enabled            *bool    `json:"enabled,omitempty"`
	PfwdInterface      string   `json:"pfwd_interface,omitempty"`
	Proto              string   `json:"proto,omitempty"`
	Src                string   `json:"src,omitempty"`
	DstPort            string   `json:"dst_port,omitempty"`
	Fwd                string   `json:"fwd,omitempty"`
	FwdPort            string   `json:"fwd_port,omitempty"`
	Log                *bool    `json:"log,omitempty"`
	DestinationIP      string   `json:"destination_ip,omitempty"`
	DestinationIPs     []string `json:"destination_ips,omitempty"`
	SrcLimitingEnabled *bool    `json:"src_limiting_enabled,omitempty"`
}

// WLANConf represents a UniFi wireless network (SSID) configuration.
//
// Field value reference:
//   - Security: "open", "wep", "wpapsk", "wpaeap"
//   - WPAMode: "wpa1", "wpa2", "wpa3"
//   - WPAEnc: "ccmp", "gcmp", "auto"
//   - WLANBand: "2g", "5g", "both"
//   - MacFilterPolicy: "allow", "deny"
//   - Pmf (PMF mode): "disabled", "optional", "required"
//   - DtimMode: "default", "custom"
//   - APGroupMode: "all", "groups"
type WLANConf struct {
	ID                       string   `json:"_id,omitempty"`
	SiteID                   string   `json:"site_id,omitempty"`
	Name                     string   `json:"name"`
	Enabled                  *bool    `json:"enabled,omitempty"`
	Security                 string   `json:"security,omitempty"`
	WPAMode                  string   `json:"wpa_mode,omitempty"`
	WPAEnc                   string   `json:"wpa_enc,omitempty"`
	WPA3Support              *bool    `json:"wpa3_support,omitempty"`
	WPA3Transition           *bool    `json:"wpa3_transition,omitempty"`
	WPA3Enhanced192          *bool    `json:"wpa3_enhanced_192,omitempty"`
	WPA3FastRoaming          *bool    `json:"wpa3_fast_roaming,omitempty"`
	XPassphrase              string   `json:"x_passphrase,omitempty"`
	XIappKey                 string   `json:"x_iapp_key,omitempty"`
	PassphraseAutogenerated  *bool    `json:"passphrase_autogenerated,omitempty"`
	PrivatePresharedKeys     []json.RawMessage `json:"private_preshared_keys,omitempty"`
	PrivatePresharedKeysEnabled *bool `json:"private_preshared_keys_enabled,omitempty"`
	NetworkID                string   `json:"networkconf_id,omitempty"`
	Usergroup                string   `json:"usergroup_id,omitempty"`
	IsGuest                  *bool    `json:"is_guest,omitempty"`
	HideSsid                 *bool    `json:"hide_ssid,omitempty"`
	WLANBand                 string   `json:"wlan_band,omitempty"`
	WLANBands                []string `json:"wlan_bands,omitempty"`
	APGroupIDs               []string `json:"ap_group_ids,omitempty"`
	APGroupMode              string   `json:"ap_group_mode,omitempty"`
	Vlan                     *int     `json:"vlan,omitempty"`
	VlanEnabled              *bool    `json:"vlan_enabled,omitempty"`
	MacFilterEnabled         *bool    `json:"mac_filter_enabled,omitempty"`
	MacFilterList            []string `json:"mac_filter_list,omitempty"`
	MacFilterPolicy          string   `json:"mac_filter_policy,omitempty"`
	RadiusProfileID          string   `json:"radiusprofile_id,omitempty"`
	RadiusDasEnabled         *bool    `json:"radius_das_enabled,omitempty"`
	RadiusMacAuthEnabled     *bool    `json:"radius_mac_auth_enabled,omitempty"`
	RadiusMacaclFormat       string   `json:"radius_macacl_format,omitempty"`
	ScheduleEnabled          *bool    `json:"schedule_enabled,omitempty"`
	Schedule                 []string `json:"schedule,omitempty"`
	ScheduleWithDuration     []json.RawMessage `json:"schedule_with_duration,omitempty"`
	SettingPreference        string   `json:"setting_preference,omitempty"`
	MinrateNgEnabled         *bool    `json:"minrate_ng_enabled,omitempty"`
	MinrateNgDataRateKbps    *int     `json:"minrate_ng_data_rate_kbps,omitempty"`
	MinrateNgAdvertisingRates *bool   `json:"minrate_ng_advertising_rates,omitempty"`
	MinrateNaEnabled         *bool    `json:"minrate_na_enabled,omitempty"`
	MinrateNaDataRateKbps    *int     `json:"minrate_na_data_rate_kbps,omitempty"`
	MinrateNaAdvertisingRates *bool   `json:"minrate_na_advertising_rates,omitempty"`
	MinrateSettingPreference string   `json:"minrate_setting_preference,omitempty"`
	No2GhzOui                *bool    `json:"no2ghz_oui,omitempty"`
	NoIPv6Ndp                *bool    `json:"no_ipv6_ndp,omitempty"`
	OptimizeIotWifiConn      *bool    `json:"optimize_iot_wifi_connectivity,omitempty"`
	Pmf                      string   `json:"pmf_mode,omitempty"`
	BcastEnhanceEnabled      *bool    `json:"bcastenhance_enabled,omitempty"`
	McastEnhanceEnabled      *bool    `json:"mcastenhance_enabled,omitempty"`
	GroupRekey               *int     `json:"group_rekey,omitempty"`
	DtimMode                 string   `json:"dtim_mode,omitempty"`
	DtimNa                   *int     `json:"dtim_na,omitempty"`
	DtimNg                   *int     `json:"dtim_ng,omitempty"`
	Dtim6e                   *int     `json:"dtim_6e,omitempty"`
	Uapsd                    *bool    `json:"uapsd_enabled,omitempty"`
	FastRoamingEnabled       *bool    `json:"fast_roaming_enabled,omitempty"`
	ProxyArp                 *bool    `json:"proxy_arp,omitempty"`
	BssTransition            *bool    `json:"bss_transition,omitempty"`
	L2Isolation              *bool    `json:"l2_isolation,omitempty"`
	IappEnabled              *bool    `json:"iapp_enabled,omitempty"`
}

// PortConf represents a UniFi switch port profile.
//
// Field value reference:
//   - Forward: "all", "native", "customize", "disabled"
//   - Dot1xCtrl: "force_authorized", "force_unauthorized", "auto", "mac_based", "multi_host"
//   - OpMode: "switch", "mirror", "aggregate"
//   - PoeMode: "auto", "pasv24", "passthrough", "off"
//   - SettingPreference: "auto", "manual"
type PortConf struct {
	ID                          string   `json:"_id,omitempty"`
	SiteID                      string   `json:"site_id,omitempty"`
	Name                        string   `json:"name"`
	Forward                     string   `json:"forward,omitempty"`
	NativeNetworkconfID         string   `json:"native_networkconf_id,omitempty"`
	TaggedNetworkconfIDs        []string `json:"tagged_networkconf_ids,omitempty"`
	VoiceNetworkconfID          string   `json:"voice_networkconf_id,omitempty"`
	Autoneg                     *bool    `json:"autoneg,omitempty"`
	Dot1xCtrl                   string   `json:"dot1x_ctrl,omitempty"`
	Dot1xIDleTimeout            *int     `json:"dot1x_idle_timeout,omitempty"`
	EgressRateLimitKbps         *int     `json:"egress_rate_limit_kbps,omitempty"`
	EgressRateLimitEnabled      *bool    `json:"egress_rate_limit_kbps_enabled,omitempty"`
	FullDuplex                  *bool    `json:"full_duplex,omitempty"`
	Isolation                   *bool    `json:"isolation,omitempty"`
	LldpmedEnabled              *bool    `json:"lldpmed_enabled,omitempty"`
	LldpmedNotifyEnabled        *bool    `json:"lldpmed_notify_enabled,omitempty"`
	MulticastRouterNetworkconfIDs []string `json:"multicast_router_networkconf_ids,omitempty"`
	OpMode                      string   `json:"op_mode,omitempty"`
	PoeMode                     string   `json:"poe_mode,omitempty"`
	PortKeepaliveEnabled        *bool    `json:"port_keepalive_enabled,omitempty"`
	PortSecurityEnabled         *bool    `json:"port_security_enabled,omitempty"`
	PortSecurityMacAddress      []string `json:"port_security_mac_address,omitempty"`
	QosProfile                  *QoSProfile `json:"qos_profile,omitempty"`
	SettingPreference           string   `json:"setting_preference,omitempty"`
	Speed                       *int     `json:"speed,omitempty"`
	StormctrlBcastEnabled       *bool    `json:"stormctrl_bcast_enabled,omitempty"`
	StormctrlBcastRate          *int     `json:"stormctrl_bcast_rate,omitempty"`
	StormctrlMcastEnabled       *bool    `json:"stormctrl_mcast_enabled,omitempty"`
	StormctrlMcastRate          *int     `json:"stormctrl_mcast_rate,omitempty"`
	StormctrlUcastEnabled       *bool    `json:"stormctrl_ucast_enabled,omitempty"`
	StormctrlUcastRate          *int     `json:"stormctrl_ucast_rate,omitempty"`
	StpPortMode                 *bool    `json:"stp_port_mode,omitempty"`
	TaggedVlanMgmt              string   `json:"tagged_vlan_mgmt,omitempty"`
}

// Routing represents a UniFi static route.
//
// Field value reference:
//   - Type: "static-route", "interface-route"
//   - StaticRouteType: "nexthop-route", "interface-route", "blackhole"
//   - GatewayType: "default", "switch"
type Routing struct {
	ID                 string `json:"_id,omitempty"`
	SiteID             string `json:"site_id,omitempty"`
	Name               string `json:"name"`
	Enabled            *bool  `json:"enabled,omitempty"`
	Type               string `json:"type,omitempty"`
	GatewayType        string `json:"gateway_type,omitempty"`
	GatewayDevice      string `json:"gateway_device,omitempty"`
	StaticRouteNetwork string `json:"static-route_network,omitempty"`
	StaticRouteNexthop string `json:"static-route_nexthop,omitempty"`
	StaticRouteDistance *int  `json:"static-route_distance,omitempty"`
	StaticRouteInterface string `json:"static-route_interface,omitempty"`
	StaticRouteType    string `json:"static-route_type,omitempty"`
}

// UserGroup represents a UniFi user group (bandwidth profile).
type UserGroup struct {
	ID             string `json:"_id,omitempty"`
	SiteID         string `json:"site_id,omitempty"`
	Name           string `json:"name"`
	QosRateMaxDown *int   `json:"qos_rate_max_down,omitempty"`
	QosRateMaxUp   *int   `json:"qos_rate_max_up,omitempty"`
	AttrHiddenID   string `json:"attr_hidden_id,omitempty"`
	AttrNoDelete   *bool  `json:"attr_no_delete,omitempty"`
}

// RADIUSProfile represents a UniFi RADIUS profile.
//
// Field value reference:
//   - VlanWlanMode: "disabled", "optional", "required"
type RADIUSProfile struct {
	ID                    string         `json:"_id,omitempty"`
	SiteID                string         `json:"site_id,omitempty"`
	Name                  string         `json:"name"`
	UseUsgAcctServer      *bool          `json:"use_usg_acct_server,omitempty"`
	UseUsgAuthServer      *bool          `json:"use_usg_auth_server,omitempty"`
	VlanEnabled           *bool          `json:"vlan_enabled,omitempty"`
	VlanWlanMode          string         `json:"vlan_wlan_mode,omitempty"`
	AcctServers           []RADIUSServer `json:"acct_servers,omitempty"`
	AuthServers           []RADIUSServer `json:"auth_servers,omitempty"`
	InterimUpdateEnabled  *bool          `json:"interim_update_enabled,omitempty"`
	InterimUpdateInterval *int           `json:"interim_update_interval,omitempty"`
	AttrHiddenID          string         `json:"attr_hidden_id,omitempty"`
	AttrNoDelete          *bool          `json:"attr_no_delete,omitempty"`
	AttrNoEdit            *bool          `json:"attr_no_edit,omitempty"`
}

// RADIUSServer represents a RADIUS server configuration.
type RADIUSServer struct {
	IP      string `json:"ip,omitempty"`
	Port    *int   `json:"port,omitempty"`
	XSecret string `json:"x_secret,omitempty"`
}

// DynamicDNS represents a UniFi dynamic DNS configuration.
//
// Field value reference:
//   - Service: "afraid", "changeip", "cloudflare", "dnspark", "dslreports", "dyndns",
//     "easydns", "namecheap", "noip", "sitelutions", "zoneedit", "custom"
//   - Interface: "wan", "wan2"
type DynamicDNS struct {
	ID        string `json:"_id,omitempty"`
	SiteID    string `json:"site_id,omitempty"`
	Service   string `json:"service,omitempty"`
	HostName  string `json:"host_name,omitempty"`
	Login     string `json:"login,omitempty"`
	XPassword string `json:"x_password,omitempty"`
	Server    string `json:"server,omitempty"`
	Interface string `json:"interface,omitempty"`
	Options   string `json:"options,omitempty"`
}

// FirewallPolicy represents a zone-based firewall policy (v2 API).
//
// Field value reference:
//   - Action: "ALLOW", "BLOCK", "REJECT"
//   - Protocol: "all", "tcp_udp", "tcp", "udp", "icmp", "icmpv6"
//   - IPVersion: "BOTH", "IPV4", "IPV6"
//   - ConnectionStateType: "ALL", "RESPOND_ONLY", "CUSTOM"
//   - OriginType: "custom_firewall_rule", "port_forward"
type FirewallPolicy struct {
	ID                    string          `json:"_id,omitempty"`
	Name                  string          `json:"name"`
	Enabled               *bool           `json:"enabled,omitempty"`
	Action                string          `json:"action,omitempty"`
	Protocol              string          `json:"protocol,omitempty"`
	IPVersion             string          `json:"ip_version,omitempty"`
	Index                 *int            `json:"index,omitempty"`
	Logging               *bool           `json:"logging,omitempty"`
	Predefined            *bool           `json:"predefined,omitempty"`
	ConnectionStateType   string          `json:"connection_state_type,omitempty"`
	ConnectionStates      []string        `json:"connection_states,omitempty"`
	CreateAllowRespond    *bool           `json:"create_allow_respond,omitempty"`
	MatchIPSec            *bool           `json:"match_ip_sec,omitempty"`
	MatchOppositeProtocol *bool           `json:"match_opposite_protocol,omitempty"`
	ICMPTypename          string          `json:"icmp_typename,omitempty"`
	ICMPV6Typename        string          `json:"icmp_v6_typename,omitempty"`
	Schedule              *PolicySchedule `json:"schedule,omitempty"`
	Source                *PolicyEndpoint `json:"source,omitempty"`
	Destination           *PolicyEndpoint `json:"destination,omitempty"`
	OriginID              string          `json:"origin_id,omitempty"`
	OriginType            string          `json:"origin_type,omitempty"`
}

// PolicyEndpoint defines source or destination matching criteria for a firewall policy.
//
// Field value reference:
//   - MatchingTarget: "ANY", "IP", "NETWORK", "DOMAIN", "REGION", "PORT_GROUP", "ADDRESS_GROUP"
//   - MatchingTargetType: "SPECIFIC", "OBJECT"
//   - PortMatchingType: "ANY", "SPECIFIC"
type PolicyEndpoint struct {
	ZoneID             string   `json:"zone_id,omitempty"`
	MatchingTarget     string   `json:"matching_target,omitempty"`
	MatchingTargetType string   `json:"matching_target_type,omitempty"`
	IPs                []string `json:"ips,omitempty"`
	MAC                string   `json:"mac,omitempty"`
	MatchMAC           *bool    `json:"match_mac,omitempty"`
	MatchOppositeIPs   *bool    `json:"match_opposite_ips,omitempty"`
	Port               string   `json:"port,omitempty"`
	PortMatchingType   string   `json:"port_matching_type,omitempty"`
	MatchOppositePorts *bool    `json:"match_opposite_ports,omitempty"`
	NetworkID          string   `json:"network_id,omitempty"`
	ClientMACs         []string `json:"client_macs,omitempty"`
}

// PolicySchedule defines when a firewall policy is active.
//
// Field value reference:
//   - Mode: "ALWAYS", "CUSTOM"
//   - DaysOfWeek: "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"
type PolicySchedule struct {
	Mode           string   `json:"mode,omitempty"`
	TimeRangeStart string   `json:"time_range_start,omitempty"`
	TimeRangeEnd   string   `json:"time_range_end,omitempty"`
	DaysOfWeek     []string `json:"days_of_week,omitempty"`
}

// FirewallZone represents a firewall zone (v2 API).
//
// Field value reference:
//   - ZoneKey: "internal", "external", "gateway", "vpn", "hotspot", "dmz" (nil for custom zones)
type FirewallZone struct {
	ID          string   `json:"_id,omitempty"`
	Name        string   `json:"name"`
	ZoneKey     *string  `json:"zone_key,omitempty"`
	DefaultZone *bool    `json:"default_zone,omitempty"`
	AttrNoEdit  *bool    `json:"attr_no_edit,omitempty"`
	NetworkIDs  []string `json:"network_ids,omitempty"`
}

// StaticDNS represents a static DNS record (v2 API).
//
// Field value reference:
//   - RecordType: "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV"
type StaticDNS struct {
	ID         string `json:"_id,omitempty"`
	Key        string `json:"key,omitempty"`
	Value      string `json:"value,omitempty"`
	RecordType string `json:"record_type,omitempty"`
	Enabled    *bool  `json:"enabled,omitempty"`
	TTL        *int   `json:"ttl,omitempty"`
	Port       *int   `json:"port,omitempty"`
	Priority   *int   `json:"priority,omitempty"`
	Weight     *int   `json:"weight,omitempty"`
}

// Client represents an active network client (v2 API, read-only).
type Client struct {
	ID                     string             `json:"id,omitempty"`
	MAC                    string             `json:"mac,omitempty"`
	DisplayName            string             `json:"display_name,omitempty"`
	Status                 string             `json:"status,omitempty"`
	Type                   string             `json:"type,omitempty"`
	IsWired                *bool              `json:"is_wired,omitempty"`
	IsGuest                *bool              `json:"is_guest,omitempty"`
	Blocked                *bool              `json:"blocked,omitempty"`
	NetworkID              string             `json:"network_id,omitempty"`
	NetworkName            string             `json:"network_name,omitempty"`
	LastIP                 string             `json:"last_ip,omitempty"`
	VLAN                   *int               `json:"vlan,omitempty"`
	OUI                    string             `json:"oui,omitempty"`
	Uptime                 *int64             `json:"uptime,omitempty"`
	FirstSeen              *int64             `json:"first_seen,omitempty"`
	LastSeen               *int64             `json:"last_seen,omitempty"`
	RxBytes                *int64             `json:"rx_bytes,omitempty"`
	TxBytes                *int64             `json:"tx_bytes,omitempty"`
	RxPackets              *int64             `json:"rx_packets,omitempty"`
	TxPackets              *int64             `json:"tx_packets,omitempty"`
	WiredRateMbps          *int               `json:"wired_rate_mbps,omitempty"`
	WifiExperienceScore    *float64           `json:"wifi_experience_score,omitempty"`
	Satisfaction           *float64           `json:"satisfaction,omitempty"`
	UserID                 string             `json:"user_id,omitempty"`
	UsergroupID            string             `json:"usergroup_id,omitempty"`
	UseFixedIP             *bool              `json:"use_fixedip,omitempty"`
	FixedIP                string             `json:"fixed_ip,omitempty"`
	LocalDnsRecord         string             `json:"local_dns_record,omitempty"`
	LocalDnsRecordEnabled  *bool              `json:"local_dns_record_enabled,omitempty"`
	Noted                  *bool              `json:"noted,omitempty"`
	Note                   string             `json:"note,omitempty"`
	Fingerprint            *ClientFingerprint `json:"fingerprint,omitempty"`
	LastUplinkMAC          string             `json:"last_uplink_mac,omitempty"`
	LastUplinkName         string             `json:"last_uplink_name,omitempty"`
	LastUplinkRemotePort   *int               `json:"last_uplink_remote_port,omitempty"`
	SwPort                 *int               `json:"sw_port,omitempty"`
	SiteID                 string             `json:"site_id,omitempty"`
}

// ClientFingerprint contains device identification data.
type ClientFingerprint struct {
	HasOverride     *bool `json:"has_override,omitempty"`
	ComputedDevID   *int  `json:"computed_dev_id,omitempty"`
	ComputedEngine  *int  `json:"computed_engine,omitempty"`
}

// DeviceList contains network devices organized by type (v2 API, read-only).
type DeviceList struct {
	NetworkDevices []NetworkDevice   `json:"network_devices,omitempty"`
	AccessDevices  []json.RawMessage `json:"access_devices,omitempty"`
	ProtectDevices []json.RawMessage `json:"protect_devices,omitempty"`
}

// NetworkDevice represents a UniFi network device (v2 API, read-only).
//
// Field value reference:
//   - Type: "uap", "usw", "ugw", "uxg", "udm"
//   - State: 0=offline, 1=connected, 2=pending
type NetworkDevice struct {
	ID                    string             `json:"_id,omitempty"`
	MAC                   string             `json:"mac,omitempty"`
	IP                    string             `json:"ip,omitempty"`
	Name                  string             `json:"name,omitempty"`
	Model                 string             `json:"model,omitempty"`
	Type                  string             `json:"type,omitempty"`
	Adopted               *bool              `json:"adopted,omitempty"`
	State                 *int               `json:"state,omitempty"`
	Version               string             `json:"version,omitempty"`
	DisplayableVersion    string             `json:"displayable_version,omitempty"`
	Upgradable            *bool              `json:"upgradable,omitempty"`
	Uptime                *int64             `json:"uptime,omitempty"`
	LastSeen              *int64             `json:"last_seen,omitempty"`
	IsAccessPoint         *bool              `json:"is_access_point,omitempty"`
	ProductLine           string             `json:"product_line,omitempty"`
	NumSta                *int               `json:"num_sta,omitempty"`
	Satisfaction          *float64           `json:"satisfaction,omitempty"`
	ConnectionNetworkID   string             `json:"connection_network_id,omitempty"`
	ConnectionNetworkName string             `json:"connection_network_name,omitempty"`
	SystemStats           *DeviceSystemStats `json:"system-stats,omitempty"`
	PortTable             []PortTableEntry   `json:"port_table,omitempty"`
	RadioTable            []RadioTableEntry  `json:"radio_table,omitempty"`
	VapTable              []VapTableEntry    `json:"vap_table,omitempty"`
	Uplink                *DeviceUplink      `json:"uplink,omitempty"`
}

// DeviceSystemStats contains CPU and memory statistics for a device.
type DeviceSystemStats struct {
	CPU    *float64 `json:"cpu,omitempty"`
	Mem    *float64 `json:"mem,omitempty"`
	Uptime *int64   `json:"uptime,omitempty"`
}

// DeviceUplink contains information about a device's uplink connection.
type DeviceUplink struct {
	Type             string `json:"type,omitempty"`
	Speed            *int   `json:"speed,omitempty"`
	UplinkMAC        string `json:"uplink_mac,omitempty"`
	UplinkDeviceName string `json:"uplink_device_name,omitempty"`
	UplinkRemotePort *int   `json:"uplink_remote_port,omitempty"`
}

// PortTableEntry represents a switch port on a network device.
//
// Field value reference:
//   - OpMode: "switch", "mirror", "aggregate"
type PortTableEntry struct {
	PortIdx      *int    `json:"port_idx,omitempty"`
	Name         string  `json:"name,omitempty"`
	Media        string  `json:"media,omitempty"`
	Speed        *int    `json:"speed,omitempty"`
	FullDuplex   *bool   `json:"full_duplex,omitempty"`
	Up           *bool   `json:"up,omitempty"`
	Enable       *bool   `json:"enable,omitempty"`
	PoeEnable    *bool   `json:"poe_enable,omitempty"`
	PoeCaps      *int    `json:"poe_caps,omitempty"`
	RxBytes      *int64  `json:"rx_bytes,omitempty"`
	TxBytes      *int64  `json:"tx_bytes,omitempty"`
	Satisfaction *int    `json:"satisfaction,omitempty"`
	IsUplink     *bool   `json:"is_uplink,omitempty"`
	PortconfID   string  `json:"portconf_id,omitempty"`
	OpMode       string  `json:"op_mode,omitempty"`
}

// RadioTableEntry represents a wireless radio on an access point.
//
// Field value reference:
//   - Radio: "ng" (2.4GHz), "na" (5GHz), "6e" (6GHz)
type RadioTableEntry struct {
	Name        string `json:"name,omitempty"`
	Radio       string `json:"radio,omitempty"`
	Channel     *int   `json:"channel,omitempty"`
	HT          *int   `json:"ht,omitempty"`
	TxPowerMode string `json:"tx_power_mode,omitempty"`
	MaxTxpower  *int   `json:"max_txpower,omitempty"`
	MinTxpower  *int   `json:"min_txpower,omitempty"`
	Is11ac      *bool  `json:"is_11ac,omitempty"`
	Is11ax      *bool  `json:"is_11ax,omitempty"`
	Is11be      *bool  `json:"is_11be,omitempty"`
	HasDFS      *bool  `json:"has_dfs,omitempty"`
	HasHT160    *bool  `json:"has_ht160,omitempty"`
}

// VapTableEntry represents a virtual access point (SSID) on a radio.
type VapTableEntry struct {
	Essid        string `json:"essid,omitempty"`
	Bssid        string `json:"bssid,omitempty"`
	Radio        string `json:"radio,omitempty"`
	RadioName    string `json:"radio_name,omitempty"`
	Channel      *int   `json:"channel,omitempty"`
	BW           *int   `json:"bw,omitempty"`
	IsGuest      *bool  `json:"is_guest,omitempty"`
	NumSta       *int   `json:"num_sta,omitempty"`
	RxBytes      *int64 `json:"rx_bytes,omitempty"`
	TxBytes      *int64 `json:"tx_bytes,omitempty"`
	Satisfaction *int   `json:"satisfaction,omitempty"`
}

// TrafficRule represents a traffic management rule (v2 API).
//
// Field value reference:
//   - Action: "BLOCK", "ALLOW"
//   - MatchingTarget: "INTERNET", "IP", "DOMAIN", "REGION", "APP"
type TrafficRule struct {
	ID               string              `json:"_id,omitempty"`
	Name             string              `json:"name"`
	Enabled          *bool               `json:"enabled,omitempty"`
	Action           string              `json:"action,omitempty"`
	MatchingTarget   string              `json:"matching_target,omitempty"`
	TargetDevices    []TrafficRuleTarget `json:"target_devices,omitempty"`
	Schedule         *PolicySchedule     `json:"schedule,omitempty"`
	Description      string              `json:"description,omitempty"`
	AppCategoryIDs   []string            `json:"app_category_ids,omitempty"`
	AppIDs           []int               `json:"app_ids,omitempty"`
	Domains          []TrafficDomain     `json:"domains,omitempty"`
	IPAddresses      []string            `json:"ip_addresses,omitempty"`
	IPRanges         []string            `json:"ip_ranges,omitempty"`
	Regions          []string            `json:"regions,omitempty"`
	NetworkID        string              `json:"network_id,omitempty"`
	BandwidthLimit   *TrafficBandwidth   `json:"bandwidth_limit,omitempty"`
}

// TrafficRuleTarget specifies a device target for a traffic rule.
type TrafficRuleTarget struct {
	ClientMAC string `json:"client_mac,omitempty"`
	Type      string `json:"type,omitempty"`
	NetworkID string `json:"network_id,omitempty"`
}

// TrafficBandwidth specifies bandwidth limits for a traffic rule.
type TrafficBandwidth struct {
	DownloadLimitKbps *int  `json:"download_limit_kbps,omitempty"`
	UploadLimitKbps   *int  `json:"upload_limit_kbps,omitempty"`
	Enabled           *bool `json:"enabled,omitempty"`
}

// TrafficDomain represents a domain entry for traffic rules and routes.
type TrafficDomain struct {
	Domain      string `json:"domain"`
	Description string `json:"description,omitempty"`
	Ports       []int  `json:"ports,omitempty"`
}

// TrafficRoute represents a policy-based routing rule (v2 API).
//
// Field value reference:
//   - MatchingTarget: "INTERNET", "IP", "DOMAIN", "REGION", "APP"
//   - TargetDevice: "ALL_CLIENTS", "SPECIFIC_CLIENTS"
type TrafficRoute struct {
	ID             string              `json:"_id,omitempty"`
	Name           string              `json:"name"`
	Enabled        *bool               `json:"enabled,omitempty"`
	Description    string              `json:"description,omitempty"`
	MatchingTarget string              `json:"matching_target,omitempty"`
	TargetDevices  []TrafficRuleTarget `json:"target_devices,omitempty"`
	NetworkID      string              `json:"network_id,omitempty"`
	Domains        []TrafficDomain     `json:"domains,omitempty"`
	IPAddresses    []string            `json:"ip_addresses,omitempty"`
	IPRanges       []string            `json:"ip_ranges,omitempty"`
	Regions        []string            `json:"regions,omitempty"`
	Fallback       *bool               `json:"fallback,omitempty"`
	KillSwitch     *bool               `json:"kill_switch,omitempty"`
}

// NatRule represents a NAT rule (v2 API).
//
// Field value reference:
//   - Type: "MASQUERADE", "DNAT", "SNAT"
//   - Protocol: "all", "tcp", "udp", "tcp_udp"
type NatRule struct {
	ID             string `json:"_id,omitempty"`
	Enabled        *bool  `json:"enabled,omitempty"`
	Type           string `json:"type,omitempty"`
	Description    string `json:"description,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	SourceAddress  string `json:"source_address,omitempty"`
	SourcePort     string `json:"source_port,omitempty"`
	DestAddress    string `json:"dest_address,omitempty"`
	DestPort       string `json:"dest_port,omitempty"`
	TranslatedIP   string `json:"translated_ip,omitempty"`
	TranslatedPort string `json:"translated_port,omitempty"`
	Logging        *bool  `json:"logging,omitempty"`
}

// AclRule represents an access control list rule (v2 API, read-only).
type AclRule struct {
	ID          string `json:"_id,omitempty"`
	Name        string `json:"name,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
	Description string `json:"description,omitempty"`
}

// QosRule represents a quality of service rule (v2 API, read-only).
type QosRule struct {
	ID          string `json:"_id,omitempty"`
	Name        string `json:"name,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
	Description string `json:"description,omitempty"`
}

// ContentFiltering represents content filtering configuration (v2 API, read-only).
type ContentFiltering struct {
	Enabled           *bool    `json:"enabled,omitempty"`
	BlockedCategories []string `json:"blocked_categories,omitempty"`
	AllowedDomains    []string `json:"allowed_domains,omitempty"`
	BlockedDomains    []string `json:"blocked_domains,omitempty"`
}

// VpnConnection represents a VPN tunnel connection status (v2 API, read-only).
//
// Field value reference:
//   - Type: "site-to-site", "remote-user"
//   - Status: "connected", "disconnected"
type VpnConnection struct {
	ID              string `json:"_id,omitempty"`
	Name            string `json:"name,omitempty"`
	Type            string `json:"type,omitempty"`
	Status          string `json:"status,omitempty"`
	LocalIP         string `json:"local_ip,omitempty"`
	RemoteIP        string `json:"remote_ip,omitempty"`
	RemoteNetwork   string `json:"remote_network,omitempty"`
	BytesIn         *int64 `json:"bytes_in,omitempty"`
	BytesOut        *int64 `json:"bytes_out,omitempty"`
	ConnectedSince  *int64 `json:"connected_since,omitempty"`
}

// VpnConnectionList wraps the VPN connections response.
type VpnConnectionList struct {
	Connections []VpnConnection `json:"connections,omitempty"`
}

// WanSla represents a WAN SLA monitoring configuration (v2 API, read-only).
type WanSla struct {
	ID                  string   `json:"_id,omitempty"`
	Name                string   `json:"name,omitempty"`
	Enabled             *bool    `json:"enabled,omitempty"`
	Interface           string   `json:"interface,omitempty"`
	Target              string   `json:"target,omitempty"`
	ThresholdLatency    *int     `json:"threshold_latency,omitempty"`
	ThresholdPacketLoss *float64 `json:"threshold_packet_loss,omitempty"`
}
