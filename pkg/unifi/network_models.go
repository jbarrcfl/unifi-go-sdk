package unifi

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
	WANDHCPOptions              []any    `json:"wan_dhcp_options,omitempty"`
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
	WANProviderCapabilities     any      `json:"wan_provider_capabilities,omitempty"`
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
	PrivatePresharedKeys     []any    `json:"private_preshared_keys,omitempty"`
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
	ScheduleWithDuration     []any    `json:"schedule_with_duration,omitempty"`
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
	QosProfile                  any      `json:"qos_profile,omitempty"`
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
