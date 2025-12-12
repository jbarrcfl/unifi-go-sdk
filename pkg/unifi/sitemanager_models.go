package unifi

// UserData contains information about a UniFi user account.
type UserData struct {
	Email               string                 `json:"email"`
	FullName            string                 `json:"fullName"`
	Role                string                 `json:"role"`
	RoleID              string                 `json:"roleId"`
	Status              string                 `json:"status"`
	LocalID             string                 `json:"localId"`
	Apps                []string               `json:"apps"`
	Controllers         []string               `json:"controllers"`
	ConsoleGroupMembers []ConsoleGroupMember   `json:"consoleGroupMembers"`
	Features            UserFeatures           `json:"features"`
	Permissions         map[string][]string    `json:"permissions"`
}

// ConsoleGroupMember represents a console's membership in a group.
type ConsoleGroupMember struct {
	MAC            string         `json:"mac"`
	Role           string         `json:"role"`
	RoleAttributes RoleAttributes `json:"roleAttributes"`
	SysID          int            `json:"sysId"`
}

// RoleAttributes contains role-specific attributes for a console.
type RoleAttributes struct {
	Applications            map[string]ApplicationRole `json:"applications"`
	CandidateRoles          []string                   `json:"candidateRoles"`
	ConnectedState          string                     `json:"connectedState"`
	ConnectedStateLastChanged string                   `json:"connectedStateLastChanged"`
}

// ApplicationRole describes a user's role for a specific application.
type ApplicationRole struct {
	Owned     bool `json:"owned"`
	Required  bool `json:"required"`
	Supported bool `json:"supported"`
}

// UserFeatures describes the features available to a user.
type UserFeatures struct {
	DeviceGroups       bool              `json:"deviceGroups"`
	Floorplan          FloorplanFeature  `json:"floorplan"`
	ManageApplications bool              `json:"manageApplications"`
	Notifications      bool              `json:"notifications"`
	Pion               bool              `json:"pion"`
	WebRTC             WebRTCFeature     `json:"webrtc"`
}

// FloorplanFeature describes floorplan capabilities for a user.
type FloorplanFeature struct {
	CanEdit bool `json:"canEdit"`
	CanView bool `json:"canView"`
}

// WebRTCFeature describes WebRTC capabilities for a user.
type WebRTCFeature struct {
	ICERestart   bool `json:"iceRestart"`
	MediaStreams bool `json:"mediaStreams"`
	TwoWayAudio  bool `json:"twoWayAudio"`
}

// Hardware contains hardware information for a UniFi device.
type Hardware struct {
	MAC             string `json:"mac"`
	Name            string `json:"name"`
	Shortname       string `json:"shortname"`
	FirmwareVersion string `json:"firmwareVersion"`
	UUID            string `json:"uuid"`
	Serialno        string `json:"serialno"`
}

// Location represents a geographical location for a UniFi host.
type Location struct {
	Lat    float64 `json:"lat"`
	Long   float64 `json:"long"`
	Radius float64 `json:"radius"`
	Text   string  `json:"text"`
}

// WAN represents a WAN interface on a UniFi host.
type WAN struct {
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	MAC       string `json:"mac"`
	Plugged   bool   `json:"plugged"`
	Port      int    `json:"port"`
	Type      string `json:"type"`
}

// Controller represents a UniFi controller application (e.g., Network, Protect).
type Controller struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	Version         string `json:"version"`
	Port            int    `json:"port"`
	IsInstalled     bool   `json:"isInstalled"`
	IsRunning       bool   `json:"isRunning"`
	IsConfigured    bool   `json:"isConfigured"`
	State           string `json:"state"`
	Status          string `json:"status"`
	StatusMessage   string `json:"statusMessage"`
	ReleaseChannel  string `json:"releaseChannel"`
	InstallState    string `json:"installState"`
	Updatable       bool   `json:"updatable"`
	UpdateAvailable string `json:"updateAvailable"`
}

// AutoUpdate contains auto-update configuration for a UniFi host.
type AutoUpdate struct {
	IncludeApplications bool           `json:"includeApplications"`
	Schedule            UpdateSchedule `json:"schedule"`
}

// UpdateSchedule defines when automatic updates should occur.
type UpdateSchedule struct {
	Day       int    `json:"day"`
	Frequency string `json:"frequency"`
	Hour      int    `json:"hour"`
}

// FirmwareUpdate contains firmware update information for a UniFi host.
type FirmwareUpdate struct {
	LatestAvailableVersion string `json:"latestAvailableVersion"`
}

// App represents an application installed on a UniFi host.
type App struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Version          string `json:"version"`
	Port             int    `json:"port"`
	IsInstalled      bool   `json:"isInstalled"`
	IsRunning        bool   `json:"isRunning"`
	IsConfigured     bool   `json:"isConfigured"`
	ControllerStatus string `json:"controllerStatus"`
}

// UIDB contains UI database information for device icons and images.
type UIDB struct {
	GUID   *string           `json:"guid"`
	IconID string            `json:"iconId"`
	ID     string            `json:"id"`
	Images map[string]string `json:"images"`
}

// Device represents a UniFi device (AP, switch, gateway, etc.).
type Device struct {
	ID             string  `json:"id"`
	MAC            string  `json:"mac"`
	Name           string  `json:"name"`
	Model          string  `json:"model"`
	Shortname      string  `json:"shortname"`
	IP             string  `json:"ip"`
	ProductLine    string  `json:"productLine"`
	Status         string  `json:"status"`
	Version        string  `json:"version"`
	FirmwareStatus string  `json:"firmwareStatus"`
	UpdateAvailable *string `json:"updateAvailable"`
	IsConsole      bool    `json:"isConsole"`
	IsManaged      bool    `json:"isManaged"`
	StartupTime    *string `json:"startupTime"`
	AdoptionTime   *string `json:"adoptionTime"`
	Note           *string `json:"note"`
	UIDB           UIDB    `json:"uidb"`
}

// HostDevices contains devices associated with a specific host.
type HostDevices struct {
	HostID    string   `json:"hostId"`
	HostName  string   `json:"hostName"`
	Devices   []Device `json:"devices"`
	UpdatedAt string   `json:"updatedAt"`
}

// Features describes capabilities available on a UniFi host.
type Features struct {
	AlarmManager                 bool   `json:"alarmManager"`
	APIIntegration               bool   `json:"apiIntegration"`
	CaptiveProxy                 bool   `json:"captiveProxy"`
	CloudBackup                  bool   `json:"cloudBackup"`
	CustomSmtpServer             bool   `json:"customSmtpServer"`
	DirectRemoteConnection       bool   `json:"directRemoteConnection"`
	HasBezel                     bool   `json:"hasBezel"`
	HasGateway                   bool   `json:"hasGateway"`
	HasLCM                       bool   `json:"hasLCM"`
	HasLED                       bool   `json:"hasLED"`
	IsAutomaticFailoverAvailable bool   `json:"isAutomaticFailoverAvailable"`
	MFA                          bool   `json:"mfa"`
	MspBridgeModesSupported      bool   `json:"mspBridgeModesSupported"`
	MultiplePoolsSupport         bool   `json:"multiplePoolsSupport"`
	NetInAppBackupSupport        bool   `json:"netInAppBackupSupport"`
	Notifications                bool   `json:"notifications"`
	SharedTokens                 bool   `json:"sharedTokens"`
	SnmpConfig                   bool   `json:"snmpConfig"`
	SupportForm                  bool   `json:"supportForm"`
	Syslog                       bool   `json:"syslog"`
	Teleport                     bool   `json:"teleport"`
	TeleportState                string `json:"teleportState"`
	UIDService                   bool   `json:"uidService"`
	UpsPairing                   bool   `json:"upsPairing"`
}

// ReportedState contains the current state reported by a UniFi host.
type ReportedState struct {
	Name                       string         `json:"name"`
	Hostname                   string         `json:"hostname"`
	Version                    string         `json:"version"`
	State                      string         `json:"state"`
	DeviceState                string         `json:"deviceState"`
	DeviceStateLastChanged     int64          `json:"deviceStateLastChanged"`
	ReleaseChannel             string         `json:"releaseChannel"`
	Timezone                   string         `json:"timezone"`
	MAC                        string         `json:"mac"`
	IP                         string         `json:"ip"`
	IPAddrs                    []string       `json:"ipAddrs"`
	Hardware                   Hardware       `json:"hardware"`
	Location                   Location       `json:"location"`
	WANs                       []WAN          `json:"wans"`
	Controllers                []Controller   `json:"controllers"`
	Apps                       []App          `json:"apps"`
	AutoUpdate                 AutoUpdate     `json:"autoUpdate"`
	FirmwareUpdate             FirmwareUpdate `json:"firmwareUpdate"`
	UIDB                       UIDB           `json:"uidb"`
	AnonID                     string         `json:"anonid"`
	ControllerUUID             string         `json:"controller_uuid"`
	Country                    int            `json:"country"`
	DeviceErrorCode            string         `json:"deviceErrorCode"`
	DirectConnectDomain        string         `json:"directConnectDomain"`
	HostType                   int            `json:"host_type"`
	IsStacked                  bool           `json:"isStacked"`
	MgmtPort                   int            `json:"mgmt_port"`
	AvailableChannels          []string       `json:"availableChannels"`
	ConsolesOnSameLocalNetwork []string       `json:"consolesOnSameLocalNetwork"`
	UnadoptedUnifiOSDevices    []string       `json:"unadoptedUnifiOSDevices"`
	Features                   Features       `json:"features"`
	// Network Server specific fields
	DeviceID            string  `json:"deviceId"`
	FirmwareVersion     *string `json:"firmware_version"`
	HardwareID          string  `json:"hardware_id"`
	InformPort          int     `json:"inform_port"`
	OverrideInformHost  bool    `json:"override_inform_host"`
}

// Host represents a UniFi console or controller host (e.g., UDM, Cloud Key).
type Host struct {
	ID                        string         `json:"id"`
	HardwareID                string         `json:"hardwareId"`
	Type                      string         `json:"type"`
	IPAddress                 string         `json:"ipAddress"`
	Owner                     bool           `json:"owner"`
	IsBlocked                 bool           `json:"isBlocked"`
	RegistrationTime          string         `json:"registrationTime"`
	LastConnectionStateChange string         `json:"lastConnectionStateChange"`
	LatestBackupTime          string         `json:"latestBackupTime"`
	UserData                  *UserData      `json:"userData"`
	ReportedState             *ReportedState `json:"reportedState"`
}

// ListHostsResponse contains the response from listing hosts.
type ListHostsResponse struct {
	Hosts     []Host
	TraceID   string
	NextToken string
}

// ListHostsOptions specifies options for listing hosts.
type ListHostsOptions struct {
	PageSize  int
	NextToken string
}

// GetHostResponse contains the response from getting a single host.
type GetHostResponse struct {
	Host    *Host
	TraceID string
}

// Site represents a UniFi Network site.
type Site struct {
	SiteID     string         `json:"siteId"`
	HostID     string         `json:"hostId"`
	Meta       SiteMeta       `json:"meta"`
	Statistics SiteStatistics `json:"statistics"`
	Permission string         `json:"permission"`
	IsOwner    bool           `json:"isOwner"`
}

// SiteMeta contains metadata about a UniFi site.
type SiteMeta struct {
	Name       string `json:"name"`
	Desc       string `json:"desc"`
	Timezone   string `json:"timezone"`
	GatewayMAC string `json:"gatewayMac"`
}

// SiteStatistics contains statistics for a UniFi site.
type SiteStatistics struct {
	Counts         SiteCounts       `json:"counts"`
	Gateway        SiteGateway      `json:"gateway"`
	ISPInfo        SiteISPInfo      `json:"ispInfo"`
	Percentages    SitePercentages  `json:"percentages"`
	InternetIssues []any            `json:"internetIssues"`
}

// SiteCounts contains device and client counts for a site.
type SiteCounts struct {
	CriticalNotification int `json:"criticalNotification"`
	GatewayDevice        int `json:"gatewayDevice"`
	GuestClient          int `json:"guestClient"`
	LANConfiguration     int `json:"lanConfiguration"`
	OfflineDevice        int `json:"offlineDevice"`
	OfflineGatewayDevice int `json:"offlineGatewayDevice"`
	OfflineWifiDevice    int `json:"offlineWifiDevice"`
	OfflineWiredDevice   int `json:"offlineWiredDevice"`
	PendingUpdateDevice  int `json:"pendingUpdateDevice"`
	TotalDevice          int `json:"totalDevice"`
	WANConfiguration     int `json:"wanConfiguration"`
	WifiClient           int `json:"wifiClient"`
	WifiConfiguration    int `json:"wifiConfiguration"`
	WifiDevice           int `json:"wifiDevice"`
	WiredClient          int `json:"wiredClient"`
	WiredDevice          int `json:"wiredDevice"`
}

// SiteGateway contains gateway information for a site.
type SiteGateway struct {
	HardwareID      string       `json:"hardwareId"`
	InspectionState string       `json:"inspectionState"`
	IPSMode         string       `json:"ipsMode"`
	IPSSignature    IPSSignature `json:"ipsSignature"`
	Shortname       string       `json:"shortname"`
}

// IPSSignature contains IPS signature information.
type IPSSignature struct {
	RulesCount int    `json:"rulesCount"`
	Type       string `json:"type"`
}

// SiteISPInfo contains ISP information for a site.
type SiteISPInfo struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
}

// SitePercentages contains uptime percentages for a site.
type SitePercentages struct {
	WANUptime float64 `json:"wanUptime"`
}

// ListSitesOptions specifies options for listing sites.
type ListSitesOptions struct {
	PageSize  int
	NextToken string
}

// ListSitesResponse contains the response from listing sites.
type ListSitesResponse struct {
	Sites     []Site
	TraceID   string
	NextToken string
}

// ListDevicesOptions specifies options for listing devices.
type ListDevicesOptions struct {
	HostIDs   []string
	PageSize  int
	NextToken string
}

// ListDevicesResponse contains the response from listing devices.
type ListDevicesResponse struct {
	HostDevices []HostDevices
	TraceID     string
	NextToken   string
}
