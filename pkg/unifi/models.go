package unifi

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

type ConsoleGroupMember struct {
	MAC            string         `json:"mac"`
	Role           string         `json:"role"`
	RoleAttributes RoleAttributes `json:"roleAttributes"`
	SysID          int            `json:"sysId"`
}

type RoleAttributes struct {
	Applications            map[string]ApplicationRole `json:"applications"`
	CandidateRoles          []string                   `json:"candidateRoles"`
	ConnectedState          string                     `json:"connectedState"`
	ConnectedStateLastChanged string                   `json:"connectedStateLastChanged"`
}

type ApplicationRole struct {
	Owned     bool `json:"owned"`
	Required  bool `json:"required"`
	Supported bool `json:"supported"`
}

type UserFeatures struct {
	DeviceGroups       bool              `json:"deviceGroups"`
	Floorplan          FloorplanFeature  `json:"floorplan"`
	ManageApplications bool              `json:"manageApplications"`
	Notifications      bool              `json:"notifications"`
	Pion               bool              `json:"pion"`
	WebRTC             WebRTCFeature     `json:"webrtc"`
}

type FloorplanFeature struct {
	CanEdit bool `json:"canEdit"`
	CanView bool `json:"canView"`
}

type WebRTCFeature struct {
	ICERestart   bool `json:"iceRestart"`
	MediaStreams bool `json:"mediaStreams"`
	TwoWayAudio  bool `json:"twoWayAudio"`
}

type Hardware struct {
	MAC             string `json:"mac"`
	Name            string `json:"name"`
	Shortname       string `json:"shortname"`
	FirmwareVersion string `json:"firmwareVersion"`
	UUID            string `json:"uuid"`
	Serialno        string `json:"serialno"`
}

type Location struct {
	Lat    float64 `json:"lat"`
	Long   float64 `json:"long"`
	Radius float64 `json:"radius"`
	Text   string  `json:"text"`
}

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

type AutoUpdate struct {
	IncludeApplications bool           `json:"includeApplications"`
	Schedule            UpdateSchedule `json:"schedule"`
}

type UpdateSchedule struct {
	Day       int    `json:"day"`
	Frequency string `json:"frequency"`
	Hour      int    `json:"hour"`
}

type FirmwareUpdate struct {
	LatestAvailableVersion string `json:"latestAvailableVersion"`
}

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

type UIDB struct {
	GUID   string            `json:"guid"`
	ID     string            `json:"id"`
	Images map[string]string `json:"images"`
}

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

type APIResponse struct {
	HTTPStatusCode int    `json:"httpStatusCode"`
	TraceID        string `json:"traceId"`
}

type ListHostsResponse struct {
	Hosts     []Host
	TraceID   string
	NextToken string
}

type ListHostsOptions struct {
	PageSize  int
	NextToken string
}

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

type SiteMeta struct {
	Name       string `json:"name"`
	Desc       string `json:"desc"`
	Timezone   string `json:"timezone"`
	GatewayMAC string `json:"gatewayMac"`
}

type SiteStatistics struct {
	Counts         SiteCounts       `json:"counts"`
	Gateway        SiteGateway      `json:"gateway"`
	ISPInfo        SiteISPInfo      `json:"ispInfo"`
	Percentages    SitePercentages  `json:"percentages"`
	InternetIssues []any            `json:"internetIssues"`
}

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

type SiteGateway struct {
	HardwareID      string       `json:"hardwareId"`
	InspectionState string       `json:"inspectionState"`
	IPSMode         string       `json:"ipsMode"`
	IPSSignature    IPSSignature `json:"ipsSignature"`
	Shortname       string       `json:"shortname"`
}

type IPSSignature struct {
	RulesCount int    `json:"rulesCount"`
	Type       string `json:"type"`
}

type SiteISPInfo struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
}

type SitePercentages struct {
	WANUptime float64 `json:"wanUptime"`
}

type ListSitesOptions struct {
	PageSize  int
	NextToken string
}

type ListSitesResponse struct {
	Sites     []Site
	TraceID   string
	NextToken string
}
