package nessie

type Acl struct {
	Permissions int         `json:"permissions"`
	Owner       interface{} `json:"owner"`
	DisplayName interface{} `json:"display_name"`
	Name        interface{} `json:"name"`
	ID          interface{} `json:"id"`
	Type        string      `json:"type"`
}

type LicenseInfo struct {
	Trimmed interface{} `json:"trimmed"`
	Limit   int64       `json:"limit"`
}

type ScanInfo struct {
	ACLs               []Acl       `json:"acls"`
	EditAllowed        bool        `json:"edit_allowed"`
	AltTargetsUsed     bool        `json:"alt_targets_used"`
	Status             string      `json:"status"`
	ScannerStart       int         `json:"scanner_start"`
	Policy             string      `json:"policy"`
	ScanGroup          interface{} `json:"scan_group"`
	PciCanUpload       bool        `json:"pci-can-upload"`
	ScanStart          int         `json:"scan_start"`
	HasAuditTrail      bool        `json:"hasaudittrail"`
	UserPermissions    int         `json:"user_permissions"`
	FolderID           int         `json:"folder_id"`
	NodeName           interface{} `json:"node_name"`
	NoTarget           bool        `json:"no_target"`
	NodeHost           interface{} `json:"node_host"`
	NodeID             interface{} `json:"node_id"`
	Targets            string      `json:"targets"`
	Control            bool        `json:"control"`
	Timestamp          int         `json:"timestamp"`
	Offline            bool        `json:"offline"`
	ObjectID           int         `json:"object_id"`
	ScannerName        string      `json:"scanner_name"`
	UUID               string      `json:"uuid"`
	HasKb              bool        `json:"haskb"`
	ScannerEnd         int         `json:"scanner_end"`
	PolicyTemplateUUID string      `json:"policy_template_uuid"`
	HostCount          int         `json:"hostcount"`
	ScanEnd            int         `json:"scan_end"`
	ScanType           string      `json:"scan_type"`
	LicenseInfo        LicenseInfo `json:"license_info"`
	Migrated           int         `json:"migrated"`
	Name               string      `json:"name"`
}

type HostsDetailInfo struct {
	Ports           []int       `json:"ports"`
	OperatingSystem interface{} `json:"operating_system"`
	HostFqdn        interface{} `json:"host_fqdn"`
	Hostname        string      `json:"hostname"`
	HostIP          string      `json:"host_ip"`
	ID              int         `json:"id"`
}

type Control struct {
	ReadableRegex string   `json:"readable_regex"`
	Prefix        string   `json:"prefix"`
	Type          string   `json:"type"`
	Regex         string   `json:"regex"`
	List          []string `json:"list"`
	OOptions      []string `json:"options"`
}

type Filter struct {
	Operators    []string `json:"operators"`
	Control      Control  `json:"control,omitempty"`
	Name         string   `json:"name"`
	ReadableName string   `json:"readable_name"`
}

type History struct {
	AltTargetsUsed       bool        `json:"alt_targets_used"`
	Scheduler            int         `json:"scheduler"`
	NodeName             interface{} `json:"node_name"`
	NodeHost             interface{} `json:"node_host"`
	ScanGroup            interface{} `json:"scan_group"`
	NodeID               interface{} `json:"node_id"`
	ScheduleType         string      `json:"schedule_type"`
	Status               string      `json:"status"`
	Type                 string      `json:"type"`
	UUID                 string      `json:"uuid"`
	LastModificationDate int         `json:"last_modification_date"`
	CreationDate         int         `json:"creation_date"`
	OwnerID              int         `json:"owner_id"`
	HistoryID            int         `json:"history_id"`
}

type Host struct {
	TotalChecksConsidered int `json:"totalchecksconsidered"`
	NumChecksConsidered   int `json:"numchecksconsidered"`
	ScanProgressTotal     int `json:"scanprogresstotal"`
	ScanProgressCurrent   int `json:"scanprogresscurrent"`
	HostIndex             int `json:"host_index"`
	Score                 int `json:"score"`
	SeverityCount         struct {
		Item []struct {
			Count         int `json:"count"`
			SeverityLevel int `json:"severitylevel"`
		} `json:"item"`
	} `json:"severitycount"`
	Progress        string `json:"progress"`
	OfflineCritical int    `json:"offline_critical"`
	OfflineHigh     int    `json:"offline_high"`
	OfflineMedium   int    `json:"offline_medium"`
	OfflineLow      int    `json:"offline_low"`
	OfflineInfo     int    `json:"offline_info"`
	Critical        int    `json:"critical"`
	High            int    `json:"high"`
	Medium          int    `json:"medium"`
	Low             int    `json:"low"`
	Info            int    `json:"info"`
	Severity        int    `json:"severity"`
	HostID          int    `json:"host_id"`
	Hostname        string `json:"hostname"`
}

type Remediation struct {
	Remediation       interface{} `json:"remediations"`
	NumHosts          int         `json:"num_hosts"`
	NumCVEs           int         `json:"num_cves"`
	NumImpactedHosts  int         `json:"num_impacted_hosts"`
	NumRemediatedCVEs int         `json:"num_remediated_cves"`
	Value             string      `json:"value"`
	NumVulns          string      `json:"vulns"`
}

type Vulnerability struct {
	Count         int         `json:"count"`
	VulnIndex     interface{} `json:"vuln_index"`
	PluginName    string      `json:"plugin_name"`
	Severity      int         `json:"severity"`
	PluginID      int         `json:"plugin_id"`
	SeverityIndex int         `json:"severity_index"`
	Cpe           interface{} `json:"cpe"`
	Offline       bool        `json:"offline"`
	PluginFamily  string      `json:"plugin_family"`
	Snoozed       int         `json:"snoozed"`
	HostID        int         `json:"host_id"`
}

type Folder struct {
	UnreadCount int    `json:"unread_count"`
	Custom      int    `json:"custom"`
	DefaultTag  int    `json:"default_tag"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	ID          int    `json:"id"`
}

type Installer struct {
}

type Feature struct {
	Policies     bool `json:"policies"`
	Report       bool `json:"report"`
	RemoteLink   bool `json:"remote_link"`
	Cluster      bool `json:"cluster"`
	Users        bool `json:"users"`
	PluginRules  bool `json:"plugin_rules"`
	API          bool `json:"api"`
	ScanAPI      bool `json:"scan_api"`
	Folders      bool `json:"folders"`
	LocalScanner bool `json:"local_scanner"`
	Logs         bool `json:"logs"`
	SMTP         bool `json:"smtp"`
}

type Update struct {
	Href       interface{} `json:"href"`
	NewVersion int         `json:"new_version"`
	Restart    int         `json:"restart"`
}

type RestartPending struct {
	Reason interface{} `json:"reason"`
	Type   interface{} `json:"type"`
}

type License struct {
	Features       Feature `json:"features"`
	Type           string  `json:"type"`
	ExpirationDate int     `json:"expiration_date"`
	Ips            int64   `json:"ips"`
	Restricted     bool    `json:"restricted"`
	Agents         int     `json:"agents"`
	Mode           int     `json:"mode"`
	Scanners       int     `json:"scanners"`
	ScannersUsed   int     `json:"scanners_used"`
	AgentsUsed     int     `json:"agents_used"`
	Name           string  `json:"name"`
}

type TenableLink struct {
	SelectedIcon string `json:"selected_icon"`
	Title        string `json:"title"`
	Icon         string `json:"icon"`
	Link         string `json:"link"`
}

type Capability struct {
	ScanVulnerabilityGroups      bool `json:"scan_vulnerability_groups"`
	ReportEmailConfig            bool `json:"report_email_config"`
	ScanVulnerabilityGroupsMixed bool `json:"scan_vulnerability_groups_mixed"`
}

type DetailColumn struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type SectionItem struct {
	Name          string         `json:"name"`
	Key           string         `json:"key"`
	IsDefault     bool           `json:"isDefault"`
	DetailColumns []DetailColumn `json:"detailColumns,omitempty"`
}

type ReportOption struct {
	CsvColumns            []SectionItem `json:"csvColumns"`
	VulnerabilitySections []SectionItem `json:"vulnerabilitySections"`
	HostSections          []SectionItem `json:"hostSections"`
	FormattingOptions     []SectionItem `json:"formattingOptions"`
}

type Export struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Chapter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Format struct {
	Name     string    `json:"name"`
	Chapters []Chapter `json:"chapters,omitempty"`
	Value    string    `json:"value"`
}

type ExportFormat struct {
	Custom []interface{} `json:"custom"`
	Export []Export      `json:"export"`
	Format []Format      `json:"format"`
}

type HostInfo struct {
	HostStart       string `json:"host_start"`
	HostEnd         string `json:"host_end"`
	NetbiosName     string `json:"netbios-name"`
	OperatingSystem string `json:"operating-system"`
	HostIP          string `json:"host-ip"`
}

type PluginOutput struct {
	Ports         map[string]interface{} `json:"ports,omitempty"`
	HasAttachment interface{}            `json:"has_attachment"`
	Hosts         interface{}            `json:"hosts"`
	Severity      int                    `json:"severity"`
	PluginOutput  string                 `json:"plugin_output"`
}

type RiskInformation struct {
	RiskFactor string `json:"risk_factor"`
}

type PluginInformation struct {
	PluginVersion          string `json:"plugin_version"`
	PluginID               int    `json:"plugin_id"`
	PluginType             string `json:"plugin_type"`
	PluginPublicationDate  string `json:"plugin_publication_date"`
	PluginFamily           string `json:"plugin_family"`
	PluginModificationDate string `json:"plugin_modification_date"`
}

type PluginAttribute struct {
	ScriptCopyright   string            `json:"script_copyright"`
	Synopsis          string            `json:"synopsis"`
	Description       string            `json:"description"`
	RiskInformation   RiskInformation   `json:"risk_information"`
	PluginName        string            `json:"plugin_name"`
	FName             string            `json:"fname"`
	Dependency        string            `json:"dependency"`
	PluginInformation PluginInformation `json:"plugin_information"`
	Solution          string            `json:"solution"`
}

type PluginDescription struct {
	Severity         int             `json:"severity"`
	PluginName       string          `json:"pluginname"`
	PluginAttributes PluginAttribute `json:"pluginattributes"`
	PluginFamily     string          `json:"pluginfamily"`
	PluginID         string          `json:"pluginid"`
}

type Policy struct {
	IsScap               int         `json:"is_scap"`
	HasCredentials       int         `json:"has_credentials"`
	NoTarget             string      `json:"no_target"`
	PluginFilters        interface{} `json:"plugin_filters"`
	TemplateUUID         string      `json:"template_uuid"`
	Description          string      `json:"description"`
	Name                 string      `json:"name"`
	Owner                string      `json:"owner"`
	Visibility           string      `json:"visibility"`
	Shared               int         `json:"shared"`
	UserPermissions      int         `json:"user_permissions"`
	LastModificationDate int         `json:"last_modification_date"`
	CreationDate         int         `json:"creation_date"`
	OwnerID              int         `json:"owner_id"`
	ID                   int         `json:"id"`
}

type PolicyTemplate struct {
	Unsupported      bool   `json:"unsupported"`
	LicenseFulfilled int    `json:"license_fulfilled"`
	Desc             string `json:"desc"`
	Order            int    `json:"order"`
	SubscriptionOnly bool   `json:"subscription_only"`
	Title            string `json:"title"`
	IsAgent          bool   `json:"is_agent"`
	UUID             string `json:"uuid"`
	DynamicScan      bool   `json:"dynamic_scan"`
	Icon             string `json:"icon"`
	ManagerOnly      bool   `json:"manager_only"`
	Category         string `json:"category"`
	Name             string `json:"name"`
	MoreInfo         string `json:"more_info,omitempty"`
}

type Input struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Hint          string   `json:"hint,omitempty"`
	Required      bool     `json:"required"`
	Default       string   `json:"default,omitempty"`
	Label         string   `json:"label"`
	Options       []string `json:"options,omitempty"`
	OptionsLabels []string `json:"optionsLabels,omitempty"`
}

type Type struct {
	Inputs    []Input       `json:"inputs"`
	Max       int           `json:"max"`
	Name      string        `json:"name"`
	Instances []interface{} `json:"instances"`
	Settings  interface{}   `json:"settings"`
}

type CredentialItem struct {
	Types         []Type `json:"types"`
	Name          string `json:"name"`
	DefaultExpand int    `json:"default_expand"`
}

type Credentials struct {
	Data []CredentialItem `json:"data"`
}

type FamilyInfo struct {
	Count  int    `json:"count"`
	ID     int    `json:"id"`
	Status string `json:"status"`
}

type Plugin struct {
	ID       int64                 `json:"id"`
	Name     string                `json:"name"`
	ReadOnly bool                  `json:"readOnly"`
	Families map[string]FamilyInfo `json:"families"`
}

type FilterAttribute struct {
	Operators    []string `json:"operators"`
	Control      Control  `json:"control,omitempty"`
	Name         string   `json:"name"`
	ReadableName string   `json:"readable_name"`
}

type GroupItem struct {
	Title string `json:"title"`
	Name  string `json:"name"`
	ACLs  []Acl  `json:"acls"`
}

type Mode struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Default string `json:"default"`
	Options []struct {
		Desc string `json:"desc"`
		Name string `json:"name"`
	} `json:"options"`
}

type Section struct {
	Inputs []Input `json:"inputs"`
	Title  string  `json:"title"`
	Name   string  `json:"name"`
}

type Setting struct {
	Inputs   []Input   `json:"inputs"`
	Modes    Mode      `json:"modes"`
	Title    string    `json:"title"`
	Name     string    `json:"name"`
	Groups   []Setting `json:"groups"`
	Sections []Section `json:"sections"`
}

// basic, assessment, advanced, discovery, report
type Settings map[string]Setting

type PolicyDetail struct {
	Credentials      Credentials       `json:"credentials"`
	UserPermissions  int               `json:"user_permissions"`
	Owner            string            `json:"owner"`
	Title            string            `json:"title"`
	IsAgent          bool              `json:"is_agent"`
	UUID             string            `json:"uuid"`
	DynamicScan      bool              `json:"dynamic_scan"`
	Plugins          Plugin            `json:"plugins"`
	FilterAttributes []FilterAttribute `json:"filter_attributes"`
	Migrated         interface{}       `json:"migrated"`
	Settings         Settings          `json:"settings"`
	Name             string            `json:"name"`
}

type Scanner struct {
	Challenge            string      `json:"challenge"`
	License              License     `json:"license"`
	NumScans             interface{} `json:"num_scans"`
	AwsAvailabilityZone  interface{} `json:"aws_availability_zone"`
	AwsUpdateInterval    interface{} `json:"aws_update_interval"`
	NeedsRestart         interface{} `json:"needs_restart"`
	LastConnect          interface{} `json:"last_connect"`
	Loadavg              interface{} `json:"loadavg"`
	NumTCPSessions       interface{} `json:"num_tcp_sessions"`
	NumHosts             interface{} `json:"num_hosts"`
	NumSessions          interface{} `json:"num_sessions"`
	RegistrationCode     interface{} `json:"registration_code"`
	ExpirationTime       interface{} `json:"expiration_time"`
	Expiration           int         `json:"expiration"`
	LoadedPluginSet      interface{} `json:"loaded_plugin_set"`
	Platform             string      `json:"platform"`
	UIBuild              string      `json:"ui_build"`
	UIVersion            string      `json:"ui_version"`
	EngineBuild          string      `json:"engine_build"`
	EngineVersion        string      `json:"engine_version"`
	Status               string      `json:"status"`
	ScanCount            int         `json:"scan_count"`
	Linked               int         `json:"linked"`
	Key                  string      `json:"key"`
	Type                 string      `json:"type"`
	Name                 string      `json:"name"`
	UUID                 string      `json:"uuid"`
	Token                interface{} `json:"token"`
	OwnerName            string      `json:"owner_name"`
	Owner                string      `json:"owner"`
	Shared               int         `json:"shared"`
	UserPermissions      int         `json:"user_permissions"`
	Timestamp            int         `json:"timestamp"`
	LastModificationDate int         `json:"last_modification_date"`
	CreationDate         int         `json:"creation_date"`
	OwnerID              int         `json:"owner_id"`
	ID                   int         `json:"id"`
}

type User struct {
	LastLogin   int     `json:"lastlogin"`
	Permissions int     `json:"permissions"`
	Type        string  `json:"type"`
	Name        string  `json:"name"`
	Email       *string `json:"email"`
	Username    string  `json:"username"`
	ID          int     `json:"id"`
}

type ScanLaunchResponse struct {
	ScanUUID string `json:"scan_uuid"`
}

// Editor resources.

// Template is used to create scans or policies with predefined parameters.
type Template struct {
	// The uuid for the template.
	UUID string `json:"uuid"`
	// The short name of the template.
	Name string `json:"name"`
	// The long name of the template.
	Title string `json:"title"`
	// The description of the template.
	Desc string `json:"description"`
	// If true, template is only available on the cloud.
	CloudOnly bool `json:"cloud_only"`
	// If true, the template is only available for subscribers.
	SubscriptionOnly bool `json:"subscription_only"`
	// If true, the template is for agent scans.
	IsAgent bool `json:"is_agent"`
	// An external URL to link the template to.
	MoreInfo string `json:"more_info"`
}

type TemplateFormInput struct {
	ID      string   `json:"id"`
	Type    string   `json:"type"`
	Label   string   `json:"label"`
	Default string   `json:"default"`
	Options []string `json:"options"`
}

type TemplateDisplayGroup struct {
	Name     string   `json:"name"`
	Title    string   `json:"title"`
	Inputs   []string `json:"inputs"`
	Sections []string `json:"sections"`
}

type TemplateSection struct {
	Name   string   `json:"name"`
	Title  string   `json:"title"`
	Inputs []string `json:"inputs"`
}

type TemplateMode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type TemplatePluginFamily struct {
	ID     int64  `json:"id"`
	Count  int64  `json:"count"`
	Status string `json:"status"`
}

// Groups resources.

type Group struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Permissions int64  `json:"permissions"`
	UserCount   int64  `json:"user_count"`
}

// Permissions resources.

type Permission struct {
	Owner       int64  `json:"owner"`
	Type        string `json:"type"`
	Permissions int64  `json:"permissions"`
	ID          int64  `json:"id"`
	Name        string `json:"name"`
}

// Plugins resources.

type PluginAttr struct {
	Name string `json:"attribute_name"`
	Val  string `json:"attribute_value"`
}

type PluginFamily struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type PluginFamilies struct {
	Families []PluginFamily `json:"families"`
}

// Plugin-rules resources.

type Rule struct {
	ID       int64  `json:"id"`
	PluginID int64  `json:"plugin_id"`
	Date     string `json:"date"`
	Host     string `json:"host"`
	Type     string `json:"type"`
	Owner    string `json:"owner"`
	OwnerID  int64  `json:"owner_id"`
}

// Scan resource.
type Scan struct {
	ID                        int64       `json:"id"`
	UUID                      string      `json:"uuid"`
	Name                      string      `json:"name"`
	Owner                     string      `json:"owner"`
	Shared                    int         `json:"shared"`
	UserPermissions           int64       `json:"user_permissions"`
	CreationDate              int64       `json:"creation_date"`
	LastModificationDate      int64       `json:"last_modification_date"`
	StartTime                 string      `json:"starttime"`
	TimeZone                  string      `json:"timezone"`
	RRules                    string      `json:"rrules"`
	ContainerID               int         `json:"container_id"`
	Description               string      `json:"description"`
	PolicyID                  int         `json:"policy_id"`
	ScannerID                 int         `json:"scanner_id"`
	Emails                    string      `json:"emails"`
	AttachReport              int         `json:"attach_report"`
	AttachedReportMaximumSize int         `json:"attached_report_maximum_size"`
	AttachedReportType        interface{} `json:"attached_report_type"`
	Sms                       interface{} `json:"sms"`
	Enabled                   int         `json:"enabled"`
	UseDashboard              int         `json:"use_dashboard"`
	DashboardFile             interface{} `json:"dashboard_file"`
	LiveResults               int         `json:"live_results"`
	ScanTimeWindow            int         `json:"scan_time_window"`
	CustomTargets             string      `json:"custom_targets"`
	Migrated                  int         `json:"migrated"`
	LastScheduledRun          string      `json:"last_scheduled_run"`
	NotificationFilters       interface{} `json:"notification_filters"`
	TagID                     int         `json:"tag_id"`
	DefaultPermissions        int         `json:"default_permissions"`
	OwnerID                   int         `json:"owner_id"`
	Type                      string      `json:"type"`
}

type Note struct {
	Title    string `json:"title"`
	Message  string `json:"message"`
	Severity int64  `json:"severity"`
}

type HostVulnerability struct {
	HostID       int64  `json:"host_id"`
	Hostname     string `json:"hostname"`
	PluginID     int64  `json:"plugin_id"`
	PluginName   string `json:"plugin_name"`
	PluginFamily string `json:"plugin_family"`
	Count        int64  `json:"count"`
	VulnIdx      int64  `json:"vuln_index"`
	SeverityIdx  int64  `json:"severity_index"`
	Severity     int64  `json:"severity"`
}

type HostCompliance struct {
	HostID       int64  `json:"host_id"`
	Hostname     string `json:"hostname"`
	PluginID     int64  `json:"plugin_id"`
	PluginName   string `json:"plugin_name"`
	PluginFamily string `json:"plugin_family"`
	Count        int64  `json:"count"`
	SeverityIdx  int64  `json:"severity_index"`
	Severity     int64  `json:"severity"`
}

type TimeZone struct {
	Name string `json:"name"`
	Val  string `json:"value"`
}

// Sessions resources.

type Session struct {
	ID          int64    `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Perms       int64    `json:"permissions"`
	LastLogin   int64    `json:"last_login"`
	ContainerID int64    `json:"container_id"`
	Groups      []string `json:"groups"`
}

// AgentGroup The details of an agent group.
type AgentGroup struct {
	ID                   int64  `json:"id"`
	Name                 string `json:"name"`
	OwnerID              int64  `json:"owner_id"`
	Owner                string `json:"owner"`
	Shared               int    `json:"shared"`
	UserPerms            int64  `json:"user_permissions"`
	CreationDate         int64  `json:"creation_date"`
	LastModificationDate int64  `json:"last_modification_date"`
}

type ServerProperty struct {
	Installers                      Installer      `json:"installers"`
	LoadedPluginSet                 interface{}    `json:"loaded_plugin_set"`
	Features                        Feature        `json:"features"`
	ServerUUID                      string         `json:"server_uuid"`
	UsersCount                      int            `json:"users_count"`
	TemplateVersion                 string         `json:"template_version"`
	Update                          Update         `json:"update"`
	RestartPending                  RestartPending `json:"restart_pending"`
	NessusUIVersion                 string         `json:"nessus_ui_version"`
	NessusType                      string         `json:"nessus_type"`
	License                         License        `json:"license"`
	TenableLinks                    []TenableLink  `json:"tenable_links"`
	FeedError                       int            `json:"feed_error"`
	RestartNeeded                   interface{}    `json:"restart_needed"`
	ServerBuild                     string         `json:"server_build"`
	ShowNpv7WhatsNew                int            `json:"show_npv7_whats_new"`
	Npv7DowngradeAvailable          int            `json:"npv7_downgrade_available"`
	Capabilities                    Capability     `json:"capabilities"`
	PluginSet                       interface{}    `json:"plugin_set"`
	UsedIPCount                     int            `json:"used_ip_count"`
	IdleTimeout                     string         `json:"idle_timeout"`
	NessusUIBuild                   string         `json:"nessus_ui_build"`
	Npv7UpgradeRequired             bool           `json:"npv7_upgrade_required"`
	ScannerBootTime                 int            `json:"scanner_boottime"`
	DisableRssWidget                interface{}    `json:"disable_rss_widget"`
	Npv7                            int            `json:"npv7"`
	LoginBanner                     interface{}    `json:"login_banner"`
	TemplateVersionUpgradeNecessary interface{}    `json:"template_version_upgrade_necessary"`
	Npv7UpgradeNotification         int            `json:"npv7_upgrade_notification"`
	Platform                        string         `json:"platform"`
	ServerVersion                   string         `json:"server_version"`
}
