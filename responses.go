package nessie

// loginResp is the internal response to login attemps.
type loginResp struct {
	Token string `json:"token"`
}

type ScanHostKbPrepareResp struct {
	Token string `json:"token"`
}

// ServerProperties is the structure returned by the ServerProperties() method.
type ServerProperties struct {
	ServerProperty
}

// ServerStatus is the stucture returned  by the ServerStatus() method.
type ServerStatus struct {
	Status             string `json:"status"`
	Progress           int64  `json:"progress"`
	MustDestroySession bool
}

type listUsersResp struct {
	Users []User `json:"users"`
}

type FamilyDetails struct {
	Name    string   `json:"name"`
	ID      int64    `json:"id"`
	Plugins []Plugin `json:"plugins"`
}

type PluginDetails struct {
	Plugin
	FamilyName string       `json:"family_name"`
	Attrs      []PluginAttr `json:"attributes"`
}

type listPoliciesResp struct {
	Policies []Policy `json:"policies"`
}

type ListScansResponse struct {
	Folders   []Folder `json:"folders"`
	Scans     []Scan   `json:"scans"`
	Timestamp int64    `json:"timestamp"`
}

type listTemplatesResp struct {
	Templates []Template `json:"templates"`
}

type startScanResp struct {
	UUID string `json:"scan_uuid"`
}

type ScanDetailsResp struct {
	Info            ScanInfo          `json:"info"`
	HostsDetailInfo []HostsDetailInfo `json:"hosts_detail_info"`
	Compliance      []interface{}     `json:"compliance"`
	Filters         []Filter          `json:"filters"`
	CompHosts       []interface{}     `json:"comphosts"`
	History         []History         `json:"history"`
	Notes           interface{}       `json:"notes"`
	Hosts           []Host            `json:"hosts"`
	Remediation     Remediation       `json:"remediations"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
}

type HostScanDetailsResp struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Compliance      []interface{}   `json:"compliance"`
	Info            HostInfo        `json:"info"`
}

type ScanPluginOutput struct {
	Outputs []PluginOutput `json:"outputs"`
	Info    struct {
		PluginDescription PluginDescription `json:"plugindescription"`
	} `json:"info"`
}

type ScanHostKbInfo struct {
	Content string
}

type tzResp struct {
	Timezones []TimeZone `json:"timezones"`
}

type listFoldersResp struct {
	Folders []Folder `json:"folders"`
}

type exportScanResp struct {
	File int64 `json:"file"`
}

type exportStatusResp struct {
	Status string `json:"status"`
}

type listGroupsResp struct {
	Groups []Group `json:"groups"`
}

type listAgentGroupsResp struct {
	Groups []AgentGroup `json:"groups"`
}

// CreatePolicyResp response body If successful
type CreatePolicyResp struct {
	PolicyID   int64  `json:"policy_id"`
	PolicyName string `json:"policy_name"`
}
