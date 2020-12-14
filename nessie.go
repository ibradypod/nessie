// Package nessie implements a client for the Tenable Nessus 6 API.
package nessie

import (
	"net/http"
	"net/url"
)

// Nessus exposes the resources offered via the Tenable Nessus RESTful API.
type Nessus interface {
	SetVerbose(bool)
	AuthCookie() string
	SetApiKeys(apiKeys string)
	Request(method string, resource string, js interface{}, wantStatus []int) (resp *http.Response, err error)
	Login(username, password string) error
	Logout() error
	Session() (Session, error)

	ServerProperties() (*ServerProperties, error)
	ServerStatus() (*ServerStatus, error)

	CreateUser(username, password, userType, permissions, name, email string) (*User, error)
	ListUsers() ([]User, error)
	DeleteUser(userID int) error
	SetUserPassword(userID int, password string) error
	EditUser(userID int, permissions, name, email string) (*User, error)

	PluginFamilies() ([]PluginFamily, error)
	FamilyDetails(ID int64) (*FamilyDetails, error)
	PluginDetails(ID int64) (*PluginDetails, error)
	AllPlugins() (chan PluginDetails, error)

	Scanners() ([]Scanner, error)
	Policies() ([]Policy, error)
	CreatePolicy(policySettings CreatePolicyRequest) (CreatePolicyResp, error)
	ConfigurePolicy(id int64, policySettings CreatePolicyRequest) error
	DeletePolicy(id int64) error

	Upload(filePath string) error
	AgentGroups() ([]AgentGroup, error)

	NewScan(editorTmplUUID, settingsName string, outputFolderID, policyID, scannerID int64, launch string, targets []string) (*Scan, error)
	CreateScan(newScanRequest NewScanRequest) (*Scan, error)
	Scans() (*ListScansResponse, error)
	ScanTemplates() ([]Template, error)
	PolicyTemplates() ([]Template, error)
	StartScan(scanID int64) (string, error)
	PauseScan(scanID int64) error
	ResumeScan(scanID int64) error
	StopScan(scanID int64) error
	DeleteScan(scanID int64) error
	ScanDetails(scanID int64, args url.Values) (*ScanDetailsResp, error)
	ConfigureScan(scanID int64, scanSetting NewScanRequest) (*Scan, error)

	Timezones() ([]TimeZone, error)

	Folders() ([]Folder, error)
	CreateFolder(name string) error
	EditFolder(folderID int64, newName string) error
	DeleteFolder(folderID int64) error

	ExportScan(scanID int64, format string) (int64, error)
	ExportFinished(scanID, exportID int64) (bool, error)
	DownloadExport(scanID, exportID int64) ([]byte, error)

	Permissions(objectType string, objectID int64) ([]Permission, error)
}
