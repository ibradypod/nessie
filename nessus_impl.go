package nessie

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type nessusImpl struct {
	// client is the HTTP client to use to issue requests to nessus.
	client *http.Client
	// authCookie is the login token returned by nessus upon successful login.
	authCookie string
	apiKeys    string
	apiURL     string
	// verbose will log requests and responses amongst other helpful debugging things.
	verbose bool
}

// NewNessus will return a new Nessus instance, if caCertPath is empty, the host certificate roots will be used to check for the validity of the nessus server API certificate.
func NewNessus(apiURL, caCertPath string) (Nessus, error) {
	return newNessus(apiURL, caCertPath, false, false, nil)
}

// NewInsecureNessus will return a nessus instance which does not check for the api certificate validity, do not use in production environment.
func NewInsecureNessus(apiURL string) (Nessus, error) {
	return newNessus(apiURL, "", true, false, nil)
}

// NewFingerprintedNessus will return a nessus instance which verifies the api server's certificate by its SHA256 fingerprint (on the RawSubjectPublicKeyInfo and base64 encoded) against a whitelist of good certFingerprints. Fingerprint verification will enable InsecureSkipVerify.
func NewFingerprintedNessus(apiURL string, certFingerprints []string) (Nessus, error) {
	return newNessus(apiURL, "", true, true, certFingerprints)
}

func newNessus(apiURL, caCertPath string, ignoreSSLCertsErrors bool, verifyCertFingerprint bool, certFingerprints []string) (Nessus, error) {
	var (
		dialTLS func(network, addr string) (net.Conn, error)
		roots   *x509.CertPool
	)
	config := &tls.Config{
		InsecureSkipVerify: ignoreSSLCertsErrors,
		RootCAs:            roots,
	}
	if len(caCertPath) != 0 {
		roots = x509.NewCertPool()
		rootPEM, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			return nil, err
		}
		ok := roots.AppendCertsFromPEM(rootPEM)
		if !ok {
			return nil, fmt.Errorf("could not append certs from PEM %s", caCertPath)
		}
	} else if verifyCertFingerprint == true {
		if len(certFingerprints) == 0 {
			return nil, fmt.Errorf("fingerprint verification enabled, fingerprint must not be empty")
		}
		dialTLS = createDialTLSFuncToVerifyFingerprint(certFingerprints, config)
	}
	return &nessusImpl{
		apiURL: apiURL,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: config,
				DialTLS:         dialTLS,
			},
		},
	}, nil
}

func sha256Fingerprint(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func createDialTLSFuncToVerifyFingerprint(certFingerprints []string, config *tls.Config) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		conn, err := tls.Dial(network, addr, config)
		if err != nil {
			return nil, err
		}
		state := conn.ConnectionState()
		// Only check the first cert in the chain. The TLS server must send its cert first (RFC5246), and this first cert is authenticated with a check for proof of private key possesion.
		peerFingerprint := sha256Fingerprint(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		for _, fingerprint := range certFingerprints {
			if peerFingerprint == fingerprint {
				return conn, nil
			}
		}
		conn.Close()
		return nil, fmt.Errorf("no server certificate with fingerprints %v was found", certFingerprints)
	}
}

func (n *nessusImpl) SetVerbose(verbosity bool) {
	n.verbose = verbosity
}

func (n *nessusImpl) SetApiKeys(apiKeys string) {
	n.apiKeys = apiKeys
}

func (n *nessusImpl) AuthCookie() string {
	return n.authCookie
}

// Request make a request to Nessus
func (n *nessusImpl) Request(method string, resource string, js interface{}, wantStatus []int) (resp *http.Response, err error) {
	u, err := url.ParseRequestURI(n.apiURL)
	if err != nil {
		return nil, err
	}
	if uri, err := url.ParseRequestURI(resource); err != nil {
		return nil, err
	} else {
		u.Path = uri.Path
		u.RawQuery = uri.RawQuery
	}

	var req *http.Request
	if js != nil {
		jb, err := json.Marshal(js)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(method, u.String(), bytes.NewBufferString(string(jb)))
	} else {
		req, err = http.NewRequest(method, u.String(), http.NoBody)
	}
	if err != nil {
		return nil, err
	}
	if method == "POST" || method == "PUT" {
		req.Header.Add("Content-Type", "application/json")
	}
	req.Header.Add("Accept", "application/json")
	if n.authCookie != "" {
		req.Header.Add("X-Cookie", fmt.Sprintf("token=%s", n.authCookie))
	}
	if n.apiKeys != "" {
		req.Header.Add("X-ApiKeys", n.apiKeys)
	}

	if n.verbose {
		db, err := httputil.DumpRequest(req, true)
		if err != nil {
			return nil, err
		}
		logrus.Debug("sending data:", string(db))
	}
	resp, err = n.client.Do(req)
	if err != nil {
		return nil, err
	}
	if n.verbose {
		if body, err := httputil.DumpResponse(resp, true); err == nil {
			logrus.Debug(string(body))
		}
	}
	var statusFound bool
	for _, status := range wantStatus {
		if resp.StatusCode == status {
			statusFound = true
			break
		}
	}
	if !statusFound {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected status code, got %d wanted %v (%s)", resp.StatusCode, wantStatus, body)
	}
	return resp, nil
}

// Login will log into nessus with the username and passwords given from the command line flags.
func (n *nessusImpl) Login(username, password string) error {
	if n.verbose {
		log.Printf("Login into %s\n", n.apiURL)
	}
	data := loginRequest{
		Username: username,
		Password: password,
	}

	resp, err := n.Request("POST", "/session", data, []int{http.StatusOK})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	reply := &loginResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return err
	}
	n.authCookie = reply.Token
	return nil
}

// Logout will invalidate the current session token.
func (n *nessusImpl) Logout() error {
	if n.authCookie == "" {
		logrus.Debug("Not logged in, nothing to do to logout...")
		return nil
	}
	if n.verbose {
		logrus.Debug("Logout...")
	}

	if _, err := n.Request("DELETE", "/session", nil, []int{http.StatusOK}); err != nil {
		return err
	}
	n.authCookie = ""
	return nil
}

// Session will return the details for the current session.
func (n *nessusImpl) Session() (Session, error) {
	if n.verbose {
		log.Printf("Getting details for current session...")
	}

	resp, err := n.Request("GET", "/session", nil, []int{http.StatusOK})
	if err != nil {
		return Session{}, err
	}
	defer resp.Body.Close()
	var reply Session
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return Session{}, err
	}
	return reply, nil
}

// ServerProperties will return the current state of the nessus instance.
func (n *nessusImpl) ServerProperties() (*ServerProperties, error) {
	if n.verbose {
		logrus.Debug("Server properties...")
	}

	resp, err := n.Request("GET", "/server/properties", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &ServerProperties{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// ServerStatus will return the current status of the nessus instance.
func (n *nessusImpl) ServerStatus() (*ServerStatus, error) {
	if n.verbose {
		logrus.Debug("Server status...")
	}

	resp, err := n.Request("GET", "/server/status", nil, []int{http.StatusOK, http.StatusServiceUnavailable})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &ServerStatus{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		reply.MustDestroySession = true
	}
	return reply, nil
}

const (
	UserTypeLocal = "local"
	UserTypeLDAP  = "ldap"

	Permissions0   = "0"
	Permissions16  = "16"
	Permissions32  = "32"
	Permissions64  = "64"
	Permissions128 = "128"
)

// CreateUser will register a new user with the nessus instance.
// Name and email can be empty.
func (n *nessusImpl) CreateUser(username, password, userType, permissions, name, email string) (*User, error) {
	if n.verbose {
		logrus.Debug("Creating new user...")
	}
	data := createUserRequest{
		Username:    username,
		Password:    password,
		Permissions: permissions,
		Type:        userType,
	}
	if name != "" {
		data.Name = name
	}
	if email != "" {
		data.Email = email
	}

	resp, err := n.Request("POST", "/users", data, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &User{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// ListUsers will return the list of users on this nessus instance.
func (n *nessusImpl) ListUsers() ([]User, error) {
	if n.verbose {
		logrus.Debug("Listing users...")
	}

	resp, err := n.Request("GET", "/users", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &listUsersResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Users, nil
}

// DeleteUser will remove a user from this nessus instance.
func (n *nessusImpl) DeleteUser(userID int) error {
	if n.verbose {
		logrus.Debug("Deleting user...")
	}

	_, err := n.Request("DELETE", fmt.Sprintf("/users/%d", userID), nil, []int{http.StatusOK})
	return err
}

// SetUserPassword will change the password for the given user.
func (n *nessusImpl) SetUserPassword(userID int, password string) error {
	if n.verbose {
		logrus.Debug("Changing password of user...")
	}
	data := setUserPasswordRequest{
		Password: password,
	}

	_, err := n.Request("PUT", fmt.Sprintf("/users/%d/chpasswd", userID), data, []int{http.StatusOK})
	return err
}

// EditUser will edit certain information about a user.
// Any non empty parameter will be set.
func (n *nessusImpl) EditUser(userID int, permissions, name, email string) (*User, error) {
	if n.verbose {
		logrus.Debug("Editing user...")
	}
	data := editUserRequest{}

	if permissions != "" {
		data.Permissions = permissions
	}
	if name != "" {
		data.Name = name
	}
	if email != "" {
		data.Email = email
	}

	resp, err := n.Request("PUT", fmt.Sprintf("/users/%d", userID), data, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &User{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *nessusImpl) PluginFamilies() ([]PluginFamily, error) {
	if n.verbose {
		logrus.Debug("Getting list of plugin families...")
	}

	resp, err := n.Request("GET", "/plugins/families", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var reply PluginFamilies
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Families, nil
}

func (n *nessusImpl) FamilyDetails(ID int64) (*FamilyDetails, error) {
	if n.verbose {
		logrus.Debug("Getting details of family...")
	}

	resp, err := n.Request("GET", fmt.Sprintf("/plugins/families/%d", ID), nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &FamilyDetails{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *nessusImpl) PluginDetails(ID int64) (*PluginDetails, error) {
	if n.verbose {
		logrus.Debug("Getting details plugin...")
	}

	resp, err := n.Request("GET", fmt.Sprintf("/plugins/plugin/%d", ID), nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &PluginDetails{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *nessusImpl) Scanners() ([]Scanner, error) {
	if n.verbose {
		logrus.Debug("Getting scanners list...")
	}

	resp, err := n.Request("GET", "/scanners", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var reply struct {
		Scanners []Scanner `json:"scanners"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Scanners, nil
}

// AllPlugin wil hammer nessus asking for details of every plugins available and feeding them in
// the returned channel.
// Getting all the plugins is slow (usually takes a few minutes on a decent machine).
func (n *nessusImpl) AllPlugins() (chan PluginDetails, error) {
	plugChan := make(chan PluginDetails, 20)

	families, err := n.PluginFamilies()
	if err != nil {
		return nil, err
	}
	idChan := make(chan int64, 20)
	var wgf sync.WaitGroup
	var wgp sync.WaitGroup
	// Launch a goroutine per family to get all the plugins of those families.
	for _, family := range families {
		wgf.Add(1)
		go func(famID int64) {
			defer wgf.Done()
			famDetails, err := n.FamilyDetails(famID)
			if err != nil {
				return
			}
			for _, plugin := range famDetails.Plugins {
				wgp.Add(1)
				idChan <- plugin.ID
			}
		}(family.ID)
	}
	// Launch our workers getting individual plugin details.
	for i := 0; i < 10; i++ {
		go func() {
			for id := range idChan {
				plugin, err := n.PluginDetails(id)
				if err != nil {
					wgp.Done()
					continue
				}
				plugChan <- *plugin
				wgp.Done()
			}
		}()
	}

	go func() {
		wgf.Wait()
		// Once we finished adding all the plugin IDs, we can close the channel.
		close(idChan)
		// Once all the plugins have been returned, we can close the plugin channel
		// to let the receiver know.
		wgp.Wait()
		close(plugChan)
	}()

	return plugChan, nil
}

func (n *nessusImpl) Policies() ([]Policy, error) {
	if n.verbose {
		logrus.Debug("Getting policies list...")
	}

	resp, err := n.Request("GET", "/policies", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var reply listPoliciesResp
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Policies, nil
}

const (
	LaunchOnDemand = "ON_DEMAND"
	LaunchDaily    = "DAILY"
	LaunchWeekly   = "WEEKLY"
	LaunchMonthly  = "MONTHLY"
	LaunchYearly   = "YEARLY"
)

func (n *nessusImpl) NewScan(
	editorTmplUUID string,
	settingsName string,
	outputFolderID int64,
	policyID int64,
	scannerID int64,
	launch string,
	targets []string) (*Scan, error) {
	data := NewScanRequest{
		UUID: editorTmplUUID,
		Settings: ScanSettingsRequest{
			Name:        settingsName,
			Description: "Some description",
			FolderID:    outputFolderID,
			ScannerID:   scannerID,
			PolicyID:    policyID,
			Launch:      launch,
			TextTargets: strings.Join(targets, ", "),
		},
	}

	return n.CreateScan(data)
}

func (n *nessusImpl) CreateScan(newScanRequest NewScanRequest) (*Scan, error) {
	if n.verbose {
		logrus.Debug("Creating a new scan...")
	}

	resp, err := n.Request("POST", "/scans", newScanRequest, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	reply := struct {
		Scan Scan `json:"scan"`
	}{}

	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return &reply.Scan, nil
}

func (n *nessusImpl) Scans() (*ListScansResponse, error) {
	if n.verbose {
		logrus.Debug("Getting scans list...")
	}

	resp, err := n.Request("GET", "/scans", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &ListScansResponse{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *nessusImpl) ScanTemplates() ([]Template, error) {
	if n.verbose {
		logrus.Debug("Getting scans templates...")
	}

	resp, err := n.Request("GET", "/editor/scan/templates", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &listTemplatesResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Templates, nil
}

func (n *nessusImpl) PolicyTemplates() ([]Template, error) {
	if n.verbose {
		logrus.Debug("Getting policy templates...")
	}

	resp, err := n.Request("GET", "/editor/policy/templates", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &listTemplatesResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Templates, nil
}

// StartScan starts the given scan and returns its UUID.
func (n *nessusImpl) StartScan(scanID int64) (string, error) {
	if n.verbose {
		logrus.Debug("Starting scan...")
	}

	resp, err := n.Request("POST", fmt.Sprintf("/scans/%d/launch", scanID), nil, []int{http.StatusOK})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	reply := &startScanResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return "", err
	}
	return reply.UUID, nil
}

func (n *nessusImpl) PauseScan(scanID int64) error {
	if n.verbose {
		logrus.Debug("Pausing scan...")
	}

	_, err := n.Request("POST", fmt.Sprintf("/scans/%d/pause", scanID), nil, []int{http.StatusOK})
	return err
}

func (n *nessusImpl) ResumeScan(scanID int64) error {
	if n.verbose {
		logrus.Debug("Resume scan...")
	}

	_, err := n.Request("POST", fmt.Sprintf("/scans/%d/resume", scanID), nil, []int{http.StatusOK})
	return err
}

func (n *nessusImpl) StopScan(scanID int64) error {
	if n.verbose {
		logrus.Debug("Stop scan...")
	}

	_, err := n.Request("POST", fmt.Sprintf("/scans/%d/stop", scanID), nil, []int{http.StatusOK})
	return err
}

func (n *nessusImpl) DeleteScan(scanID int64) error {
	if n.verbose {
		logrus.Debug("Deleting scan...")
	}

	_, err := n.Request("DELETE", fmt.Sprintf("/scans/%d", scanID), nil, []int{http.StatusOK})
	return err
}

func (n *nessusImpl) ScanDetails(scanID int64, args url.Values) (*ScanDetailsResp, error) {
	if n.verbose {
		logrus.Debug("Getting details about a scan...")
	}
	var uri = fmt.Sprintf("/scans/%d", scanID)
	if len(args) > 0 {
		uri += "?" + args.Encode()
	}
	resp, err := n.Request("GET", uri, nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &ScanDetailsResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *nessusImpl) HostScanDetails(scanID int64, hostID int64, args url.Values) (*HostScanDetailsResp, error) {
	if n.verbose {
		logrus.Debug("Getting host details about a scan...")
	}
	var uri = fmt.Sprintf("/scans/%d/hosts/%d", scanID, hostID)
	if len(args) > 0 {
		uri += "?" + args.Encode()
	}
	resp, err := n.Request("GET", uri, nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &HostScanDetailsResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *nessusImpl) ScanPluginOutput(scanID int64, hostID int64, pluginID int64) (*ScanPluginOutput, error) {
	if n.verbose {
		logrus.Debug("Getting plugin output about a scan...")
	}
	var uri = fmt.Sprintf("/scans/%d/hosts/%d/plugins/%d", scanID, hostID, pluginID)
	resp, err := n.Request("GET", uri, nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &ScanPluginOutput{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *nessusImpl) ScanKbInfo(scanID int64, hostID int64) (*ScanHostKbInfo, error) {
	if n.verbose {
		logrus.Debug("Getting ScanKbInfo about a scan...")
	}
	var uri = fmt.Sprintf("/scans/%d/hosts/%d/kb/prepare", scanID, hostID)
	resp, err := n.Request("GET", uri, nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &ScanHostKbPrepareResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	resp1, err := n.Request("GET", fmt.Sprintf("/tokens/%s/download", reply.Token), nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp1.Body.Close()
	content, err := ioutil.ReadAll(resp1.Body)
	if err != nil {
		return nil, err
	}
	reply1 := &ScanHostKbInfo{
		Content: string(content),
	}
	return reply1, nil
}

func (n *nessusImpl) ConfigureScan(scanID int64, scanSetting NewScanRequest) (*Scan, error) {
	if n.verbose {
		logrus.Debug("Configuring a scan...")
	}

	resp, err := n.Request("PUT", fmt.Sprintf("/scans/%d", scanID), scanSetting, []int{http.StatusOK})
	if nil != err {
		return nil, err
	}

	defer resp.Body.Close()
	reply := &Scan{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); nil != err {
		return nil, err
	}
	return reply, nil
}

func (n *nessusImpl) Timezones() ([]TimeZone, error) {
	if n.verbose {
		logrus.Debug("Getting list of timezones...")
	}

	resp, err := n.Request("GET", "/scans/timezones", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &tzResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Timezones, nil
}

func (n *nessusImpl) Folders() ([]Folder, error) {
	if n.verbose {
		logrus.Debug("Getting list of folders...")
	}

	resp, err := n.Request("GET", "/folders", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &listFoldersResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Folders, nil
}

func (n *nessusImpl) CreateFolder(name string) error {
	if n.verbose {
		logrus.Debug("Creating folders...")
	}

	req := createFolderRequest{Name: name}
	_, err := n.Request("POST", "/folders", req, []int{http.StatusOK})
	return err
}

func (n *nessusImpl) EditFolder(folderID int64, newName string) error {
	if n.verbose {
		logrus.Debug("Editing folders...")
	}

	req := editFolderRequest{Name: newName}
	_, err := n.Request("PUT", fmt.Sprintf("/folders/%d", folderID), req, []int{http.StatusOK})
	return err
}

func (n *nessusImpl) DeleteFolder(folderID int64) error {
	if n.verbose {
		logrus.Debug("Deleting folders...")
	}

	_, err := n.Request("DELETE", fmt.Sprintf("/folders/%d", folderID), nil, []int{http.StatusOK})
	return err
}

const (
	ExportNessus = "nessus"
	ExportPDF    = "pdf"
	ExportHTML   = "html"
	ExportCSV    = "csv"
	ExportDB     = "db"
)

// ExportScan exports a scan to a File resource.
// Call ExportStatus to get the status of the export and call Download() to download the actual file.
func (n *nessusImpl) ExportScan(scanID int64, format string) (int64, error) {
	if n.verbose {
		logrus.Debug("Exporting scan...")
	}

	req := exportScanRequest{Format: format}
	resp, err := n.Request("POST", fmt.Sprintf("/scans/%d/export", scanID), req, []int{http.StatusOK})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	reply := &exportScanResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return 0, err
	}
	return reply.File, nil
}

// ExportFinished returns whether the given scan export file has finished being prepared.
func (n *nessusImpl) ExportFinished(scanID, exportID int64) (bool, error) {
	if n.verbose {
		logrus.Debug("Getting export status...")
	}

	resp, err := n.Request("GET", fmt.Sprintf("/scans/%d/export/%d/status", scanID, exportID), nil, []int{http.StatusOK})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	reply := &exportStatusResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return false, err
	}
	return reply.Status == "ready", nil
}

// DownloadExport will download the given export from nessus.
func (n *nessusImpl) DownloadExport(scanID, exportID int64) ([]byte, error) {
	if n.verbose {
		logrus.Debug("Downloading export file...")
	}

	resp, err := n.Request("GET", fmt.Sprintf("/scans/%d/export/%d/download", scanID, exportID), nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}
	return body, err
}

// TODO: Currently returns a 404... not exposed yet?
func (n *nessusImpl) ListGroups() ([]Group, error) {
	if n.verbose {
		logrus.Debug("Listing groups...")
	}

	resp, err := n.Request("GET", "/groups", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &listGroupsResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Groups, nil
}

// TODO: Currently returns a 404... not exposed yet?
func (n *nessusImpl) CreateGroup(name string) (Group, error) {
	if n.verbose {
		logrus.Debug("Creating a group...")
	}

	req := createGroupRequest{
		Name: name,
	}
	resp, err := n.Request("POST", "/groups", req, []int{http.StatusOK})
	if err != nil {
		return Group{}, err
	}
	defer resp.Body.Close()
	var reply Group
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return Group{}, err
	}
	return reply, nil
}

func (n *nessusImpl) Permissions(objectType string, objectID int64) ([]Permission, error) {
	if n.verbose {
		logrus.Debug("Creating a group...")
	}

	resp, err := n.Request("GET", fmt.Sprintf("/permissions/%s/%d", objectType, objectID), nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var reply []Permission
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// CreatePolicy Create a policy.
func (n *nessusImpl) CreatePolicy(createPolicyRequest CreatePolicyRequest) (CreatePolicyResp, error) {
	if n.verbose {
		logrus.Debug("Creating a policy...")
	}

	resp, err := n.Request("POST", "/policies", createPolicyRequest, []int{http.StatusOK})
	if err != nil {
		return CreatePolicyResp{}, err
	}

	defer resp.Body.Close()
	var reply CreatePolicyResp
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return CreatePolicyResp{}, err
	}
	return reply, nil
}

// ConfigurePolicy Changes the parameters of a policy.
func (n *nessusImpl) ConfigurePolicy(policyID int64, createPolicyRequest CreatePolicyRequest) error {
	if n.verbose {
		logrus.Debug("Configuring a policy...")
	}

	_, err := n.Request("PUT", fmt.Sprintf("/policies/%d", policyID), createPolicyRequest, []int{http.StatusOK})
	return err
}

// DeletePolicy Delete a policy.
func (n *nessusImpl) DeletePolicy(policyID int64) error {
	if n.verbose {
		logrus.Debug("Deleting a policy...")
	}

	_, err := n.Request("DELETE", fmt.Sprintf("/policies/%d", policyID), nil, []int{http.StatusOK})
	return err
}

// Upload Upload a file.
func (n *nessusImpl) Upload(filePath string) error {
	if n.verbose {
		logrus.Debug("Uploading a file...")
	}

	f, err := os.OpenFile(filePath, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("Filedata", filepath.Base(filePath))
	if err != nil {
		return err
	}
	_, err = io.Copy(part, f)

	if err = writer.Close(); nil != err {
		return err
	}

	u, err := url.ParseRequestURI(n.apiURL)
	if err != nil {
		return err
	}
	u.Path = "/file/upload"
	urlStr := fmt.Sprintf("%v", u)

	req, err := http.NewRequest(http.MethodPost, urlStr, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	req.Header.Add("Accept", "application/json")
	if n.authCookie != "" {
		req.Header.Add("X-Cookie", fmt.Sprintf("token=%s", n.authCookie))
	}

	resp, err := n.client.Do(req)
	if nil != err {
		return err
	}

	reply := struct {
		FileUploaded string `json:"fileuploaded"`
	}{}

	if err = json.NewDecoder(resp.Body).Decode(&reply); nil != err {
		return err
	}

	// Duplicate updates will get different replies
	// request:             CIS_CentOS_7_Server_L1_v3.0.0.audit
	// reply: {FileUploaded:CIS_CentOS_7_Server_L1_v3.0.0-6.audit}
	if 0 == len(reply.FileUploaded) {
		return fmt.Errorf("upload failed, api reply: %+v", reply)
	}

	return nil
}

// AgentGroups Returns a list of agent groups.
func (n *nessusImpl) AgentGroups() ([]AgentGroup, error) {
	if n.verbose {
		logrus.Debug("Getting list of agent-groups...")
	}

	resp, err := n.Request("GET", "/agent-groups", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply := &listAgentGroupsResp{
		Groups: make([]AgentGroup, 0),
	}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Groups, nil
}
