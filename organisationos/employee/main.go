// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var errRunning = errors.New("employee helper already running")

const version = "0.3.1-candidate.1"
const engineSHA = "14421c4afbe5b48ddd9065410310f6fd667d678ae5943bd9520f28f261d8eb4b"

//go:embed assets/engine.bin
var engineBytes []byte
var uuidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
var keyPattern = regexp.MustCompile(`^[A-Z2-7]{7}(?:-[A-Z2-7]{7}){7}$`)

type Config struct {
	Schema   int    `json:"schema"`
	Instance string `json:"instanceId"`
	Portal   string `json:"portalOrigin"`
	API      string `json:"apiOrigin"`
	Name     string `json:"organisationName"`
	Server   string `json:"serverDeviceKey"`
	Address  string `json:"publicEndpoint"`
}
type State struct {
	Device   string `json:"deviceId"`
	Identity string `json:"deviceKey"`
}
type Pending struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Identity string `json:"deviceKey"`
	Expires  int64  `json:"expiresAt"`
}
type Server struct {
	Key     string `json:"deviceKey"`
	Address string `json:"publicEndpoint"`
}
type Folder struct {
	ID        string `json:"id"`
	Selection string `json:"selectionId"`
	Label     string `json:"label"`
	State     string `json:"state"`
	Mode      string `json:"mode"`
}
type Configuration struct {
	Status  string   `json:"status"`
	Device  string   `json:"deviceId"`
	Server  Server   `json:"server"`
	Folders []Folder `json:"folders"`
}
type Node struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Text     string     `xml:",chardata"`
	Children []Node     `xml:",any"`
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func base() string         { return filepath.Join(os.Getenv("LOCALAPPDATA"), "OrganisationOS", "Syncthing") }
func home(c Config) string { return filepath.Join(base(), "Organisations", c.Instance) }
func writeJSON(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(path, b, 0600)
}
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	if s, e := os.Lstat(path); e == nil && (!s.Mode().IsRegular() || s.Mode()&os.ModeSymlink != 0) {
		return errors.New("unsafe local file")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".oos-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Rename(name, path)
}
func loadJSON(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(b) > 65536 {
		return errors.New("oversized local state")
	}
	return json.Unmarshal(b, v)
}
func validate(c Config) error {
	known := map[string][3]string{"27c0be38-60bd-4dce-bb28-ef0088716a25": {"https://portal.thecgp.com", "tcp://syncthing.thecgp.com:22000", "https://portal.thecgp.com"}, "b7a1f6b1-c4aa-4de7-95fb-29d509d3398d": {"https://portal.villesadp.ca", "tcp://syncthing.villesadp.ca:22000", "https://api.villesadp.ca"}}
	p, ok := known[c.Instance]
	if !ok || c.Schema != 2 || c.API != p[2] || c.Portal != p[0] || c.Address != p[1] || !keyPattern.MatchString(c.Server) || c.Name == "" || len(c.Name) > 120 {
		return errors.New("organisation configuration refused")
	}
	return nil
}
func getConfig(instance string) (Config, error) {
	var c Config
	if !uuidPattern.MatchString(instance) {
		return c, errors.New("unknown organisation")
	}
	e := loadJSON(filepath.Join(base(), "Organisations", instance, "organisation.json"), &c)
	if e == nil {
		e = validate(c)
	}
	if c.Instance != instance {
		return c, errors.New("organisation mismatch")
	}
	return c, e
}
func child(n *Node, name string) *Node {
	for i := range n.Children {
		if n.Children[i].XMLName.Local == name {
			return &n.Children[i]
		}
	}
	n.Children = append(n.Children, Node{XMLName: xml.Name{Local: name}})
	return &n.Children[len(n.Children)-1]
}
func set(n *Node, name, value string) { child(n, name).Text = value }
func identity(certPEM []byte) (string, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return "", errors.New("certificate missing")
	}
	if _, e := x509.ParseCertificate(b.Bytes); e != nil {
		return "", e
	}
	h := sha256.Sum256(b.Bytes)
	raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:])
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	checked := ""
	for i := 0; i < len(raw); i += 13 {
		part := raw[i : i+13]
		sum, factor := 0, 1
		for _, c := range part {
			v := strings.IndexRune(alphabet, c) * factor
			sum += v/32 + v%32
			factor = 3 - factor
		}
		checked += part + string(alphabet[(32-sum%32)%32])
	}
	parts := []string{}
	for i := 0; i < len(checked); i += 7 {
		parts = append(parts, checked[i:i+7])
	}
	return strings.Join(parts, "-"), nil
}
func prepare(c Config, engine string) error {
	state := filepath.Join(home(c), "Etat")
	if _, e := os.Stat(filepath.Join(state, "cert.pem")); e == nil {
		_, e = readIdentity(c)
		return e
	}
	if _, e := os.Stat(state); !os.IsNotExist(e) {
		return errors.New("incomplete existing state retained")
	}
	if e := os.Mkdir(state, 0700); e != nil {
		return e
	}
	command := exec.Command(engine, "generate", "--home", state, "--no-port-probing")
	hide(command)
	if e := command.Run(); e != nil {
		return errors.New("identity generation failed")
	}
	raw, e := os.ReadFile(filepath.Join(state, "config.xml"))
	if e != nil {
		return e
	}
	var cfg Node
	if e = xml.Unmarshal(raw, &cfg); e != nil {
		return e
	}
	folders := []Node{}
	for _, n := range cfg.Children {
		if n.XMLName.Local != "folder" {
			folders = append(folders, n)
		}
	}
	cfg.Children = folders
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	address := listener.Addr().String()
	listener.Close()
	gui := child(&cfg, "gui")
	set(gui, "address", address)
	options := child(&cfg, "options")
	set(options, "listenAddress", "tcp://127.0.0.1:0")
	for _, k := range []string{"globalAnnounceEnabled", "localAnnounceEnabled", "relaysEnabled", "natEnabled", "crashReportingEnabled"} {
		set(options, k, "false")
	}
	out, e := xml.Marshal(cfg)
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(state, "config.xml"), out, 0600)
}
func readIdentity(c Config) (string, error) {
	raw, e := os.ReadFile(filepath.Join(home(c), "Etat", "cert.pem"))
	if e != nil {
		return "", e
	}
	return identity(raw)
}
func proof(c Config, record, method, path string, body []byte) (map[string]any, error) {
	cert, e := os.ReadFile(filepath.Join(home(c), "Etat", "cert.pem"))
	if e != nil {
		return nil, e
	}
	private, e := os.ReadFile(filepath.Join(home(c), "Etat", "key.pem"))
	if e != nil {
		return nil, e
	}
	pair, e := tls.X509KeyPair(cert, private)
	if e != nil {
		return nil, e
	}
	nonce, e := randomHex(16)
	if e != nil {
		return nil, e
	}
	timestamp := time.Now().Unix()
	payload := []byte(strings.Join([]string{"organisationos-offline-v1", c.Instance, record, fmt.Sprint(timestamp), nonce, method, path, digest(body)}, "\n"))
	var signature []byte
	switch key := pair.PrivateKey.(type) {
	case ed25519.PrivateKey:
		signature = ed25519.Sign(key, payload)
	case *ecdsa.PrivateKey:
		h := sha256.Sum256(payload)
		signature, e = ecdsa.SignASN1(rand.Reader, key, h[:])
	case *rsa.PrivateKey:
		h := sha256.Sum256(payload)
		signature, e = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	default:
		e = errors.New("unsupported device key")
	}
	if e != nil {
		return nil, e
	}
	return map[string]any{"certificate": string(cert), "nonce": nonce, "signature": base64.StdEncoding.EncodeToString(signature), "timestamp": timestamp}, nil
}

var client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}

func portal(c Config, method, path string, body any, p map[string]any, out any) error {
	var data []byte
	var e error
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequest(method, c.API+path, bytes.NewReader(data))
	if e != nil {
		return e
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if p != nil {
		raw, _ := json.Marshal(p)
		req.Header.Set("X-OrganisationOS-Device-Proof", base64.StdEncoding.EncodeToString(raw))
	}
	r, e := client.Do(req)
	if e != nil {
		return errors.New("organisation unavailable")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return errors.New("organisation access refused or temporarily unavailable")
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 2097153))
	if e != nil || len(raw) > 2097152 {
		return errors.New("organisation response refused")
	}
	var wrapper struct {
		Data json.RawMessage `json:"data"`
	}
	if e = json.Unmarshal(raw, &wrapper); e != nil {
		return e
	}
	return json.Unmarshal(wrapper.Data, out)
}
func local(c Config, method, path string, body any, out any) error {
	raw, e := os.ReadFile(filepath.Join(home(c), "Etat", "config.xml"))
	if e != nil {
		return e
	}
	var cfg Node
	if e = xml.Unmarshal(raw, &cfg); e != nil {
		return e
	}
	gui := child(&cfg, "gui")
	address := strings.TrimSpace(child(gui, "address").Text)
	host, _, e := net.SplitHostPort(address)
	if e != nil || host != "127.0.0.1" {
		return errors.New("local administration address refused")
	}
	key := strings.TrimSpace(child(gui, "apikey").Text)
	var payload []byte
	if body != nil {
		payload, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequest(method, "http://"+address+"/rest/"+path, bytes.NewReader(payload))
	if e != nil {
		return e
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", "application/json")
	r, e := client.Do(req)
	if e != nil {
		return errors.New("local engine unavailable")
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return errors.New("local engine operation refused")
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(r.Body, 4194304)).Decode(out)
}
func begin(c Config) error {
	id, e := readIdentity(c)
	if e != nil {
		return e
	}
	verifier, e := randomHex(32)
	if e != nil {
		return e
	}
	state, e := randomHex(16)
	if e != nil {
		return e
	}
	pending := Pending{state, verifier, id, time.Now().Add(10 * time.Minute).Unix()}
	if e = writeJSON(filepath.Join(home(c), "pending.json"), pending); e != nil {
		return e
	}
	hostname, e := os.Hostname()
	if e != nil || hostname == "" {
		hostname = "Mon appareil"
	}
	q := url.Values{"device": {id}, "challenge": {digest([]byte(verifier))}, "state": {state}, "name": {hostname}}
	return browser(c.Portal + "/documents/offline/enroll?" + q.Encode())
}
func callback(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "organisationos-syncthing" || u.Host != "enrollment" || u.Path != "" || u.Fragment != "" {
		return errors.New("enrollment callback refused")
	}
	q := u.Query()
	for k, v := range q {
		if len(v) != 1 || (k != "state" && k != "code" && k != "deviceId") {
			return errors.New("enrollment callback refused")
		}
	}
	if !uuidPattern.MatchString(q.Get("deviceId")) {
		return errors.New("device record refused")
	}
	entries, e := os.ReadDir(filepath.Join(base(), "Organisations"))
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		c, e := getConfig(entry.Name())
		if e != nil {
			continue
		}
		var pending Pending
		if loadJSON(filepath.Join(home(c), "pending.json"), &pending) != nil || pending.State != q.Get("state") {
			continue
		}
		if pending.Expires < time.Now().Unix() {
			return errors.New("enrollment expired; reconnect from application")
		}
		id, e := readIdentity(c)
		if e != nil || id != pending.Identity {
			return errors.New("device identity changed")
		}
		record := q.Get("deviceId")
		path := "/api/v1/documents/offline/devices/" + record + "/exchange"
		var configuration Configuration
		if code := q.Get("code"); code != "" {
			if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(code) {
				return errors.New("enrollment code refused")
			}
			body := map[string]any{"code": code, "verifier": pending.Verifier}
			canonical, _ := json.Marshal(body)
			p, e := proof(c, record, "POST", path, canonical)
			if e != nil {
				return e
			}
			body["proof"] = p
			if e = portal(c, "POST", path, body, nil, &configuration); e != nil {
				// A lost acknowledgement may follow a committed exchange. A signed read proves the same key.
				path = "/api/v1/documents/offline/devices/" + record + "/configuration"
				retryProof, proofErr := proof(c, record, "GET", path, nil)
				if proofErr != nil {
					return proofErr
				}
				if retryErr := portal(c, "GET", path, nil, retryProof, &configuration); retryErr != nil {
					return retryErr
				}
			}
		} else {
			path = "/api/v1/documents/offline/devices/" + record + "/configuration"
			p, e := proof(c, record, "GET", path, nil)
			if e != nil {
				return e
			}
			if e = portal(c, "GET", path, nil, p, &configuration); e != nil {
				return e
			}
		}
		if e = validateResponse(c, record, configuration); e != nil {
			return e
		}
		if e = writeJSON(filepath.Join(home(c), "enrollment.json"), State{record, id}); e != nil {
			return e
		}
		os.Remove(filepath.Join(home(c), "pending.json"))
		return browser(c.Portal + "/documents/offline")
	}
	return errors.New("no pending local enrollment matches this callback")
}
func validateResponse(c Config, record string, r Configuration) error {
	if r.Status != "ACTIVE" || r.Device != record || r.Server.Key != c.Server || r.Server.Address != c.Address || len(r.Folders) > 32 {
		return errors.New("organisation server identity or scope changed")
	}
	seen := map[string]bool{}
	for _, f := range r.Folders {
		if !uuidPattern.MatchString(f.Selection) || f.ID != "oos-"+f.Selection || seen[f.ID] || f.Mode != "sendreceive" {
			return errors.New("folder scope refused")
		}
		seen[f.ID] = true
	}
	return nil
}
func configure(c Config, state State, r Configuration) error {
	if e := validateResponse(c, state.Device, r); e != nil {
		return e
	}
	id, e := readIdentity(c)
	if e != nil || id != state.Identity {
		return errors.New("local identity changed")
	}
	var status struct {
		ID string `json:"myID"`
	}
	if e = local(c, "GET", "system/status", nil, &status); e != nil || status.ID != id {
		return errors.New("local API identity refused")
	}
	var cfg map[string]any
	if e = local(c, "GET", "config", nil, &cfg); e != nil {
		return e
	}
	// This state directory belongs solely to OrganisationOS. Never adopt an unrelated peer/folder.
	devices, _ := cfg["devices"].([]any)
	for _, item := range devices {
		d, ok := item.(map[string]any)
		if !ok || (d["deviceID"] != id && d["deviceID"] != c.Server) {
			return errors.New("unexpected peer retained for review")
		}
	}
	cfg["devices"] = []any{map[string]any{"deviceID": id, "name": "OrganisationOS local", "addresses": []string{"dynamic"}, "introducer": false, "autoAcceptFolders": false}, map[string]any{"deviceID": c.Server, "name": c.Name, "addresses": []string{c.Address}, "introducer": false, "autoAcceptFolders": false, "untrusted": false}}
	prior, _ := cfg["folders"].([]any)
	wanted := map[string]Folder{}
	for _, f := range r.Folders {
		wanted[f.ID] = f
	}
	next := []any{}
	retained := map[string]bool{}
	for _, item := range prior {
		f, ok := item.(map[string]any)
		if !ok {
			return errors.New("invalid local folder")
		}
		fid, _ := f["id"].(string)
		path, _ := f["path"].(string)
		w, active := wanted[fid]
		if !strings.HasPrefix(fid, "oos-") || !uuidPattern.MatchString(strings.TrimPrefix(fid, "oos-")) {
			return errors.New("unexpected local folder retained")
		}
		expected := filepath.Join(home(c), "Fichiers", strings.TrimPrefix(fid, "oos-"))
		if filepath.Clean(path) != expected {
			return errors.New("local folder relocation requires review")
		}
		if active {
			f["paused"] = false
			f["type"] = "sendreceive"
			f["devices"] = []any{map[string]any{"deviceID": id, "encryptionPassword": ""}, map[string]any{"deviceID": c.Server, "encryptionPassword": ""}}
			f["label"] = w.Label
			next = append(next, f)
			retained[fid] = true
		}
	}
	for _, f := range r.Folders {
		if retained[f.ID] {
			continue
		}
		path := filepath.Join(home(c), "Fichiers", f.Selection)
		if e = os.MkdirAll(path, 0700); e != nil {
			return e
		}
		if e = os.MkdirAll(filepath.Join(path, ".stfolder"), 0700); e != nil {
			return e
		}
		next = append(next, map[string]any{"id": f.ID, "label": f.Label, "path": path, "type": "sendreceive", "devices": []any{map[string]any{"deviceID": id, "encryptionPassword": ""}, map[string]any{"deviceID": c.Server, "encryptionPassword": ""}}, "rescanIntervalS": 60, "fsWatcherEnabled": true, "ignorePerms": true, "paused": false})
	}
	cfg["folders"] = next
	return local(c, "PUT", "config", cfg, nil)
}
func run(c Config, engine string) error {
	binary, readErr := os.ReadFile(engine)
	if readErr != nil || digest(binary) != engineSHA {
		return errors.New("installed engine integrity refused")
	}
	binary = nil
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	listener.Close() // lifecycle exclusivity is acquired by the platform lock below
	release, e := runLock(c)
	if e != nil {
		return e
	}
	defer release()
	command := exec.Command(engine, "serve", "--home", filepath.Join(home(c), "Etat"), "--no-browser", "--no-restart", "--no-upgrade", "--no-port-probing")
	hide(command)
	if e = command.Start(); e != nil {
		return e
	}
	defer command.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-done:
			return errors.New("local engine stopped; files retained")
		case <-timer.C:
			var state State
			if loadJSON(filepath.Join(home(c), "enrollment.json"), &state) == nil && uuidPattern.MatchString(state.Device) {
				path := "/api/v1/documents/offline/devices/" + state.Device + "/configuration"
				p, e := proof(c, state.Device, "GET", path, nil)
				var cfg Configuration
				if e == nil {
					e = portal(c, "GET", path, nil, p, &cfg)
				}
				if e == nil {
					e = configure(c, state, cfg)
				}
				status := "Synchronisation autorisée"
				if e != nil {
					status = "Connexion à vérifier ; fichiers et conflits conservés"
					_ = local(c, "PATCH", "config/devices/"+c.Server, map[string]any{"paused": true}, nil)
				}
				writeJSON(filepath.Join(home(c), "status.json"), map[string]any{"state": status, "checkedAt": time.Now().UTC().Format(time.RFC3339), "helperVersion": version})
			}
			timer.Reset(60 * time.Second)
		}
	}
}
func install(configFile string) error {
	var c Config
	if e := loadJSON(configFile, &c); e != nil {
		return e
	}
	if e := validate(c); e != nil {
		return e
	}
	if digest(engineBytes) != engineSHA {
		return errors.New("embedded engine integrity failed")
	}
	if os.Getenv("LOCALAPPDATA") == "" {
		return errors.New("local profile unavailable")
	}
	if e := os.MkdirAll(home(c), 0700); e != nil {
		return e
	}
	existing := filepath.Join(home(c), "organisation.json")
	if _, e := os.Stat(existing); e == nil {
		var old Config
		e := loadJSON(existing, &old)
		// Explicit configuration-only upgrade; preserve identity, enrollment, files and conflicts.
		if e == nil && old.Schema == 1 && old.API == "" {
			old.Schema = 2
			old.API = c.API
		}
		if e != nil || validate(old) != nil || old != c {
			return errors.New("existing organisation configuration differs; retained unchanged")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := writeJSON(existing, c); e != nil {
		return e
	}
	engine := filepath.Join(home(c), "engine-"+engineSHA+".exe")
	if b, e := os.ReadFile(engine); e == nil {
		if digest(b) != engineSHA {
			return errors.New("existing engine integrity failed")
		}
	} else if e = atomicWrite(engine, engineBytes, 0700); e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	self, e := os.ReadFile(exe)
	if e != nil {
		return e
	}
	release := filepath.Join(base(), "Releases", digest(self))
	if e = os.MkdirAll(release, 0700); e != nil {
		return e
	}
	installed := filepath.Join(release, "OrganisationOS-Syncthing.exe")
	if b, e := os.ReadFile(installed); e == nil {
		if digest(b) != digest(self) {
			return errors.New("helper integrity failed")
		}
	} else if e = atomicWrite(installed, self, 0700); e != nil {
		return e
	}
	if e = prepare(c, engine); e != nil {
		return e
	}
	if e = register(installed, c); e != nil {
		return e
	}
	command := exec.Command(installed, "run", c.Instance)
	hide(command)
	if e = command.Start(); e != nil {
		return e
	}
	return begin(c)
}
func main() {
	var err error
	args := os.Args[1:]
	if len(args) == 1 && strings.HasPrefix(args[0], "organisationos-syncthing:") {
		err = callback(args[0])
	} else if len(args) == 2 && args[0] == "run" {
		var c Config
		c, err = getConfig(args[1])
		if err == nil {
			err = run(c, filepath.Join(home(c), "engine-"+engineSHA+".exe"))
		}
	} else if len(args) == 2 && args[0] == "connect" {
		var c Config
		c, err = getConfig(args[1])
		if err == nil {
			err = begin(c)
		}
	} else if len(args) == 1 && args[0] == "--version" {
		fmt.Println(version)
		return
	} else if len(args) == 0 {
		exe, e := os.Executable()
		if e != nil {
			err = e
		} else {
			err = install(filepath.Join(filepath.Dir(exe), "organisation.json"))
		}
	} else {
		err = errors.New("invalid invocation")
	}
	if errors.Is(err, errRunning) {
		return
	}
	if err != nil {
		notify("Syncthing OrganisationOS", "L’opération n’a pas pu être terminée. Les identités, fichiers et conflits existants sont conservés. Reprenez la connexion depuis l’application ou contactez votre administrateur.")
		os.Exit(1)
	}
}
