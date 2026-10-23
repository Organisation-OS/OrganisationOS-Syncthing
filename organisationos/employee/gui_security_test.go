// SPDX-License-Identifier: MPL-2.0
package main

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRealEngineGUIProtectionAndUpgrade(t *testing.T) {
	engine := os.Getenv("OOS_TEST_ENGINE")
	if engine == "" {
		t.Skip("requires explicit isolated native engine")
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	c := fixtureConfig()
	if e := os.MkdirAll(home(c), 0700); e != nil {
		t.Fatal(e)
	}
	if e := prepare(c, engine); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(home(c), "Etat")
	cert, _ := os.ReadFile(filepath.Join(dir, "cert.pem"))
	key, _ := os.ReadFile(filepath.Join(dir, "key.pem"))
	id, e := readIdentity(c)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "config.xml"))
	var cfg Node
	if e = xml.Unmarshal(raw, &cfg); e != nil {
		t.Fatal(e)
	}
	gui := child(&cfg, "gui")
	hash := child(gui, "password").Text
	apiKey := child(gui, "apikey").Text
	if child(gui, "user").Text != "OrganisationOS" || !passwordHashPattern.MatchString(hash) {
		t.Fatal("new installation not protected before launch")
	}
	if len(apiKey) < 20 {
		t.Fatal("missing unique API key")
	}
	cmd := engineServeCommand(c, engine)
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	ready := false
	for i := 0; i < 100; i++ {
		if local(c, "GET", "system/status", nil, nil) == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated engine unavailable")
	}
	baseURL := "http://" + child(gui, "address").Text
	anonymous := func() {
		t.Helper()
		r, e := http.Get(baseURL + "/rest/system/status")
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode != 403 && r.StatusCode != 401 {
			t.Fatal("anonymous administration accepted", r.StatusCode)
		}
	}
	anonymous()
	if e = secureGUI(c); e != nil {
		t.Fatal(e)
	}
	// Reproduce the old installer: remove GUI authentication through the native API.
	if e = local(c, "PATCH", "config/gui", map[string]any{"user": "", "password": "", "insecureAdminAccess": true, "metricsWithoutAuth": true}, nil); e != nil {
		t.Fatal(e)
	}
	time.Sleep(250 * time.Millisecond)
	var before map[string]any
	if e = local(c, "GET", "config", nil, &before); e != nil {
		t.Fatal(e)
	}
	sentinel := filepath.Join(home(c), "Fichiers", "synthetic.sync-conflict-test.txt")
	os.MkdirAll(filepath.Dir(sentinel), 0700)
	os.WriteFile(sentinel, []byte("synthetic conflict retained"), 0600)
	writeJSON(filepath.Join(home(c), "enrollment.json"), State{"11111111-1111-4111-8111-111111111111", id})
	enrollment, _ := os.ReadFile(filepath.Join(home(c), "enrollment.json"))
	if e = secureGUI(c); e != nil {
		t.Fatal(e)
	}
	anonymous()
	var after map[string]any
	if e = local(c, "GET", "config", nil, &after); e != nil {
		t.Fatal(e)
	}
	for _, k := range []string{"devices", "folders", "options"} {
		if !reflect.DeepEqual(before[k], after[k]) {
			t.Fatal("unrelated configuration changed", k)
		}
	}
	gotGUI := after["gui"].(map[string]any)
	if gotGUI["apiKey"] != apiKey || !passwordHashPattern.MatchString(gotGUI["password"].(string)) {
		t.Fatal("API key changed or password not hashed")
	}
	if e = secureGUI(c); e != nil {
		t.Fatal(e)
	}
	var replay map[string]any
	local(c, "GET", "config/gui", nil, &replay)
	if !reflect.DeepEqual(gotGUI, replay) {
		t.Fatal("protection replay rotated settings")
	}
	for _, p := range []struct {
		name string
		data []byte
	}{{"Etat/cert.pem", cert}, {"Etat/key.pem", key}, {"enrollment.json", enrollment}, {"Fichiers/synthetic.sync-conflict-test.txt", []byte("synthetic conflict retained")}} {
		got, _ := os.ReadFile(filepath.Join(home(c), p.name))
		if string(got) != string(p.data) {
			t.Fatal("state changed", p.name)
		}
	}
	// Distinct installation produces a distinct password hash and API key.
	c2 := c
	c2.Instance = "11111111-1111-4111-8111-111111111111"
	os.MkdirAll(home(c2), 0700)
	if e = prepare(c2, engine); e != nil {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(filepath.Join(home(c2), "Etat", "config.xml"))
	var cfg2 Node
	xml.Unmarshal(raw, &cfg2)
	if child(child(&cfg2, "gui"), "password").Text == hash || child(child(&cfg2, "gui"), "apikey").Text == apiKey {
		t.Fatal("common installation credential")
	}
}

func TestResumeEnrollmentUsesExistingProofWithoutNewCode(t *testing.T) {
	c, record, _ := callbackFixture(t)
	id, _ := readIdentity(c)
	writeJSON(filepath.Join(home(c), "enrollment.json"), State{record, id})
	old, oldBrowser := client, openBrowser
	defer func() { client = old; openBrowser = oldBrowser }()
	count := 0
	client = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		count++
		if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/"+record+"/configuration") {
			t.Fatal("new enrollment attempted")
		}
		data, _ := json.Marshal(map[string]any{"data": Configuration{"ACTIVE", record, Server{c.Server, c.Address}, []Folder{}}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
	})}
	opened := false
	openBrowser = func(u string) error { opened = u == c.Portal+"/documents/offline"; return nil }
	if yes, e := resumeEnrollment(c); !yes || e != nil || !opened || count != 1 {
		t.Fatal("existing enrollment not resumed", e)
	}
	writeJSON(filepath.Join(home(c), "enrollment.json"), State{record, "different"})
	if yes, e := resumeEnrollment(c); !yes || e == nil || count != 1 {
		t.Fatal("identity mismatch not refused")
	}
}
