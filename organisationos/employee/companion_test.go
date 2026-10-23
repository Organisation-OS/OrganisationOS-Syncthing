// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func clientResult(t *testing.T, args []string, input string, wantCode int) map[string]any {
	t.Helper()
	var out bytes.Buffer
	handled, code := clientInvocation(args, strings.NewReader(input), &out)
	if !handled || code != wantCode || out.Len() > 8192 {
		t.Fatal("client invocation status", handled, code)
	}
	var value map[string]any
	if json.Unmarshal(out.Bytes(), &value) != nil || value["schema"] != "oos-syncthing-client-result-v1" || value["helperVersion"] != version {
		t.Fatal("client result contract")
	}
	return value
}

func windowsClient(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("native Windows lifecycle mutex required")
	}
}

func TestClientInvocationClosedAndLegacyUnchanged(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	var out bytes.Buffer
	if handled, _ := clientInvocation([]string{"connect", "legacy"}, strings.NewReader(""), &out); handled || out.Len() != 0 {
		t.Fatal("legacy invocation intercepted")
	}
	for _, args := range [][]string{{"install-dev-client"}, {"connect-client"}, {"callback-client", "not-an-instance", "secret-not-on-stdout"}} {
		value := clientResult(t, args, "", 1)
		if value["status"] != "FAILED" || value["portalUri"] != nil {
			t.Fatal("failure claimed an intent")
		}
		raw, _ := json.Marshal(value)
		if strings.Contains(string(raw), "secret-not-on-stdout") {
			t.Fatal("argument leaked")
		}
	}
}

func TestClientInstallRetainsNativeAdmissionBeforeIdentity(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	value := clientResult(t, []string{"install-dev-client", "absent-package.zip", "absent-envelope.json"}, "", 1)
	if value["status"] != "FAILED" {
		t.Fatal("invalid package admitted")
	}
	if _, err := os.Stat(filepath.Join(base(), "Organisations")); !os.IsNotExist(err) {
		t.Fatal("identity written before admission")
	}
}

func TestClientConnectNativePKCEWithoutDefaultBrowser(t *testing.T) {
	windowsClient(t)
	c, _, _ := callbackFixture(t)
	old, oldBrowser, oldNotify := client, openBrowser, showNotification
	defer func() { client, openBrowser, showNotification = old, oldBrowser, oldNotify }()
	client = &http.Client{Transport: captureTransport(func(*http.Request) (*http.Response, error) { t.Fatal("network during begin"); return nil, nil })}
	openBrowser = func(string) error { t.Fatal("default browser invoked"); return nil }
	showNotification = func(string, string) { t.Fatal("machine invocation opened modal") }
	value := clientResult(t, []string{"connect-client", c.Instance}, "", 0)
	u, err := url.Parse(value["portalUri"].(string))
	if err != nil || u.Scheme+"://"+u.Host != c.Portal || u.Path != "/documents/offline/enroll" {
		t.Fatal("native portal URI")
	}
	var pending Pending
	if loadJSON(filepath.Join(home(c), "pending.json"), &pending) != nil {
		t.Fatal("pending absent")
	}
	q := u.Query()
	if q.Get("state") != pending.State || q.Get("challenge") != digest([]byte(pending.Verifier)) || q.Get("device") != pending.Identity {
		t.Fatal("native PKCE binding changed")
	}
	raw, _ := json.Marshal(value)
	if strings.Contains(string(raw), pending.Verifier) {
		t.Fatal("private verifier escaped")
	}
}

func TestClientCallbackBoundToSelectedInstance(t *testing.T) {
	windowsClient(t)
	c, _, raw := callbackFixture(t)
	other := c
	other.Instance = "b7a1f6b1-c4aa-4de7-95fb-29d509d3398d"
	other.Portal = "https://portal.villesadp.ca"
	other.API = "https://api.villesadp.ca"
	other.Address = "tcp://syncthing.villesadp.ca:22000"
	os.MkdirAll(home(other), 0700)
	writeJSON(filepath.Join(home(other), "organisation.json"), other)
	before, _ := os.ReadFile(filepath.Join(home(c), "pending.json"))
	old := client
	defer func() { client = old }()
	client = &http.Client{Transport: captureTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("foreign callback reached network")
		return nil, nil
	})}
	value := clientResult(t, []string{"callback-client", other.Instance}, raw, 1)
	encoded, _ := json.Marshal(value)
	if value["portalUri"] != nil || strings.Contains(string(encoded), strings.Repeat("c", 43)) {
		t.Fatal("callback secret leaked")
	}
	after, _ := os.ReadFile(filepath.Join(home(c), "pending.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("foreign pending changed")
	}
	clientResult(t, []string{"callback-client", c.Instance}, strings.Repeat("x", 4097), 1)
}

func TestClientCallbackStdinUsesNativeProofAndFinalization(t *testing.T) {
	windowsClient(t)
	c, record, raw := callbackFixture(t)
	old, oldBrowser := client, openBrowser
	defer func() { client, openBrowser = old, oldBrowser }()
	requests := 0
	client = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/"+record+"/exchange") {
			t.Fatal("wrong native exchange")
		}
		var body map[string]json.RawMessage
		json.NewDecoder(r.Body).Decode(&body)
		if len(body) != 3 || body["proof"] == nil || body["verifier"] == nil || body["code"] == nil {
			t.Fatal("native exchange contract changed")
		}
		data, _ := json.Marshal(map[string]any{"data": Configuration{"ACTIVE", record, Server{c.Server, c.Address}, []Folder{}}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}
	openBrowser = func(string) error { t.Fatal("default browser invoked"); return nil }
	value := clientResult(t, []string{"callback-client", c.Instance}, raw, 0)
	if value["portalUri"] != c.Portal+"/documents/offline" || requests != 1 {
		t.Fatal("native finalization intent")
	}
	var state State
	if loadJSON(filepath.Join(home(c), "enrollment.json"), &state) != nil || state.Device != record {
		t.Fatal("native enrollment absent")
	}
	if _, err := os.Stat(filepath.Join(home(c), "pending.json")); !os.IsNotExist(err) {
		t.Fatal("pending retained after confirmed exchange")
	}
}

func TestClientResumeRequiresCurrentDeviceProof(t *testing.T) {
	windowsClient(t)
	c, record, _ := callbackFixture(t)
	id, _ := readIdentity(c)
	writeJSON(filepath.Join(home(c), "enrollment.json"), State{record, id})
	before, _ := os.ReadFile(filepath.Join(home(c), "pending.json"))
	old := client
	defer func() { client = old }()
	status := 200
	client = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/configuration") {
			t.Fatal("unexpected enrollment")
		}
		data, _ := json.Marshal(map[string]any{"data": Configuration{"ACTIVE", record, Server{c.Server, c.Address}, []Folder{}}})
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}
	value := clientResult(t, []string{"connect-client", c.Instance}, "", 0)
	if value["portalUri"] != c.Portal+"/documents/offline" {
		t.Fatal("new enrollment instead of resume")
	}
	status = 403
	value = clientResult(t, []string{"connect-client", c.Instance}, "", 1)
	if value["portalUri"] != nil {
		t.Fatal("revocation emitted approval")
	}
	after, _ := os.ReadFile(filepath.Join(home(c), "pending.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("resume replaced pending")
	}
}
