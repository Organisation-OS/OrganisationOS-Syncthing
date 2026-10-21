// SPDX-License-Identifier: MPL-2.0
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func callbackFixture(t *testing.T) (Config, string, string) {
	t.Helper()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	c := fixtureConfig()
	dir := filepath.Join(home(c), "Etat")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	cert, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); e != nil {
		t.Fatal(e)
	}
	id, e := readIdentity(c)
	if e != nil {
		t.Fatal(e)
	}
	writeJSON(filepath.Join(home(c), "organisation.json"), c)
	writeJSON(filepath.Join(home(c), "pending.json"), Pending{strings.Repeat("a", 32), strings.Repeat("b", 64), id, time.Now().Add(time.Minute).Unix()})
	record := "11111111-1111-4111-8111-111111111111"
	raw := "organisationos-syncthing://enrollment?" + url.Values{"deviceId": {record}, "state": {strings.Repeat("a", 32)}, "code": {strings.Repeat("c", 43)}}.Encode()
	return c, record, raw
}
func TestCallbackFinalizationKeepsIdentity(t *testing.T) {
	c, record, raw := callbackFixture(t)
	old := client
	oldBrowser := openBrowser
	defer func() { client = old; openBrowser = oldBrowser }()
	before, _ := os.ReadFile(filepath.Join(home(c), "Etat", "cert.pem"))
	requests := 0
	client = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != "POST" || r.URL.Host != "portal.thecgp.com" || !strings.HasSuffix(r.URL.Path, "/exchange") {
			t.Fatal("wrong route")
		}
		var body map[string]json.RawMessage
		json.NewDecoder(r.Body).Decode(&body)
		if len(body) != 3 || body["proof"] == nil || body["verifier"] == nil || body["code"] == nil {
			t.Fatal("closed exchange shape")
		}
		data, _ := json.Marshal(map[string]any{"data": Configuration{"ACTIVE", record, Server{c.Server, c.Address}, []Folder{}}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
	})}
	openBrowser = func(u string) error {
		if u != c.Portal+"/documents/offline" {
			t.Fatal("foreign browser")
		}
		return nil
	}
	if e := callback(raw); e != nil {
		t.Fatal(e)
	}
	var s State
	if loadJSON(filepath.Join(home(c), "enrollment.json"), &s) != nil || s.Device != record {
		t.Fatal("final state absent")
	}
	after, _ := os.ReadFile(filepath.Join(home(c), "Etat", "cert.pem"))
	if string(before) != string(after) || requests != 1 {
		t.Fatal("identity changed or repeated exchange")
	}
	if _, e := os.Stat(filepath.Join(home(c), "pending.json")); !os.IsNotExist(e) {
		t.Fatal("pending not retired")
	}
}
func TestWindowsRootCallbackFinalizationKeepsIdentity(t *testing.T) {
	c, record, raw := callbackFixture(t)
	raw = strings.Replace(raw, "enrollment?", "enrollment/?", 1)
	old := client
	oldBrowser := openBrowser
	defer func() { client = old; openBrowser = oldBrowser }()
	before, _ := os.ReadFile(filepath.Join(home(c), "Etat", "cert.pem"))
	requests := 0
	client = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != "POST" || r.URL.Host != "portal.thecgp.com" || !strings.HasSuffix(r.URL.Path, "/exchange") {
			t.Fatal("wrong route")
		}
		var body map[string]json.RawMessage
		json.NewDecoder(r.Body).Decode(&body)
		if len(body) != 3 || body["proof"] == nil || body["verifier"] == nil || body["code"] == nil {
			t.Fatal("closed exchange shape")
		}
		data, _ := json.Marshal(map[string]any{"data": Configuration{"ACTIVE", record, Server{c.Server, c.Address}, []Folder{}}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
	})}
	openBrowser = func(u string) error {
		if u != c.Portal+"/documents/offline" {
			t.Fatal("foreign browser")
		}
		return nil
	}
	if e := callback(raw); e != nil {
		t.Fatal(e)
	}
	var s State
	if loadJSON(filepath.Join(home(c), "enrollment.json"), &s) != nil || s.Device != record {
		t.Fatal("final state absent")
	}
	after, _ := os.ReadFile(filepath.Join(home(c), "Etat", "cert.pem"))
	if string(before) != string(after) || requests != 1 {
		t.Fatal("identity changed or repeated exchange")
	}
	if _, e := os.Stat(filepath.Join(home(c), "pending.json")); !os.IsNotExist(e) {
		t.Fatal("pending not retired")
	}
}
func TestCallbackFailedExchangeRetainsStateAndBothHTTPStatuses(t *testing.T) {
	c, _, raw := callbackFixture(t)
	old := client
	defer func() { client = old }()
	requests := 0
	pending, _ := os.ReadFile(filepath.Join(home(c), "pending.json"))
	client = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		status := 403
		if r.Method == "GET" {
			status = 409
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("secret provider body")), Header: make(http.Header)}, nil
	})}
	e := callback(raw)
	var op *operationError
	if !errors.As(e, &op) || op.Stage != "EXCHANGE_RECOVERY" || op.HTTPStatus != 409 || op.PriorHTTPStatus != 403 || requests != 2 {
		t.Fatal("missing precise refusal", e)
	}
	after, _ := os.ReadFile(filepath.Join(home(c), "pending.json"))
	if string(pending) != string(after) {
		t.Fatal("pending changed")
	}
	if _, e := os.Stat(filepath.Join(home(c), "enrollment.json")); !os.IsNotExist(e) {
		t.Fatal("failed exchange enrolled")
	}
	persistDiagnostic(e)
	b, _ := os.ReadFile(filepath.Join(base(), "diagnostic.json"))
	for _, secret := range []string{raw, "secret provider body", strings.Repeat("b", 64), strings.Repeat("c", 43), "BEGIN CERTIFICATE"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("diagnostic leak")
		}
	}
}
func TestExpiredPendingHasNoNetworkAndRemains(t *testing.T) {
	c, _, raw := callbackFixture(t)
	var p Pending
	loadJSON(filepath.Join(home(c), "pending.json"), &p)
	p.Expires = time.Now().Add(-time.Minute).Unix()
	writeJSON(filepath.Join(home(c), "pending.json"), p)
	old := client
	defer func() { client = old }()
	client = &http.Client{Transport: captureTransport(func(*http.Request) (*http.Response, error) { t.Fatal("network on expired callback"); return nil, nil })}
	var op *operationError
	if e := callback(raw); !errors.As(e, &op) || op.Code != "PENDING_EXPIRED" {
		t.Fatal("expiry not classified", e)
	}
	if _, e := os.Stat(filepath.Join(home(c), "pending.json")); e != nil {
		t.Fatal(e)
	}
}
func TestDiagnosticNeverPersistsArbitraryErrorText(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	secret := "https://private.invalid/?token=NEVER_LOG_THIS"
	r := persistDiagnostic(errors.New(secret))
	b, e := os.ReadFile(filepath.Join(base(), "diagnostic.json"))
	if e != nil || strings.Contains(string(b), secret) || r.Code != "OPERATION_FAILED" || !strings.HasPrefix(r.Reference, "OOS-ST-") {
		t.Fatal("unsafe diagnostic")
	}
}
func TestReturnParserRefusesAlternateDestinations(t *testing.T) {
	for _, s := range []string{"https://enrollment?code=SECRET", "organisationos-syncthing://evil?code=SECRET", "organisationos-syncthing://user@enrollment?code=SECRET", "organisationos-syncthing://enrollment/other?code=SECRET"} {
		var e *operationError
		if !errors.As(callback(s), &e) || e.Stage != "RETURN_URI" {
			t.Fatal("unsafe return accepted")
		}
	}
}
func TestReadOnlyProbeSendsNoDeviceCredential(t *testing.T) {
	c, _, _ := callbackFixture(t)
	pending, _ := os.ReadFile(filepath.Join(home(c), "pending.json"))
	old := client
	defer func() { client = old }()
	n := 0
	client = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		n++
		if r.Method != "GET" || r.URL.Path != "/api/v1/documents/offline/devices" || r.Header.Get("X-OrganisationOS-Device-Proof") != "" || r.Header.Get("Cookie") != "" || r.ContentLength != 0 {
			t.Fatal("probe is not anonymous read-only")
		}
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	oldDiagnostic := persistDiagnostic(operationFailure("RETURN_URI", "INVALID_RETURN", nil))
	diagnose()
	after, _ := os.ReadFile(filepath.Join(home(c), "pending.json"))
	var d diagnosticReceipt
	loadJSON(filepath.Join(base(), "diagnostic-readonly.json"), &d)
	if string(pending) != string(after) || n != 1 || d.Code != "LOCAL_PROOF_AND_API_REACHABLE" || d.Reference == oldDiagnostic.Reference {
		t.Fatal("probe changed state or missing proof")
	}
}
func TestLostExchangeAcknowledgementRecoversWithoutSecondExchange(t *testing.T) {
	c, record, raw := callbackFixture(t)
	old := client
	oldBrowser := openBrowser
	defer func() { client = old; openBrowser = oldBrowser }()
	n := 0
	client = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		n++
		if n == 1 {
			return nil, errors.New("lost response with SECRET")
		}
		if n != 2 || r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/configuration") || r.Header.Get("X-OrganisationOS-Device-Proof") == "" {
			t.Fatal("recovery identity missing")
		}
		data, _ := json.Marshal(map[string]any{"data": Configuration{"ACTIVE", record, Server{c.Server, c.Address}, []Folder{}}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
	})}
	openBrowser = func(string) error { return nil }
	if e := callback(raw); e != nil {
		t.Fatal(e)
	}
	var state State
	if n != 2 || loadJSON(filepath.Join(home(c), "enrollment.json"), &state) != nil || state.Device != record {
		t.Fatal("recovery failed")
	}
}

func TestMalformedReturnsPreserveIdentityAndPending(t *testing.T) {
	for _, variant := range []string{"/other", "//", "/%2e", "/%2f", "%2f", "/../", ":443", "?extra=x", "?state=duplicate", "?code=duplicate", "?deviceId=duplicate", "?bad=%zz", "?bad=x;y", "#", "#fragment"} {
		t.Run(variant, func(t *testing.T) {
			c, _, raw := callbackFixture(t)
			cert, _ := os.ReadFile(filepath.Join(home(c), "Etat", "cert.pem"))
			pending, _ := os.ReadFile(filepath.Join(home(c), "pending.json"))
			if strings.HasPrefix(variant, "?") {
				raw += "&" + variant[1:]
			} else if strings.HasPrefix(variant, "#") {
				raw += variant
			} else {
				raw = strings.Replace(raw, "enrollment?", "enrollment"+variant+"?", 1)
			}
			old := client
			defer func() { client = old }()
			client = &http.Client{Transport: captureTransport(func(*http.Request) (*http.Response, error) { t.Fatal("network on malformed return"); return nil, nil })}
			var op *operationError
			if e := callback(raw); !errors.As(e, &op) || op.Stage != "RETURN_URI" {
				t.Fatal("malformed return accepted", e)
			}
			afterCert, _ := os.ReadFile(filepath.Join(home(c), "Etat", "cert.pem"))
			afterPending, _ := os.ReadFile(filepath.Join(home(c), "pending.json"))
			if string(cert) != string(afterCert) || string(pending) != string(afterPending) {
				t.Fatal("local state changed")
			}
		})
	}
}

func TestReadOnlyDiagnosticWriteFailureIsExplicit(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if e := os.MkdirAll(filepath.Join(base(), "diagnostic-readonly.json"), 0700); e != nil {
		t.Fatal(e)
	}
	r, e := persistDiagnosticFile(operationFailure("READ_ONLY_DIAGNOSTIC", "LOCAL_PROOF_AND_API_REACHABLE", nil), "diagnostic-readonly.json")
	if e == nil || r.Reference == "" || r.At == "" {
		t.Fatal("write failure hidden")
	}
}
