// SPDX-License-Identifier: MPL-2.0
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func pilotFixture(t *testing.T) (devTrust, Config, []byte, time.Time) {
	a, c, _, now := devFixture(t)
	a.Schema, a.Audience = "oos-helper-pilot-anchor-v1", "pilot"
	a.InstanceID = "27c0be38-60bd-4dce-bb28-ef0088716a25"
	c.Instance = a.InstanceID
	a.PortalOrigin, a.PublicEndpoint = c.Portal, c.Address
	raw, _ := json.Marshal(pilotTrust{"oos-helper-pilot-trust-v1", true, []devTrust{a}})
	return a, c, raw, now
}
func TestPilotAnchorsClosedAndFresh(t *testing.T) {
	a, _, raw, now := pilotFixture(t)
	if _, e := readPilotTrust(raw, a.InstanceID, now); e != nil {
		t.Fatal(e)
	}
	if _, e := readDevTrust(mustJSON(a), now); e == nil {
		t.Fatal("pilot accepted as DEV")
	}
	for name, change := range map[string]func(*devTrust){
		"expired":  func(p *devTrust) { p.ExpiresAt = now.Format(time.RFC3339) },
		"future":   func(p *devTrust) { p.NotBefore = now.Add(time.Minute).Format(time.RFC3339) },
		"overlong": func(p *devTrust) { p.ExpiresAt = now.Add(31 * 24 * time.Hour).Format(time.RFC3339) },
		"http":     func(p *devTrust) { p.PortalOrigin = "http://synthetic.invalid" },
		"redirect": func(p *devTrust) { p.APIOrigin = "https://synthetic.invalid/a" },
		"userinfo": func(p *devTrust) { p.PortalOrigin = "https://user@synthetic.invalid" },
		"endpoint": func(p *devTrust) { p.PublicEndpoint = "tcp://synthetic.invalid:22000/path" },
		"audience": func(p *devTrust) { p.Audience = "dev" },
		"key":      func(p *devTrust) { p.PublicKey = "untrusted" },
	} {
		b := a
		change(&b)
		if _, e := readPilotTrust(mustJSON(pilotTrust{"oos-helper-pilot-trust-v1", true, []devTrust{b}}), a.InstanceID, now); e == nil {
			t.Fatal(name)
		}
	}
	for _, bad := range [][]byte{append(raw, raw...), []byte(strings.Replace(string(raw), `"enabled":true`, `"enabled":false,"enabled":true`, 1)), mustJSON(pilotTrust{"oos-helper-pilot-trust-v1", true, []devTrust{a, a}}), mustJSON(pilotTrust{"oos-helper-pilot-trust-v1", true, nil})} {
		if _, e := readPilotTrust(bad, a.InstanceID, now); e == nil {
			t.Fatal("ambiguous policy")
		}
	}
	b := a
	b.InstallationID = "33333333-3333-4333-8333-333333333333"
	b.InstanceID = "b7a1f6b1-c4aa-4de7-95fb-29d509d3398d"
	raw = mustJSON(pilotTrust{"oos-helper-pilot-trust-v1", true, []devTrust{a, b}})
	for _, id := range []string{a.InstanceID, b.InstanceID} {
		got, e := readPilotTrust(raw, id, now)
		if e != nil || got.InstanceID != id {
			t.Fatal("multi instance", e)
		}
	}
	if _, e := readPilotTrust(raw, "44444444-4444-4444-8444-444444444444", now); e == nil {
		t.Fatal("unknown instance")
	}
}
func mustJSON(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func TestPilotSignatureDestinationsAndReplay(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	a, c, key, now := devFixture(t)
	a.Schema, a.Audience = "oos-helper-pilot-anchor-v1", "pilot"
	a.InstanceID = "27c0be38-60bd-4dce-bb28-ef0088716a25"
	c.Instance = a.InstanceID
	a.PortalOrigin, a.PublicEndpoint = c.Portal, c.Address
	hash := strings.Repeat("a", 64)
	raw := signedDev(t, a, c, key, 2, hash, hash, "pilot")
	if _, e := verifyDev(raw, a, hash, hash, now); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Config){func(v *Config) { v.Instance = "b7a1f6b1-c4aa-4de7-95fb-29d509d3398d" }, func(v *Config) { v.API = "https://other.invalid" }, func(v *Config) { v.Portal = "https://other.invalid" }, func(v *Config) { v.Address = "tcp://other.invalid:22000" }} {
		bad := c
		mutate(&bad)
		if _, e := verifyDev(signedDev(t, a, bad, key, 2, hash, hash, "pilot"), a, hash, hash, now); e == nil {
			t.Fatal("signed wrong destination")
		}
	}
	if _, e := verifyDev(signedDev(t, a, c, key, 2, hash, hash, "dev"), a, hash, hash, now); e == nil {
		t.Fatal("DEV relabel")
	}
	if e := storeDevReceipt(a, raw, hash, hash, now); e != nil {
		t.Fatal(e)
	}
	if e := storeDevReceipt(a, signedDev(t, a, c, key, 1, hash, hash, "pilot"), hash, hash, now); e == nil {
		t.Fatal("replay")
	}
	if _, e := os.Stat(filepath.Join(base(), "Organisations", a.InstanceID, "AdmissionDEV")); !os.IsNotExist(e) {
		t.Fatal("DEV history touched")
	}
	if _, e := latestDevReceipt(a, hash, now.Add(2*time.Hour)); e == nil {
		t.Fatal("expired receipt")
	}
}
func TestPilotNoHistoricalUnsignedFallback(t *testing.T) {
	a, c, raw, _ := pilotFixture(t)
	old := pilotTrustBytes
	pilotTrustBytes = raw
	defer func() { pilotTrustBytes = old }()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if validateInstalled(c) == nil {
		t.Fatal("unsigned pilot accepted")
	}
	if installPilot(a.InstanceID, "absent.zip", "absent.json") == nil {
		t.Fatal("unadmitted install")
	}
	if _, e := os.Stat(base()); !os.IsNotExist(e) {
		t.Fatal("failed admission wrote state")
	}
	pilotTrustBytes = []byte(`{"broken":true}`)
	if validateInstalled(c) == nil {
		t.Fatal("malformed trust fell back")
	}
}

func TestPilotRealEngineExpiresAndRetainsFiles(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("requires native Windows lifecycle lock; Linux engine transport alone is insufficient")
	}
	engine := os.Getenv("OOS_TEST_ENGINE")
	if engine == "" {
		t.Skip("requires explicit isolated native engine")
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	a, c, key, _ := devFixture(t)
	a.Schema, a.Audience = "oos-helper-pilot-anchor-v1", "pilot"
	a.InstanceID = "27c0be38-60bd-4dce-bb28-ef0088716a25"
	c.Instance = a.InstanceID
	a.PortalOrigin, a.PublicEndpoint = c.Portal, c.Address
	if e := os.MkdirAll(home(c), 0700); e != nil {
		t.Fatal(e)
	}
	if e := prepare(c, engine); e != nil {
		t.Fatal(e)
	}
	canary := filepath.Join(home(c), "preserve-local-write.txt")
	os.WriteFile(canary, []byte("synthetic-write"), 0600)
	now := time.Now().UTC()
	deadline := now.Add(10 * time.Second)
	a.ExpiresAt = deadline.Format(time.RFC3339Nano)
	hash, e := selfSHA()
	if e != nil {
		t.Fatal(e)
	}
	raw := signedDev(t, a, c, key, 1, strings.Repeat("a", 64), hash, "pilot")
	if e = storeDevReceipt(a, raw, strings.Repeat("a", 64), hash, now); e != nil {
		t.Fatal(e)
	}
	old := pilotTrustBytes
	pilotTrustBytes = mustJSON(pilotTrust{"oos-helper-pilot-trust-v1", true, []devTrust{a}})
	defer func() { pilotTrustBytes = old }()
	writeJSON(filepath.Join(home(c), "organisation.json"), c)
	e = run(c, engine)
	if e == nil || e.Error() != "local engine stopped; files retained" || time.Now().Before(deadline) || time.Since(deadline) > 5*time.Second {
		t.Fatal("pilot expiration", e)
	}
	if validateInstalled(c) == nil {
		t.Fatal("expired pilot authority")
	}
	kept, e := os.ReadFile(canary)
	if e != nil || string(kept) != "synthetic-write" {
		t.Fatal("local writes changed")
	}
}
