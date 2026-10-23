// SPDX-License-Identifier: MPL-2.0
package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func devFixture(t *testing.T) (devTrust, Config, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	trust := devTrust{"oos-helper-dev-trust-v1", true, "dev", base64.StdEncoding.EncodeToString(pub), "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "https://dev.synthetic.invalid:18443", "syncthing", 1, now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)}
	c := Config{2, trust.InstanceID, "https://portal.synthetic.invalid", trust.APIOrigin, "Synthetic", strings.Repeat("AAAAAAA-", 7) + "AAAAAAA", "tcp://sync.synthetic.invalid:22223"}
	return trust, c, key, now
}

func signedDev(t *testing.T, trust devTrust, c Config, key ed25519.PrivateKey, sequence int64, pack, helper, audience string) []byte {
	t.Helper()
	pub, _ := base64.StdEncoding.DecodeString(trust.PublicKey)
	v := map[string]any{"schema": "oos-signed-v1", "purpose": "organisation-employee-software-v1", "algorithm": "Ed25519", "issuer": digest(pub), "payload": map[string]any{"schema": "oos-employee-software-release-v1", "installationId": trust.InstallationID, "instanceId": trust.InstanceID, "applicationId": trust.ApplicationID, "sequence": sequence, "operation": "install", "package": map[string]any{"sha256": pack, "provenance": map[string]any{"schema": "oos-employee-build-provenance-v1", "installerVersion": version, "admissionAudience": audience, "engineVersion": "v2.1.6-oos.2", "engineWindowsSha256": engineSHA, "installerSha256": helper, "configuration": c}}}}
	// Synthetic ASCII-only fixture: sorted maps match the native Python encoding.
	raw, _ := json.Marshal(v)
	json.Unmarshal(raw, &v)
	raw, _ = json.Marshal(v)
	v["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))
	raw, _ = json.Marshal(v)
	return raw
}

func TestDEVTrustDoesNotWidenLegacy(t *testing.T) {
	trust, c, key, now := devFixture(t)
	if validate(c) == nil {
		t.Fatal("unsigned DEV config admitted")
	}
	raw, _ := json.Marshal(trust)
	if _, e := readDevTrust(raw, now); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"27c0be38-60bd-4dce-bb28-ef0088716a25", "b7a1f6b1-c4aa-4de7-95fb-29d509d3398d"} {
		bad := trust
		bad.InstanceID = id
		encoded, _ := json.Marshal(bad)
		if _, e := readDevTrust(encoded, now); e == nil {
			t.Fatal("DEV overrides legacy", id)
		}
	}
	for _, mutate := range []func(*devTrust){func(p *devTrust) { p.Enabled = false }, func(p *devTrust) { p.Audience = "production" }, func(p *devTrust) { p.ExpiresAt = now.Format(time.RFC3339) }, func(p *devTrust) { p.NotBefore = now.Add(time.Minute).Format(time.RFC3339) }, func(p *devTrust) { p.ExpiresAt = now.Add(25 * time.Hour).Format(time.RFC3339) }, func(p *devTrust) { p.PublicKey = "untrusted" }} {
		bad := trust
		mutate(&bad)
		encoded, _ := json.Marshal(bad)
		if _, e := readDevTrust(encoded, now); e == nil {
			t.Fatal("bad trust admitted")
		}
	}
	hash := strings.Repeat("a", 64)
	for _, audience := range []string{"production", "", "DEV"} {
		if _, e := verifyDev(signedDev(t, trust, c, key, 1, hash, hash, audience), trust, hash, hash, now); e == nil {
			t.Fatal("wrong audience")
		}
	}
	if _, e := readDevTrust([]byte(`{"schema":"oos-helper-dev-trust-v1","enabled":false}`), now); e == nil {
		t.Fatal("repository must not enable operational DEV admission")
	}
}

func TestDEVReceiptsRejectReplayAndRetainHistory(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	trust, c, key, now := devFixture(t)
	hash := strings.Repeat("a", 64)
	first := signedDev(t, trust, c, key, 1, hash, hash, "dev")
	second := signedDev(t, trust, c, key, 2, hash, hash, "dev")
	for _, raw := range [][]byte{first, first, second, second} {
		if e := storeDevReceipt(trust, raw, hash, hash, now); e != nil {
			t.Fatal(e)
		}
	}
	entries, _ := os.ReadDir(receiptDirectory(trust))
	if len(entries) != 2 {
		t.Fatal("receipts replaced or duplicated")
	}
	if e := storeDevReceipt(trust, first, hash, hash, now); e == nil {
		t.Fatal("rollback accepted")
	}
	changed := c
	changed.Name = "Changed"
	if e := storeDevReceipt(trust, signedDev(t, trust, changed, key, 2, hash, hash, "dev"), hash, hash, now); e == nil {
		t.Fatal("same sequence different content")
	}
	os.WriteFile(filepath.Join(receiptDirectory(trust), "partial.json"), []byte("{"), 0600)
	if _, e := latestDevReceipt(trust, hash, now); e == nil {
		t.Fatal("partial history ignored")
	}
}

func devZip(t *testing.T, c Config, helper []byte, extra bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	config, _ := json.Marshal(c)
	for _, item := range []struct {
		name string
		data []byte
	}{{"organisation.json", config}, {"OrganisationOS-Syncthing-Installer.exe", helper}} {
		f, e := z.Create(item.name)
		if e != nil {
			t.Fatal(e)
		}
		f.Write(item.data)
	}
	if extra {
		f, _ := z.Create("../escape")
		f.Write([]byte("refused"))
	}
	z.Close()
	return buf.Bytes()
}

func TestDEVExactArchiveAndInstalledBinding(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	trust, c, key, now := devFixture(t)
	hash, e := selfSHA()
	if e != nil {
		t.Fatal(e)
	}
	syntheticHelper := []byte("synthetic helper bytes, never executed")
	archive := devZip(t, c, syntheticHelper, false)
	raw := signedDev(t, trust, c, key, 1, digest(archive), digest(syntheticHelper), "dev")
	a, e := verifyDev(raw, trust, digest(archive), digest(syntheticHelper), now)
	if e != nil {
		t.Fatal(e)
	}
	if e = verifyDevArchive(archive, a, digest(syntheticHelper)); e != nil {
		t.Fatal(e)
	}
	if verifyDevArchive(devZip(t, c, syntheticHelper, true), a, digest(syntheticHelper)) == nil {
		t.Fatal("traversal accepted")
	}
	if verifyDevArchive(archive, a, hash) == nil {
		t.Fatal("foreign executable accepted")
	}
	raw = signedDev(t, trust, c, key, 1, strings.Repeat("a", 64), hash, "dev")
	if e = storeDevReceipt(trust, raw, strings.Repeat("a", 64), hash, now); e != nil {
		t.Fatal(e)
	}
	old := devTrustBytes
	devTrustBytes, _ = json.Marshal(trust)
	defer func() { devTrustBytes = old }()
	if e = writeJSON(filepath.Join(home(c), "organisation.json"), c); e != nil {
		t.Fatal(e)
	}
	if got, e := getConfig(c.Instance); e != nil || got != c {
		t.Fatal("installed admission", e)
	}
	c.API = "https://foreign.synthetic.invalid"
	writeJSON(filepath.Join(home(c), "organisation.json"), c)
	if _, e = getConfig(c.Instance); e == nil {
		t.Fatal("config replacement accepted")
	}
	if e = installDev("missing.zip", "missing.json"); e == nil {
		t.Fatal("missing package accepted")
	}
}

func TestDEVUnadmittedInstallHasNoSideEffects(t *testing.T) {
	old := devTrustBytes
	devTrustBytes = []byte(`{"schema":"oos-helper-dev-trust-v1","enabled":false}`)
	defer func() { devTrustBytes = old }()
	profile := t.TempDir()
	t.Setenv("LOCALAPPDATA", profile)
	if e := installDev("missing.zip", "missing.json"); e == nil {
		t.Fatal("unadmitted install")
	}
	entries, e := os.ReadDir(profile)
	if e != nil || len(entries) != 0 {
		t.Fatal("profile changed before admission")
	}
}

func TestDEVRejectedSignedInstallHasNoSideEffects(t *testing.T) {
	profile := t.TempDir()
	t.Setenv("LOCALAPPDATA", profile)
	trust, c, key, _ := devFixture(t)
	old := devTrustBytes
	devTrustBytes, _ = json.Marshal(trust)
	defer func() { devTrustBytes = old }()
	archive := devZip(t, c, []byte("foreign helper; never executed"), false)
	hash, e := selfSHA()
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	pack := filepath.Join(dir, "package.zip")
	manifest := filepath.Join(dir, "manifest.json")
	os.WriteFile(pack, archive, 0600)
	for _, raw := range [][]byte{[]byte(`{"signature":"invalid"}`), signedDev(t, trust, c, key, 1, digest(archive), hash, "production"), signedDev(t, trust, c, key, 1, digest(archive), hash, "dev")} {
		os.WriteFile(manifest, raw, 0600)
		if installDev(pack, manifest) == nil {
			t.Fatal("foreign bundle admitted")
		}
		entries, _ := os.ReadDir(profile)
		if len(entries) != 0 {
			t.Fatal("profile written before signature/archive admission")
		}
	}
}

func TestDEVHistoryQuotaMissingAndExpiry(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	trust, c, key, now := devFixture(t)
	hash := strings.Repeat("a", 64)
	for seq := int64(1); seq <= 64; seq++ {
		if e := storeDevReceipt(trust, signedDev(t, trust, c, key, seq, hash, hash, "dev"), hash, hash, now); e != nil {
			t.Fatal(seq, e)
		}
	}
	if storeDevReceipt(trust, signedDev(t, trust, c, key, 65, hash, hash, "dev"), hash, hash, now) == nil {
		t.Fatal("unbounded history")
	}
	if _, e := latestDevReceipt(trust, hash, now.Add(2*time.Hour)); e == nil {
		t.Fatal("expired admission reused")
	}
	old := devTrustBytes
	devTrustBytes, _ = json.Marshal(trust)
	defer func() { devTrustBytes = old }()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	os.MkdirAll(home(c), 0700)
	writeJSON(filepath.Join(home(c), "organisation.json"), c)
	if _, e := getConfig(c.Instance); e == nil {
		t.Fatal("missing history after installation ignored")
	}
}

func TestDEVInstallMutexAndUnsafePaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows lifecycle mutex")
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	trust, _, _, _ := devFixture(t)
	release, e := devInstallLock(trust.InstanceID)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if second, e := devInstallLock(trust.InstanceID); e == nil {
		second()
		t.Fatal("concurrent install accepted")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.Mkdir(target, 0700)
	link := filepath.Join(dir, "link")
	if e = os.Symlink(target, link); e != nil {
		t.Skip("Windows symlink privilege unavailable; mutex tested")
	}
	if safeDevPath(filepath.Join(link, "new-file")) == nil {
		t.Fatal("linked ancestor accepted")
	}
}

func TestDEVRealEngineStopsAtAdmissionDeadline(t *testing.T) {
	engine := os.Getenv("OOS_TEST_ENGINE")
	if engine == "" {
		t.Skip("requires explicit isolated native engine")
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	trust, c, key, _ := devFixture(t)
	os.MkdirAll(home(c), 0700)
	if e := prepare(c, engine); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	trust.ExpiresAt = now.Add(2 * time.Second).Format(time.RFC3339Nano)
	hash, e := selfSHA()
	if e != nil {
		t.Fatal(e)
	}
	raw := signedDev(t, trust, c, key, 1, strings.Repeat("a", 64), hash, "dev")
	if e = storeDevReceipt(trust, raw, strings.Repeat("a", 64), hash, now); e != nil {
		t.Fatal(e)
	}
	old := devTrustBytes
	devTrustBytes, _ = json.Marshal(trust)
	defer func() { devTrustBytes = old }()
	writeJSON(filepath.Join(home(c), "organisation.json"), c)
	started := time.Now()
	e = run(c, engine)
	if e == nil || e.Error() != "local engine stopped; files retained" || time.Since(started) < time.Second || time.Since(started) > 5*time.Second {
		t.Fatal("deadline did not terminate engine", e)
	}
	if validateInstalled(c) == nil {
		t.Fatal("expired configuration retained authority")
	}
	// TempDir cleanup must succeed: no child may retain the database file handle.
}
