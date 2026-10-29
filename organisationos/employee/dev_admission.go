// SPDX-License-Identifier: MPL-2.0
package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"organisationos.local/offline-employee/internal/admission"
)

// This PUBLIC build input is disabled in source control. Only the native CP
// factory may bind it to an independently admitted DEV installation. It never
// comes from the untrusted software archive or the command line.
//
//go:embed dev-trust.json
var devTrustBytes []byte

var errDevAdmission = errors.New("DEV software admission refused; retained unchanged")

// Includes the complete native engine legal/source bundle (137 files in the
// qualified bundle) plus helper/configuration/provenance, currently 143 total.
const maxDevPackageFiles = 256

type devTrust struct {
	Schema          string `json:"schema"`
	Enabled         bool   `json:"enabled"`
	Audience        string `json:"audience"`
	PublicKey       string `json:"publicKey"`
	InstallationID  string `json:"installationId"`
	InstanceID      string `json:"instanceId"`
	APIOrigin       string `json:"apiOrigin"`
	ApplicationID   string `json:"applicationId"`
	MinimumSequence int64  `json:"minimumSequence"`
	NotBefore       string `json:"notBefore"`
	ExpiresAt       string `json:"expiresAt"`
	PortalOrigin    string `json:"portalOrigin,omitempty"`
	PublicEndpoint  string `json:"publicEndpoint,omitempty"`
}

func legacyInstance(id string) bool {
	return id == "27c0be38-60bd-4dce-bb28-ef0088716a25" || id == "b7a1f6b1-c4aa-4de7-95fb-29d509d3398d"
}

func readDevTrust(raw []byte, now time.Time) (devTrust, error) {
	return readScopedTrust(raw, now, false)
}

func readScopedTrust(raw []byte, now time.Time, pilot bool) (devTrust, error) {
	var t devTrust
	if !admission.ValidJSON(raw) {
		return t, errDevAdmission
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if len(raw) > 4096 || dec.Decode(&t) != nil {
		return t, errDevAdmission
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return t, errDevAdmission
	}
	key, e := base64.StdEncoding.Strict().DecodeString(t.PublicKey)
	start, e1 := time.Parse(time.RFC3339, t.NotBefore)
	end, e2 := time.Parse(time.RFC3339, t.ExpiresAt)
	schema, audience, duration := "oos-helper-dev-trust-v1", "dev", 24*time.Hour
	if pilot {
		schema, audience, duration = "oos-helper-pilot-anchor-v1", "pilot", 30*24*time.Hour
	}
	if t.Schema != schema || !t.Enabled || t.Audience != audience || e != nil || len(key) != ed25519.PublicKeySize ||
		!uuidPattern.MatchString(t.InstallationID) || !uuidPattern.MatchString(t.InstanceID) || (!pilot && legacyInstance(t.InstanceID)) ||
		t.ApplicationID == "" || t.MinimumSequence < 1 || e1 != nil || e2 != nil || !start.Before(end) || end.Sub(start) > duration || now.Before(start) || !now.Before(end) {
		return t, errDevAdmission
	}
	if !admission.ValidOrigin(t.APIOrigin) || (pilot && (!admission.ValidOrigin(t.PortalOrigin) || !admission.ValidEndpoint(t.PublicEndpoint))) || (!pilot && (t.PortalOrigin != "" || t.PublicEndpoint != "")) {
		return t, errDevAdmission
	}
	return t, nil
}

func verifyDev(raw []byte, trust devTrust, packageSHA, helperSHA string, now time.Time) (admission.Admission, error) {
	// Re-evaluate the compiled policy at every boundary, including receipt reads.
	encoded, _ := json.Marshal(trust)
	if _, e := readScopedTrust(encoded, now, trust.Schema == "oos-helper-pilot-anchor-v1"); e != nil {
		return admission.Admission{}, e
	}
	key, _ := base64.StdEncoding.Strict().DecodeString(trust.PublicKey)
	result, e := admission.Verify(raw, admission.Policy{PublicKey: key, InstallationID: trust.InstallationID, InstanceID: trust.InstanceID, APIOrigin: trust.APIOrigin, ApplicationID: trust.ApplicationID, PackageSHA: packageSHA, HelperSHA: helperSHA, MinimumSequence: trust.MinimumSequence})
	if e != nil {
		return result, errDevAdmission
	}
	// Verify already rejected duplicate keys and authenticated the whole payload.
	var envelope struct {
		Payload struct {
			Package struct {
				Provenance struct {
					Audience string `json:"admissionAudience"`
					Version  string `json:"installerVersion"`
				} `json:"provenance"`
			} `json:"package"`
		} `json:"payload"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Payload.Package.Provenance.Audience != trust.Audience || envelope.Payload.Package.Provenance.Version != version {
		return result, errDevAdmission
	}
	if trust.Audience == "pilot" && (result.Config.Portal != trust.PortalOrigin || result.Config.Address != trust.PublicEndpoint) {
		return admission.Admission{}, errDevAdmission
	}
	return result, nil
}

type devReceipt struct {
	Schema     string          `json:"schema"`
	PackageSHA string          `json:"packageSha256"`
	Envelope   json.RawMessage `json:"envelope"`
}

func safeDevPath(path string) error {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return errDevAdmission
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, e := os.Lstat(current)
		if e != nil && !os.IsNotExist(e) {
			return errDevAdmission
		}
		if e == nil && (info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || platformReparse(current)) {
			return errDevAdmission
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func readBounded(path string, maximum int64) ([]byte, error) {
	if safeDevPath(path) != nil {
		return nil, errDevAdmission
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > maximum {
		return nil, errDevAdmission
	}
	data, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil || int64(len(data)) > maximum {
		return nil, errDevAdmission
	}
	return data, nil
}

func selfSHA() (string, error) {
	exe, e := os.Executable()
	if e != nil {
		return "", e
	}
	raw, e := readBounded(exe, 128<<20)
	if e != nil {
		return "", e
	}
	return digest(raw), nil
}

func receiptDirectory(t devTrust) string {
	scope := "AdmissionDEV"
	if t.Audience == "pilot" {
		scope = "AdmissionPilot"
	}
	return filepath.Join(base(), "Organisations", t.InstanceID, scope)
}

// Bounded append-only receipts retain previous admissions. This detects replay
// while the user-profile history is intact; it does NOT claim rollback defence
// against the Windows account owner deleting/restoring their entire profile.
func latestDevReceipt(t devTrust, helperSHA string, now time.Time) (admission.Admission, error) {
	var latest admission.Admission
	dir := receiptDirectory(t)
	if safeDevPath(dir) != nil {
		return latest, errDevAdmission
	}
	entries, e := os.ReadDir(dir)
	if os.IsNotExist(e) {
		return latest, nil
	}
	if e != nil || len(entries) > 64 {
		return latest, errDevAdmission
	}
	sequences := map[int64]bool{}
	for _, entry := range entries {
		if entry.IsDir() {
			return latest, errDevAdmission
		}
		raw, e := readBounded(filepath.Join(dir, entry.Name()), 70000)
		if e != nil {
			return latest, errDevAdmission
		}
		var r devReceipt
		if json.Unmarshal(raw, &r) != nil || r.Schema != receiptSchema(t) {
			return latest, errDevAdmission
		}
		a, e := verifyDev(r.Envelope, t, r.PackageSHA, helperSHA, now)
		if e != nil || entry.Name() != strconv.FormatInt(a.Sequence, 10)+"-"+a.EnvelopeSHA+".json" {
			return latest, errDevAdmission
		}
		if sequences[a.Sequence] {
			return latest, errDevAdmission
		}
		sequences[a.Sequence] = true
		if a.Sequence > latest.Sequence {
			latest = a
		}
	}
	return latest, nil
}

func storeDevReceipt(t devTrust, raw []byte, packageSHA, helperSHA string, now time.Time) error {
	a, e := verifyDev(raw, t, packageSHA, helperSHA, now)
	if e != nil {
		return e
	}
	latest, e := latestDevReceipt(t, helperSHA, now)
	if e != nil {
		return e
	}
	if a.Sequence < latest.Sequence || a.Sequence == latest.Sequence && a.EnvelopeSHA != latest.EnvelopeSHA {
		return errDevAdmission
	}
	if a.Sequence == latest.Sequence {
		return nil
	}
	dir := receiptDirectory(t)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) >= 64 {
		return errDevAdmission
	}
	data, e := json.Marshal(devReceipt{receiptSchema(t), packageSHA, raw})
	if e != nil {
		return e
	}
	// Exclusive creation never replaces a receipt. A partial write is retained and
	// causes a closed failure on the next read, rather than silently lowering state.
	file, e := os.OpenFile(filepath.Join(dir, strconv.FormatInt(a.Sequence, 10)+"-"+a.EnvelopeSHA+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = file.Write(data)
	if e == nil {
		e = file.Sync()
	}
	closeErr := file.Close()
	if e != nil {
		return e
	}
	return closeErr
}

func validateInstalled(c Config) error {
	if !pilotEnabled() && legacyInstance(c.Instance) {
		return validate(c)
	}
	t, e := installedTrust(c.Instance, time.Now())
	if e != nil || c.Instance != t.InstanceID {
		return errDevAdmission
	}
	hash, e := selfSHA()
	if e != nil {
		return e
	}
	a, e := latestDevReceipt(t, hash, time.Now())
	if e != nil || a.Sequence == 0 || Config(a.Config) != c {
		return errDevAdmission
	}
	return nil
}

// Verify the exact ZIP without extracting anything. No path from the package is
// passed to the filesystem or shell. The CP envelope is deliberately external
// to the ZIP, so its signature has no recursive dependency on the package hash.
func verifyDevArchive(raw []byte, a admission.Admission, helperSHA string) error {
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil || len(z.File) > maxDevPackageFiles {
		return errDevAdmission
	}
	names := map[string]bool{}
	found := 0
	for _, f := range z.File {
		if names[f.Name] || f.Mode()&os.ModeSymlink != 0 || strings.Contains(f.Name, "\\") || strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, ":") {
			return errDevAdmission
		}
		for _, part := range strings.Split(f.Name, "/") {
			if part == ".." || part == "." || part == "" {
				return errDevAdmission
			}
		}
		names[f.Name] = true
		if f.Name != "organisation.json" && f.Name != "OrganisationOS-Syncthing-Installer.exe" {
			continue
		}
		limit := int64(128 << 20)
		if f.Name == "organisation.json" {
			limit = 4096
		}
		if f.UncompressedSize64 > uint64(limit) {
			return errDevAdmission
		}
		r, e := f.Open()
		if e != nil {
			return errDevAdmission
		}
		data, e := io.ReadAll(io.LimitReader(r, limit+1))
		r.Close()
		if e != nil || int64(len(data)) > limit {
			return errDevAdmission
		}
		if f.Name == "organisation.json" {
			if !admission.ConfigurationMatches(data, a.Config) {
				return errDevAdmission
			}
		} else if digest(data) != helperSHA {
			return errDevAdmission
		}
		found++
	}
	if found != 2 {
		return errDevAdmission
	}
	return nil
}

func installDev(packageFile, envelopeFile string) error {
	now := time.Now()
	t, e := readDevTrust(devTrustBytes, now)
	if e != nil {
		return e
	}
	return installAdmitted(packageFile, envelopeFile, t, now)
}

func installAdmitted(packageFile, envelopeFile string, t devTrust, now time.Time) error {
	helperSHA, e := selfSHA()
	if e != nil {
		return e
	}
	raw, e := readBounded(envelopeFile, 65536)
	if e != nil {
		return e
	}
	archive, e := readBounded(packageFile, 256<<20)
	if e != nil {
		return e
	}
	packageSHA := digest(archive)
	a, e := verifyDev(raw, t, packageSHA, helperSHA, now)
	if e != nil {
		return e
	}
	if e = verifyDevArchive(archive, a, helperSHA); e != nil {
		return e
	}
	if os.Getenv("LOCALAPPDATA") == "" || safeDevPath(home(Config(a.Config))) != nil {
		return errDevAdmission
	}
	release, e := devInstallLock(t.InstanceID)
	if e != nil {
		return e
	}
	defer release()
	if _, e = os.Lstat(filepath.Join(home(Config(a.Config)), "organisation.json")); e == nil {
		prior, priorErr := latestDevReceipt(t, helperSHA, time.Now())
		if priorErr != nil {
			return errDevAdmission
		}
		if prior.Sequence == 0 {
			// A first signed pilot receipt may adopt only an exact schema2
			// historical configuration. Identity, enrollment and files stay put.
			var old Config
			if t.Audience != "pilot" || loadJSON(filepath.Join(home(Config(a.Config)), "organisation.json"), &old) != nil || validateLegacy(old) != nil || old != Config(a.Config) {
				return errDevAdmission
			}
		}
	} else if !os.IsNotExist(e) {
		return errDevAdmission
	}
	return installConfig(Config(a.Config), func() error { return storeDevReceipt(t, raw, packageSHA, helperSHA, time.Now()) })
}
