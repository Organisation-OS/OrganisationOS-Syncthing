// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"organisationos.local/offline-employee/internal/admission"
	"time"
)

// Public CP factory input. Neither downloads nor command arguments supply trust.
//
//go:embed pilot-trust.json
var pilotTrustBytes []byte

type pilotTrust struct {
	Schema  string     `json:"schema"`
	Enabled bool       `json:"enabled"`
	Anchors []devTrust `json:"anchors"`
}

func pilotEnabled() bool {
	var p pilotTrust
	if len(pilotTrustBytes) > 16384 || !admission.ValidJSON(pilotTrustBytes) {
		return true
	}
	d := json.NewDecoder(bytes.NewReader(pilotTrustBytes))
	d.DisallowUnknownFields()
	// Invalid compiled policy never falls back to historical unsigned installs.
	return d.Decode(&p) != nil || p.Enabled || p.Schema != "oos-helper-pilot-trust-v1" || len(p.Anchors) != 0
}

func readPilotTrust(raw []byte, instance string, now time.Time) (devTrust, error) {
	var empty devTrust
	var p pilotTrust
	if len(raw) > 16384 || !admission.ValidJSON(raw) {
		return empty, errDevAdmission
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return empty, errDevAdmission
	}
	var extra any
	if d.Decode(&extra) != io.EOF || p.Schema != "oos-helper-pilot-trust-v1" || !p.Enabled || len(p.Anchors) < 1 || len(p.Anchors) > 2 {
		return empty, errDevAdmission
	}
	seenInstances, seenInstallations := map[string]bool{}, map[string]bool{}
	var selected devTrust
	for _, a := range p.Anchors {
		encoded, _ := json.Marshal(a)
		if _, e := readScopedTrust(encoded, now, true); e != nil || seenInstances[a.InstanceID] || seenInstallations[a.InstallationID] {
			return empty, errDevAdmission
		}
		seenInstances[a.InstanceID], seenInstallations[a.InstallationID] = true, true
		if a.InstanceID == instance {
			selected = a
		}
	}
	if selected.InstanceID == "" {
		return empty, errDevAdmission
	}
	return selected, nil
}
func installedTrust(instance string, now time.Time) (devTrust, error) {
	if pilotEnabled() {
		return readPilotTrust(pilotTrustBytes, instance, now)
	}
	return readDevTrust(devTrustBytes, now)
}
func receiptSchema(t devTrust) string {
	if t.Audience == "pilot" {
		return "oos-helper-pilot-receipt-v1"
	}
	return "oos-helper-dev-receipt-v1"
}
func installPilot(instance, packageFile, envelopeFile string) error {
	now := time.Now()
	t, e := readPilotTrust(pilotTrustBytes, instance, now)
	if e != nil {
		return e
	}
	return installAdmitted(packageFile, envelopeFile, t, now)
}
