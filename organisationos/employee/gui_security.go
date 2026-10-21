// SPDX-License-Identifier: MPL-2.0
package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var passwordHashPattern = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)

// Protect only the managed engine whose certificate identity matches this profile.
// The native API hashes a fresh password; plaintext is never written or logged.
// The helper continues to use the per-installation API key, not this password.
func secureGUI(c Config) error {
	id, e := readIdentity(c)
	if e != nil {
		return e
	}
	var status struct {
		ID string `json:"myID"`
	}
	if e = local(c, "GET", "system/status", nil, &status); e != nil || status.ID != id {
		return errors.New("local API identity refused")
	}
	var gui map[string]any
	if e = local(c, "GET", "config/gui", nil, &gui); e != nil {
		return e
	}
	address, _ := gui["address"].(string)
	host, _, e := net.SplitHostPort(address)
	if e != nil || host != "127.0.0.1" {
		return errors.New("local administration address refused")
	}
	if gui["authMode"] != "static" {
		return errors.New("unexpected local authentication mode retained")
	}
	user, _ := gui["user"].(string)
	password, _ := gui["password"].(string)
	patch := map[string]any{}
	if user == "" || !passwordHashPattern.MatchString(password) {
		password, e = randomHex(32)
		if e != nil {
			return e
		}
		patch["user"] = "OrganisationOS"
		patch["password"] = password
	}
	for _, name := range []string{"insecureAdminAccess", "insecureSkipHostcheck", "insecureAllowFrameLoading", "metricsWithoutAuth"} {
		if gui[name] != false {
			patch[name] = false
		}
	}
	if len(patch) == 0 {
		return nil
	}
	if e = local(c, "PATCH", "config/gui", patch, nil); e != nil {
		return e
	}
	// GUI configuration reloads its HTTP listener. A bounded retry tolerates that
	// restart, while an installation cannot report success without readback.
	for i := 0; i < 20; i++ {
		var got map[string]any
		if local(c, "GET", "config/gui", nil, &got) == nil {
			u, _ := got["user"].(string)
			p, _ := got["password"].(string)
			if u != "" && passwordHashPattern.MatchString(p) && got["authMode"] == "static" && got["address"] == address && got["insecureAdminAccess"] == false && got["insecureSkipHostcheck"] == false && got["insecureAllowFrameLoading"] == false && got["metricsWithoutAuth"] == false {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("local administration protection not confirmed")
}

// A completed enrollment is reused only after its device proof is accepted by
// the current organisation. Never start another enrollment for an active device.
func resumeEnrollment(c Config) (bool, error) {
	var state State
	if e := loadJSON(filepath.Join(home(c), "enrollment.json"), &state); e != nil {
		if os.IsNotExist(e) {
			return false, nil
		}
		return true, errors.New("existing enrollment unreadable; retained")
	}
	id, e := readIdentity(c)
	if e != nil || !uuidPattern.MatchString(state.Device) || state.Identity != id {
		return true, errors.New("existing enrollment identity refused")
	}
	path := "/api/v1/documents/offline/devices/" + state.Device + "/configuration"
	p, e := proof(c, state.Device, "GET", path, nil)
	if e != nil {
		return true, e
	}
	var cfg Configuration
	if e = portal(c, "GET", path, nil, p, &cfg); e != nil {
		return true, e
	}
	if e = validateResponse(c, state.Device, cfg); e != nil {
		return true, e
	}
	return true, openBrowser(c.Portal + "/documents/offline")
}

func waitSecureGUI(c Config) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		e := secureGUI(c)
		if e == nil || time.Now().After(deadline) {
			return e
		}
		time.Sleep(200 * time.Millisecond)
	}
}
