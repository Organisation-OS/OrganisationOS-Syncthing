// SPDX-License-Identifier: MPL-2.0
package main

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"
)

// Explicit parent-client mode. Native approval/exchange stays unchanged; the
// caller displays the exact native Portal URI in its own isolated browser.
// Callback codes travel on stdin, never on a process command line or in logs.
func clientInvocation(args []string, input io.Reader, output io.Writer) (bool, int) {
	if len(args) == 0 || (args[0] != "install-dev-client" && args[0] != "install-pilot-client" && args[0] != "connect-client" && args[0] != "callback-client") {
		return false, 0
	}
	oldBrowser := openBrowser
	defer func() { openBrowser = oldBrowser }()
	intent := ""
	openBrowser = func(raw string) error {
		u, e := url.Parse(raw)
		if e != nil || len(raw) > 4096 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" ||
			(u.Path != "/documents/offline" && u.Path != "/documents/offline/enroll") || strings.ContainsAny(raw, "\r\n\x00") || intent != "" {
			return operationFailure("CLIENT_INTENT", "INVALID_PORTAL_URI", nil)
		}
		intent = raw
		return nil
	}
	err := performClientInvocation(args, input)
	if err == nil && intent == "" {
		err = operationFailure("CLIENT_INTENT", "PORTAL_URI_ABSENT", nil)
	}
	result := map[string]any{"schema": "oos-syncthing-client-result-v1", "helperVersion": version}
	code := 0
	if err != nil {
		diagnostic := persistDiagnostic(err)
		result["status"] = "FAILED"
		result["stage"] = diagnostic.Stage
		result["code"] = diagnostic.Code
		result["reference"] = diagnostic.Reference
		code = 1
	} else {
		result["status"] = "PORTAL_NAVIGATION_REQUIRED"
		result["portalUri"] = intent
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return true, 1
	}
	return true, code
}

func performClientInvocation(args []string, input io.Reader) error {
	if args[0] == "install-pilot-client" && len(args) == 4 {
		return installPilot(args[1], args[2], args[3])
	}
	if args[0] == "install-dev-client" && len(args) == 3 {
		return installDev(args[1], args[2])
	}
	if len(args) != 2 || (args[0] != "connect-client" && args[0] != "callback-client") {
		return operationFailure("INVOCATION", "INVALID_ARGUMENTS", nil)
	}
	c, err := getConfig(args[1])
	if err != nil {
		return operationFailure("LOCAL_CONFIGURATION", "CONFIGURATION_REFUSED", nil)
	}
	unlock, err := devInstallLock(c.Instance)
	if err != nil {
		return operationFailure("LOCAL_LIFECYCLE", "OPERATION_IN_PROGRESS", nil)
	}
	defer unlock()
	if args[0] == "callback-client" {
		raw, err := io.ReadAll(io.LimitReader(input, 4097))
		if err != nil || len(raw) == 0 || len(raw) > 4096 {
			return operationFailure("RETURN_URI", "INVALID_RETURN", nil)
		}
		return callbackForInstance(strings.TrimSpace(string(raw)), c.Instance)
	}
	if resumed, err := resumeEnrollment(c); resumed || err != nil {
		return err
	}
	return begin(c)
}
