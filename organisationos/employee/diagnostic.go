// SPDX-License-Identifier: MPL-2.0
package main

import (
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"
)

// No error text, URI, argument, certificate, code, verifier or token is persisted.
type requestError struct {
	Kind   string
	Status int
}

func (e *requestError) Error() string { return e.Kind }

type operationError struct {
	Stage, Code, Transport      string
	HTTPStatus, PriorHTTPStatus int
}

func (e *operationError) Error() string { return e.Stage + ":" + e.Code }
func operationFailure(stage, code string, cause error) *operationError {
	e := &operationError{Stage: stage, Code: code}
	var r *requestError
	if errors.As(cause, &r) {
		e.Transport = r.Kind
		e.HTTPStatus = r.Status
	}
	return e
}
func transportFailure(err error) error {
	kind := "NETWORK_UNAVAILABLE"
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var ne net.Error
	if errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		kind = "TLS_CERTIFICATE_REFUSED"
	} else if errors.As(err, &ne) && ne.Timeout() {
		kind = "NETWORK_TIMEOUT"
	}
	return &requestError{Kind: kind}
}

var openBrowser = browser

type diagnosticReceipt struct {
	Schema          string `json:"schema"`
	Reference       string `json:"reference"`
	At              string `json:"at"`
	HelperVersion   string `json:"helperVersion"`
	Stage           string `json:"stage"`
	Code            string `json:"code"`
	Transport       string `json:"transport,omitempty"`
	HTTPStatus      int    `json:"httpStatus,omitempty"`
	PriorHTTPStatus int    `json:"priorHttpStatus,omitempty"`
}

func persistDiagnostic(err error) diagnosticReceipt {
	r, _ := persistDiagnosticFile(err, "diagnostic.json")
	return r
}
func persistDiagnosticFile(err error, name string) (diagnosticReceipt, error) {
	op := &operationError{Stage: "APPLICATION", Code: "OPERATION_FAILED"}
	var reported *operationError
	if errors.As(err, &reported) {
		op = reported
	}
	ref, e := randomHex(8)
	if e != nil {
		ref = "unavailable"
	}
	r := diagnosticReceipt{"oos-employee-diagnostic-v1", "OOS-ST-" + ref, time.Now().UTC().Format(time.RFC3339), version, op.Stage, op.Code, op.Transport, op.HTTPStatus, op.PriorHTTPStatus}
	if os.Getenv("LOCALAPPDATA") == "" {
		return r, errors.New("local directory unavailable")
	}
	if err := os.MkdirAll(base(), 0700); err != nil {
		return r, err
	}
	return r, writeJSON(filepath.Join(base(), name), r)
}
func reportReadOnly(err error) {
	r, writeErr := persistDiagnosticFile(err, "diagnostic-readonly.json")
	message := "Diagnostic en lecture seule — " + r.HelperVersion + "\nHeure UTC : " + r.At + "\nRéférence : " + r.Reference + "\nÉtape : " + r.Stage + " · " + r.Code + "\nAucun enrôlement ni réglage modifié."
	if writeErr != nil {
		message += "\nÉcriture du nouveau diagnostic impossible. Tout fichier précédent est obsolète ; transmettez uniquement cette référence, cette heure et cette étape."
	} else {
		message += "\nRésultat de ce lancement : %LOCALAPPDATA%\\OrganisationOS\\Syncthing\\diagnostic-readonly.json."
	}
	notify("Syncthing OrganisationOS — diagnostic en lecture seule", message)
}

func reportFailure(err error) {
	r := persistDiagnostic(err)
	message := "Connexion non terminée. Votre identité, vos fichiers et vos conflits sont conservés.\nRéférence : " + r.Reference + "\nÉtape : " + r.Stage + " · " + r.Code
	if r.HTTPStatus != 0 {
		message += "\nUne réponse HTTP de refus a été enregistrée dans le diagnostic."
	}
	if r.Code == "ENROLLED_BROWSER_UNAVAILABLE" {
		message += "\nLa connexion est enregistrée. Ouvrez Documents → Hors ligne dans votre portail."
	} else {
		message += "\nReprise : menu Démarrer → OrganisationOS → Syncthing, puis reconnectez ce même appareil. Si l’erreur revient, transmettez uniquement diagnostic.json dans %LOCALAPPDATA%\\OrganisationOS\\Syncthing."
	}
	notify("Syncthing OrganisationOS", message)
}

// This probe uses no browser session and cannot enroll, revoke or configure a device.
func diagnose() {
	entries, err := os.ReadDir(filepath.Join(base(), "Organisations"))
	if err != nil {
		reportReadOnly(operationFailure("LOCAL_CONFIGURATION", "ORGANISATIONS_UNAVAILABLE", err))
		return
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		c, e := getConfig(entry.Name())
		if e != nil {
			continue
		}
		count++
		record := "11111111-1111-4111-8111-111111111111"
		if _, e = proof(c, record, "GET", "/api/v1/documents/offline/devices/"+record+"/configuration", nil); e != nil {
			reportReadOnly(operationFailure("DEVICE_PROOF", "PROOF_UNAVAILABLE", e))
			return
		}
		var out any
		e = portal(c, "GET", "/api/v1/documents/offline/devices", nil, nil, &out)
		var status *requestError
		if !errors.As(e, &status) || status.Status != 401 {
			reportReadOnly(operationFailure("API_REACHABILITY", "EXPECTED_AUTHENTICATION_REFUSAL_NOT_OBSERVED", e))
			return
		}
	}
	if count == 0 {
		reportReadOnly(operationFailure("LOCAL_CONFIGURATION", "NO_VALID_ORGANISATION", nil))
		return
	}
	reportReadOnly(operationFailure("READ_ONLY_DIAGNOSTIC", "LOCAL_PROOF_AND_API_REACHABLE", nil))
}
