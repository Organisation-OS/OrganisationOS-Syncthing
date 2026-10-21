// SPDX-License-Identifier: MPL-2.0
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureConfig() Config {
	return Config{1, "27c0be38-60bd-4dce-bb28-ef0088716a25", "https://portal.thecgp.com", "TheCGP", "KMYJWX3-EJ6OKF7-Z4TIBZI-EMYAEMW-3OCR7BB-2Z2OM54-SJMJ2KI-SKQXAQR", "tcp://syncthing.thecgp.com:22000"}
}
func TestInstanceBoundary(t *testing.T) {
	c := fixtureConfig()
	if validate(c) != nil {
		t.Fatal("valid instance")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Portal = "https://foreign.example" }, func(c *Config) { c.Address = "tcp://syncthing.villesadp.ca:22000" }, func(c *Config) { c.Instance = "b7a1f6b1-c4aa-4de7-95fb-29d509d3398d" }, func(c *Config) { c.Server = "invalid" }} {
		bad := c
		mutate(&bad)
		if validate(bad) == nil {
			t.Fatal("cross-instance configuration accepted")
		}
	}
}
func TestEmbeddedQualifiedEngine(t *testing.T) {
	if digest(engineBytes) != engineSHA {
		t.Fatal("engine bytes differ from qualified fork")
	}
	if len(engineBytes) < 10000000 {
		t.Fatal("missing engine")
	}
}
func TestResponsePinsAndFolders(t *testing.T) {
	c := fixtureConfig()
	id := "11111111-1111-4111-8111-111111111111"
	r := Configuration{"ACTIVE", id, Server{c.Server, c.Address}, []Folder{{"oos-" + id, id, "Synthetic", "READY", "sendreceive"}}}
	if validateResponse(c, id, r) != nil {
		t.Fatal("valid reply")
	}
	r.Server.Key = "OTHER"
	if validateResponse(c, id, r) == nil {
		t.Fatal("server replacement accepted")
	}
	r.Server.Key = c.Server
	r.Folders = append(r.Folders, r.Folders[0])
	if validateResponse(c, id, r) == nil {
		t.Fatal("duplicate folder accepted")
	}
}
func TestEd25519ProofBoundToRequest(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	c := fixtureConfig()
	state := filepath.Join(home(c), "Etat")
	if e := os.MkdirAll(state, 0700); e != nil {
		t.Fatal(e)
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	cert, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(state, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0600)
	os.WriteFile(filepath.Join(state, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600)
	record := "11111111-1111-4111-8111-111111111111"
	path := "/api/v1/documents/offline/devices/" + record + "/exchange"
	body, _ := json.Marshal(map[string]string{"code": "synthetic", "verifier": "synthetic"})
	p, e := proof(c, record, "POST", path, body)
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte(strings.Join([]string{"organisationos-offline-v1", c.Instance, record, fmt.Sprint(p["timestamp"]), p["nonce"].(string), "POST", path, digest(body)}, "\n"))
	sig, _ := base64.StdEncoding.DecodeString(p["signature"].(string))
	if !ed25519.Verify(pub, payload, sig) {
		t.Fatal("real signature failed")
	}
	changed := sha256.Sum256(payload)
	if ed25519.Verify(pub, changed[:], sig) {
		t.Fatal("wrong payload accepted")
	}
	id, e := readIdentity(c)
	if e != nil || !keyPattern.MatchString(id) {
		t.Fatal("identity representation")
	}
	second, _ := readIdentity(c)
	if id != second {
		t.Fatal("identity was regenerated")
	}
}
func TestAtomicWriteRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "original")
	os.WriteFile(target, []byte("retained"), 0600)
	link := filepath.Join(dir, "link")
	if e := os.Symlink(target, link); e != nil {
		t.Skip("symlink unavailable")
	}
	if atomicWrite(link, []byte("overwrite"), 0600) == nil {
		t.Fatal("symlink followed")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "retained" {
		t.Fatal("original changed")
	}
}
