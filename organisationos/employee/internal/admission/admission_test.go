package admission

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) (map[string]any, Policy, ed25519.PrivateKey) {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	p := Policy{public, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "https://dev.synthetic.invalid:18443", "syncthing", strings.Repeat("a", 64), strings.Repeat("b", 64), 1}
	keySHA := sha256.Sum256(public)
	config := map[string]any{"schema": json.Number("2"), "instanceId": p.InstanceID, "apiOrigin": p.APIOrigin, "portalOrigin": "https://portal.synthetic.invalid", "organisationName": "Banc synthétique", "serverDeviceKey": strings.Repeat("AAAAAAA-", 7) + "AAAAAAA", "publicEndpoint": "tcp://sync.synthetic.invalid:22223"}
	payload := map[string]any{"schema": "oos-employee-software-release-v1", "installationId": p.InstallationID, "instanceId": p.InstanceID, "applicationId": p.ApplicationID, "sequence": json.Number("1"), "operation": "install", "package": map[string]any{"sha256": p.PackageSHA, "provenance": map[string]any{"schema": "oos-employee-build-provenance-v1", "engineVersion": "v2.1.6-oos.2", "engineWindowsSha256": EngineSHA, "installerSha256": p.HelperSHA, "configuration": config}}}
	return map[string]any{"schema": "oos-signed-v1", "purpose": Purpose, "algorithm": "Ed25519", "issuer": hex.EncodeToString(keySHA[:]), "payload": payload}, p, private
}
func sign(t *testing.T, m map[string]any, key ed25519.PrivateKey) []byte {
	t.Helper()
	delete(m, "signature")
	raw, e := canonical(m)
	if e != nil {
		t.Fatal(e)
	}
	m["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))
	raw, e = json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestSyntheticSignedConfiguration(t *testing.T) {
	m, p, key := fixture(t)
	got, e := Verify(sign(t, m, key), p)
	if e != nil || got.Config.Instance != p.InstanceID || got.Config.API != p.APIOrigin || got.Sequence != 1 || !hash.MatchString(got.EnvelopeSHA) {
		t.Fatalf("admission: %v", e)
	}
}
func TestSignedContractRefusals(t *testing.T) {
	cases := []string{"purpose", "instance", "installation", "application", "withdraw", "sequence", "package", "engine", "helper", "origin", "portal", "transport", "server", "configuration-field", "issuer", "algorithm"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			m, p, key := fixture(t)
			payload := m["payload"].(map[string]any)
			pack := payload["package"].(map[string]any)
			prov := pack["provenance"].(map[string]any)
			c := prov["configuration"].(map[string]any)
			switch name {
			case "purpose":
				m["purpose"] = "other-purpose"
			case "instance":
				payload["instanceId"] = "33333333-3333-4333-8333-333333333333"
			case "installation":
				payload["installationId"] = "33333333-3333-4333-8333-333333333333"
			case "application":
				payload["applicationId"] = "other"
			case "withdraw":
				payload["operation"] = "withdraw"
			case "sequence":
				payload["sequence"] = json.Number("0")
			case "package":
				pack["sha256"] = strings.Repeat("c", 64)
			case "engine":
				prov["engineWindowsSha256"] = strings.Repeat("c", 64)
			case "helper":
				prov["installerSha256"] = strings.Repeat("c", 64)
			case "origin":
				c["apiOrigin"] = "https://other.synthetic.invalid"
			case "portal":
				c["portalOrigin"] = "https://user:secret@portal.synthetic.invalid"
			case "transport":
				c["publicEndpoint"] = "tcp://sync.synthetic.invalid:22223?relay=1"
			case "server":
				c["serverDeviceKey"] = "invalid"
			case "configuration-field":
				c["command"] = "arbitrary"
			case "issuer":
				m["issuer"] = strings.Repeat("c", 64)
			case "algorithm":
				m["algorithm"] = "none"
			}
			if _, e := Verify(sign(t, m, key), p); e == nil {
				t.Fatal("invalid signed contract accepted")
			}
		})
	}
}
func TestTamperKeyDuplicateAndTrailingData(t *testing.T) {
	m, p, key := fixture(t)
	raw := sign(t, m, key)
	other, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	badPolicy := p
	badPolicy.PublicKey = other
	if _, e := Verify(raw, badPolicy); e == nil {
		t.Fatal("foreign anchor accepted")
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte("Banc"), []byte("Autre"), 1), append(append([]byte{}, raw...), []byte(" {}")...), append([]byte(`{"purpose":"duplicate",`), raw[1:]...), make([]byte, 65537)} {
		if _, e := Verify(bad, p); e == nil {
			t.Fatal("tampered or malformed envelope accepted")
		}
	}
	p.MinimumSequence = 2
	if _, e := Verify(raw, p); e == nil {
		t.Fatal("replay accepted")
	}
}
func TestNativePythonCanonicalVectors(t *testing.T) {
	raw, e := os.ReadFile("canonical-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct{ Input, Canonical string }
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors {
		parsed, e := parse([]byte(v.Input))
		if e != nil {
			t.Fatal(e)
		}
		got, e := canonical(parsed)
		if e != nil || string(got) != v.Canonical {
			t.Fatalf("canonical mismatch\ngot %s\nwant %s", got, v.Canonical)
		}
	}
}
func TestParserBounds(t *testing.T) {
	for _, s := range []string{`{"x":1,"x":2}`, `{"x":1.1}`, `{"x":1e2}`, `{"x":9223372036854775808}`, strings.Repeat("[", 18) + strings.Repeat("]", 18), "\xff"} {
		if _, e := parse([]byte(s)); e == nil {
			t.Fatalf("invalid accepted: %s", s)
		}
	}
}
func TestDestinations(t *testing.T) {
	for _, s := range []string{"http://host", "https://host/path", "https://host?", "https://host#fragment", "https://host:99999", "https://host/%2f", "https://user@host"} {
		if origin(s) {
			t.Fatalf("invalid origin: %s", s)
		}
	}
	for _, s := range []string{"tcp://host", "tcp://host:0", "tcp://host:65536", "tcp://user@host:1", "quic://host:1", "tcp://host:1/path"} {
		if endpoint(s) {
			t.Fatalf("invalid transport: %s", s)
		}
	}
}
