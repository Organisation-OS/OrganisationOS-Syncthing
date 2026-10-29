// Package admission is a candidate verifier for the existing CP employee-software
// envelope. It does not install software, enroll a device, or select a trust root.
package admission

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const Purpose = "organisation-employee-software-v1"
const EngineSHA = "14421c4afbe5b48ddd9065410310f6fd667d678ae5943bd9520f28f261d8eb4b"

var refused = errors.New("signed instance configuration refused")
var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
var hash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var device = regexp.MustCompile(`^[A-Z2-7]{7}(?:-[A-Z2-7]{7}){7}$`)

// Policy comes from an independently admitted native installation. The public
// key MUST NOT be accepted from the same untrusted download as the envelope.
type Policy struct {
	PublicKey                                                                   ed25519.PublicKey
	InstallationID, InstanceID, APIOrigin, ApplicationID, PackageSHA, HelperSHA string
	MinimumSequence                                                             int64
}
type Config struct {
	Schema   int    `json:"schema"`
	Instance string `json:"instanceId"`
	Portal   string `json:"portalOrigin"`
	API      string `json:"apiOrigin"`
	Name     string `json:"organisationName"`
	Server   string `json:"serverDeviceKey"`
	Address  string `json:"publicEndpoint"`
}
type Admission struct {
	Config      Config
	Sequence    int64
	EnvelopeSHA string
}

// ConfigurationMatches uses the same bounded strict JSON parser as Verify.
func ConfigurationMatches(raw []byte, expected Config) bool {
	if len(raw) > 4096 {
		return false
	}
	parsed, err := parse(raw)
	if err != nil {
		return false
	}
	m, ok := parsed.(map[string]any)
	if !ok || len(m) != 7 {
		return false
	}
	normalized, err := json.Marshal(m)
	if err != nil {
		return false
	}
	var config Config
	return json.Unmarshal(normalized, &config) == nil && config == expected
}

func Verify(raw []byte, p Policy) (Admission, error) {
	var empty Admission
	if len(raw) > 65536 || len(p.PublicKey) != ed25519.PublicKeySize || !uuid.MatchString(p.InstallationID) || !uuid.MatchString(p.InstanceID) || !origin(p.APIOrigin) || !hash.MatchString(p.PackageSHA) || !hash.MatchString(p.HelperSHA) || p.ApplicationID == "" || p.MinimumSequence < 1 {
		return empty, refused
	}
	value, e := parse(raw)
	if e != nil {
		return empty, refused
	}
	envelope, ok := value.(map[string]any)
	if !ok || len(envelope) != 6 {
		return empty, refused
	}
	keySHA := sha256.Sum256(p.PublicKey)
	if envelope["schema"] != "oos-signed-v1" || envelope["purpose"] != Purpose || envelope["algorithm"] != "Ed25519" || envelope["issuer"] != hex.EncodeToString(keySHA[:]) {
		return empty, refused
	}
	signature, ok := envelope["signature"].(string)
	if !ok {
		return empty, refused
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(signature)
	if e != nil || len(sig) != 64 {
		return empty, refused
	}
	delete(envelope, "signature")
	canonical, e := canonical(envelope)
	if e != nil || !ed25519.Verify(p.PublicKey, canonical, sig) {
		return empty, refused
	}
	payload, ok := envelope["payload"].(map[string]any)
	if !ok {
		return empty, refused
	}
	if payload["schema"] != "oos-employee-software-release-v1" || payload["installationId"] != p.InstallationID || payload["instanceId"] != p.InstanceID || payload["applicationId"] != p.ApplicationID || payload["operation"] != "install" {
		return empty, refused
	}
	seq, ok := payload["sequence"].(json.Number)
	if !ok {
		return empty, refused
	}
	sequence, e := seq.Int64()
	if e != nil || sequence < p.MinimumSequence {
		return empty, refused
	}
	pack, ok := payload["package"].(map[string]any)
	if !ok || pack["sha256"] != p.PackageSHA {
		return empty, refused
	}
	provenance, ok := pack["provenance"].(map[string]any)
	if !ok || provenance["schema"] != "oos-employee-build-provenance-v1" || provenance["engineVersion"] != "v2.1.6-oos.2" || provenance["engineWindowsSha256"] != EngineSHA || provenance["installerSha256"] != p.HelperSHA {
		return empty, refused
	}
	config, ok := provenance["configuration"].(map[string]any)
	if !ok || len(config) != 7 {
		return empty, refused
	}
	configRaw, _ := json.Marshal(config)
	var c Config
	if json.Unmarshal(configRaw, &c) != nil || c.Schema != 2 || c.Instance != p.InstanceID || c.API != p.APIOrigin || !origin(c.API) || !origin(c.Portal) || !endpoint(c.Address) || !device.MatchString(c.Server) || strings.TrimSpace(c.Name) == "" || len(c.Name) > 120 || strings.ContainsAny(c.Name, "\x00\r\n") {
		return empty, refused
	}
	// No organisation-specific host, account, or provider table exists here.
	// The signed configuration binds all destinations; local policy binds API.
	envelope["signature"] = signature
	all, e := canonicalJSON(envelope)
	if e != nil {
		return empty, refused
	}
	digest := sha256.Sum256(all)
	return Admission{c, sequence, hex.EncodeToString(digest[:])}, nil
}

func origin(s string) bool {
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.Contains(s, "%") || u.String() != s {
		return false
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}
func endpoint(s string) bool {
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "tcp" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.Contains(s, "%") || u.String() != s {
		return false
	}
	host, port, e := net.SplitHostPort(u.Host)
	n, e2 := strconv.Atoi(port)
	return e == nil && e2 == nil && host != "" && n > 0 && n <= 65535
}

// Match native Python canonical JSON for the bounded integer/string payload
// subset. Duplicate keys, floating numbers and invalid UTF-8 are rejected.
func parse(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, refused
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 16 {
			return nil, refused
		}
		token, e := dec.Token()
		if e != nil {
			return nil, e
		}
		if d, ok := token.(json.Delim); ok {
			switch d {
			case '{':
				m := map[string]any{}
				for dec.More() {
					k, e := dec.Token()
					if e != nil {
						return nil, e
					}
					key, ok := k.(string)
					if !ok {
						return nil, refused
					}
					if _, exists := m[key]; exists {
						return nil, refused
					}
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					m[key] = v
				}
				end, e := dec.Token()
				if e != nil || end != json.Delim('}') {
					return nil, refused
				}
				return m, nil
			case '[':
				a := []any{}
				for dec.More() {
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				end, e := dec.Token()
				if e != nil || end != json.Delim(']') {
					return nil, refused
				}
				return a, nil
			default:
				return nil, refused
			}
		}
		if number, ok := token.(json.Number); ok {
			if _, e := number.Int64(); e != nil {
				return nil, refused
			}
		}
		return token, nil
	}
	v, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = dec.Token(); e != io.EOF {
		return nil, refused
	}
	return v, nil
}
func canonical(value any) ([]byte, error) { return canonicalJSON(value) }
func canonicalJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	var write func(any) error
	stringBytes := func(s string) []byte {
		var b bytes.Buffer
		b.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"':
				b.WriteString(`\"`)
			case '\\':
				b.WriteString(`\\`)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				if r < 32 {
					fmt.Fprintf(&b, `\u%04x`, r)
				} else {
					b.WriteRune(r)
				}
			}
		}
		b.WriteByte('"')
		return b.Bytes()
	}
	write = func(v any) error {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					out.WriteByte(',')
				}
				out.Write(stringBytes(k))
				out.WriteByte(':')
				if e := write(x[k]); e != nil {
					return e
				}
			}
			out.WriteByte('}')
		case []any:
			out.WriteByte('[')
			for i, item := range x {
				if i > 0 {
					out.WriteByte(',')
				}
				if e := write(item); e != nil {
					return e
				}
			}
			out.WriteByte(']')
		case string:
			out.Write(stringBytes(x))
		case json.Number:
			n, e := x.Int64()
			if e != nil {
				return refused
			}
			out.WriteString(strconv.FormatInt(n, 10))
		case bool:
			out.WriteString(strconv.FormatBool(x))
		case nil:
			out.WriteString("null")
		default:
			return refused
		}
		return nil
	}
	if e := write(value); e != nil {
		return nil, e
	}
	return out.Bytes(), nil
}

// Closed public input checks shared by DEV and pilot factory anchors.
func ValidJSON(raw []byte) bool   { _, e := parse(raw); return e == nil }
func ValidOrigin(s string) bool   { return origin(s) }
func ValidEndpoint(s string) bool { return endpoint(s) }
