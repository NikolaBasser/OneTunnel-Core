package profiles

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"os"
	"strings"
	"testing"
)

const vless = "vless://6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a@127.0.0.1:443?security=tls&sni=localhost"

func fixture(t *testing.T, name, source string) Profile {
	t.Helper()
	p, e := Parse(name, source, nil)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestImportsAgainstCompilerParityCorpus(t *testing.T) {
	data, e := os.ReadFile("../protocol/testdata/parity.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Kind   int
		Source string
	}
	if json.Unmarshal(data, &cases) != nil {
		t.Fatal("corpus")
	}
	if len(cases) != 126 {
		t.Fatal("fixture count changed")
	}
	for i, c := range cases {
		p, e := Parse("Fixture", c.Source, &c.Kind)
		if e != nil || p.Protocol != c.Kind || p.Source != strings.TrimSpace(c.Source) {
			t.Fatalf("import parity case %d kind %d: %v", i, c.Kind, e)
		}
	}
}
func TestUnicodeImportNamesAndBounds(t *testing.T) {
	family := "👨‍👩‍👧‍👦"
	name := strings.Repeat("🇩🇪", 99) + family + "overflow"
	truncated := ImportedName(name)
	if truncated != strings.Repeat("🇩🇪", 99)+family || !ValidName(truncated) || ValidName(name) {
		t.Fatal("grapheme limit")
	}
	for _, bad := range []string{"bad\nname", string([]byte{0xff})} {
		if ValidName(bad) {
			t.Fatal("invalid Unicode name")
		}
	}
	if _, e := Parse("bad\nname", vless, nil); e == nil {
		t.Fatal("controls accepted")
	}
	if _, e := Parse("", vless+"#%F0%9F%87%A9%F0%9F%87%AA", nil); e != nil {
		t.Fatal(e)
	}
}
func TestSubscriptionFormatsAndSafety(t *testing.T) {
	text := vless + "#one\n" + vless + "#alias\nsocks5://127.0.0.1:1080\ntrojan://unsupported"
	r, e := ParseSubscription(text)
	if e != nil || len(r.Profiles) != 2 || r.Duplicates != 1 || r.Skipped != 1 {
		t.Fatal("text", e)
	}
	r, e = ParseSubscription(base64.RawURLEncoding.EncodeToString([]byte(text)))
	if e != nil || len(r.Profiles) != 2 {
		t.Fatal("base64", e)
	}
	out, _ := protocol.Outbound(vless, 2)
	jsonBytes, _ := json.Marshal([]any{map[string]any{"remarks": "🇩🇪 Node", "outbounds": []any{out, map[string]any{"protocol": "freedom"}}}})
	r, e = ParseSubscription(string(jsonBytes))
	if e != nil || len(r.Profiles) != 1 || r.Profiles[0].Name != "🇩🇪 Node" {
		t.Fatal("JSON", e)
	}
	out["proxySettings"] = map[string]any{"tag": "other"}
	jsonBytes, _ = json.Marshal(out)
	if _, e = ParseSubscription(string(jsonBytes)); e == nil {
		t.Fatal("unsafe chain imported")
	}
	if _, e = ParseSubscription(strings.Repeat("a", MaxBytes+1)); e == nil {
		t.Fatal("unbounded input")
	}
	if _, e = ParseSubscription(strings.Repeat(vless+"\n", 2001)); e == nil {
		t.Fatal("unbounded candidates")
	}
	if SecureURL("http://example.com") || SecureURL("https://user:pass@example.com") || !SecureURL("https://example.com/sub") {
		t.Fatal("HTTPS validation")
	}
}
func TestAmneziaCompressedImport(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	conf := "[Interface]\nPrivateKey = " + key + "\nAddress = 10.9.0.2/32\nJc = 3\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\n[Peer]\nPublicKey = " + key + "\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 10.9.0.1/32"
	last, _ := json.Marshal(map[string]any{"config": conf})
	root, _ := json.Marshal(map[string]any{"description": "🇩🇪 Amnezia", "dns1": "1.1.1.1", "dns2": "", "containers": []any{map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": string(last)}}}})
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(root)))
	writer := zlib.NewWriter(&b)
	writer.Write(root)
	writer.Close()
	p, e := Parse("", "vpn://"+base64.RawURLEncoding.EncodeToString(b.Bytes()), nil)
	if e != nil || p.Protocol != 0 || p.Name != "🇩🇪 Amnezia" || !strings.Contains(p.Source, "DNS = 1.1.1.1") {
		t.Fatal("Amnezia", e)
	}
	bad := append([]byte(nil), b.Bytes()...)
	binary.BigEndian.PutUint32(bad, MaxBytes+1)
	if _, e = Parse("", "vpn://"+base64.RawURLEncoding.EncodeToString(bad), nil); e == nil {
		t.Fatal("decompression limit")
	}
}
func TestSubscriptionMergePreservesPreferences(t *testing.T) {
	old := fixture(t, "Node", vless)
	old.Group = "subscription"
	old.Transport = &protocol.TransportOptions{Fragment: true, FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", MuxConcurrency: 8}
	retired := fixture(t, "Retired", strings.ReplaceAll(vless, ":443", ":444"))
	retired.Group = old.Group
	personal := fixture(t, "Personal", vless)
	fresh := fixture(t, "Node", strings.ReplaceAll(vless, ":443", ":445"))
	r, e := Merge([]Profile{old, retired, personal}, []Profile{fresh}, old.Group)
	if e != nil || r.Updated != 1 || r.Removed != 1 || r.Added != 0 || len(r.Profiles) != 2 || r.Profiles[0].ID != old.ID || r.Profiles[0].Transport != old.Transport || r.Profiles[1].ID != personal.ID {
		t.Fatal("merge", e)
	}
	empty, e := Merge(r.Profiles, nil, old.Group)
	if e != nil || len(empty.Profiles) != 2 {
		t.Fatal("empty cleared profiles")
	}
}
