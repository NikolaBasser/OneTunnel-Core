package control

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func testProfile() *Profile {
	return &Profile{ID: "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a", Name: "🇩🇪 Test 👩🏽‍💻", Protocol: 2, Source: "vless://test", Group: "🇩🇪 Servers"}
}
func TestContractRoundTrip(t *testing.T) {
	request := Request{Version: 1, Command: "start", Profile: testProfile(), FullDevice: true}
	var b bytes.Buffer
	if err := WriteFrame(&b, request); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame[Request](&b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile.Name != request.Profile.Name || got.Profile.Protocol != 2 || !got.FullDevice || Validate(got) != "" {
		t.Fatal("desktop contract mismatch")
	}
	data, _ := json.Marshal(Response{Version: 1, Instance: "test", State: State{Status: "Отключено"}})
	if !bytes.Contains(data, []byte(`"ProfileId":null`)) || !bytes.Contains(data, []byte(`"Error":null`)) {
		t.Fatal("nullable desktop fields changed")
	}
}
func TestRejectFrameBeforeAllocation(t *testing.T) {
	for _, n := range []uint32{0, 1, MaxFrameBytes + 1, 0xffffffff} {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.LittleEndian, n)
		if _, err := ReadFrame[Request](&b); err == nil {
			t.Fatalf("accepted length %d", n)
		}
	}
}
func TestMalformedJsonAndSchema(t *testing.T) {
	for _, text := range []string{`{"Version":1,"Command":"status","Executable":"bad.exe"}`, `{"Version":1} {}`, `{"Version":"one"}`, `{"Profile":{"Source":` + strings.Repeat("[", 50) + `0` + strings.Repeat("]", 50) + `}}`, `{"Command":`} {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.LittleEndian, uint32(len(text)))
		b.WriteString(text)
		if _, err := ReadFrame[Request](&b); err == nil {
			t.Fatal("accepted malformed schema")
		}
	}
}
func TestTruncatedFrame(t *testing.T) {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(100))
	b.WriteString("{}")
	if _, err := ReadFrame[Request](&b); err != io.ErrUnexpectedEOF {
		t.Fatal("truncation not detected")
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}
func TestPartialWrites(t *testing.T) {
	w := &shortWriter{}
	if WriteFrame(w, Request{Version: 1, Command: "status"}) != nil {
		t.Fatal("write failed")
	}
	if _, err := ReadFrame[Request](&w.Buffer); err != nil {
		t.Fatal(err)
	}
}
func TestRequestValidation(t *testing.T) {
	for _, command := range []string{"hello", "status", "stop", "recover", "probe"} {
		if Validate(Request{Version: 1, Command: command}) != "" {
			t.Fatal(command)
		}
	}
	cases := []struct {
		r    Request
		code string
	}{
		{Request{Version: 2, Command: "status"}, "incompatible_version"},
		{Request{Version: 1, Command: "execute"}, "unknown_command"},
		{Request{Version: 1, Command: "status", FullDevice: true}, "invalid_request"},
		{Request{Version: 1, Command: "stop", Profile: testProfile()}, "invalid_request"},
		{Request{Version: 1, Command: "start"}, "invalid_configuration"},
	}
	for _, c := range cases {
		if got := Validate(c.r); got != c.code {
			t.Fatalf("%s != %s", got, c.code)
		}
	}
	for protocol := 0; protocol < 6; protocol++ {
		p := testProfile()
		p.Protocol = protocol
		if Validate(Request{Version: 1, Command: "start", Profile: p}) != "" {
			t.Fatal("lost protocol")
		}
	}
	for _, change := range []func(*Profile){func(p *Profile) { p.ID = "../../bad" }, func(p *Profile) { p.Protocol = 11 }, func(p *Profile) { p.ID = "00000000-0000-0000-0000-000000000000" }, func(p *Profile) { p.Source = strings.Repeat("x", 131073) }, func(p *Profile) { p.Name = strings.Repeat("😀", 2049) }} {
		p := testProfile()
		change(p)
		if Validate(Request{Version: 1, Command: "start", Profile: p}) != "invalid_configuration" {
			t.Fatal("accepted invalid profile")
		}
	}
}
