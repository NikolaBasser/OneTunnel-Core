package control

import "testing"

func TestQualitySelectionValidation(t *testing.T) {
	p := Profile{ID: "11111111-1111-4111-8111-111111111111", Protocol: 6, Source: "http://127.0.0.1:8080", Reliability: &ReliabilityOptions{AutoReconnect: true, UseFallbacks: true, AutoSelect: true}}
	r := Request{Version: Version, Command: "start", Profile: &p}
	if Validate(r) != "" {
		t.Fatal("valid proxy quality mode rejected")
	}
	r.FullDevice = true
	if Validate(r) != "" {
		t.Fatal("TUN quality mode rejected")
	}
	r.FullDevice = false
	p.Protocol = 0
	if Validate(r) != "" {
		t.Fatal("native quality mode rejected")
	}
	p.Protocol = 6
	p.Reliability.UseFallbacks = false
	if Validate(r) == "" {
		t.Fatal("quality without fallback permission accepted")
	}
}
