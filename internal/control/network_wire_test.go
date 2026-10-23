package control

import (
	"bytes"
	"encoding/json"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"testing"
)

func TestLegacyDecoderRejectsNetworkPolicyInPrimaryAndFallback(t *testing.T) {
	type oldProfile struct {
		ID       string `json:"Id"`
		Name     string
		Protocol int
		Source   string
		Group    string
	}
	type oldRequest struct {
		Version    int
		Command    string
		Profile    *oldProfile
		FullDevice bool
		Fallbacks  []oldProfile
	}
	p := Profile{ID: "11111111-1111-4111-8111-111111111111", Name: "Synthetic", Protocol: 3, Source: "socks5://127.0.0.1:1080", Group: "Manual"}
	policy := &protocol.NetworkOptions{Rules: []protocol.NetworkRule{{Kind: "cidr", Value: "192.0.2.1", Action: "reject"}}}
	for _, where := range []string{"primary", "fallback"} {
		t.Run(where, func(t *testing.T) {
			request := Request{Version: 1, Command: "start", Profile: &p, FullDevice: true}
			primary := p
			request.Profile = &primary
			if where == "primary" {
				primary.Network = policy
			} else {
				fallback := p
				fallback.Network = policy
				request.Fallbacks = []Profile{fallback}
			}
			var frame bytes.Buffer
			if err := WriteFrame(&frame, request); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadFrame[oldRequest](&frame); err == nil {
				t.Fatal("old strict service silently dropped policy")
			}
		})
	}
	raw, _ := json.Marshal(Request{Version: 1, Command: "start", Profile: &p, FullDevice: true})
	if bytes.Contains(raw, []byte(`"Network"`)) {
		t.Fatal("nil policy changed legacy wire schema")
	}
	var frame bytes.Buffer
	malicious := []byte(`{"Version":1,"Command":"start","FullDevice":true,"Profile":{"Id":"11111111-1111-4111-8111-111111111111","Name":"Synthetic","Protocol":3,"Source":"socks5://127.0.0.1:1080","Group":"Manual","Network":{"Unexpected":"do not silently drop"}}}`)
	if err := WriteFrame(&frame, json.RawMessage(malicious)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame[Request](&frame); err == nil {
		t.Fatal("unknown nested policy field accepted")
	}
}
