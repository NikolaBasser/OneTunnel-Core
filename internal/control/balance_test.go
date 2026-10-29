package control

import (
	"bytes"
	"reflect"
	"testing"
)

func TestBalanceRequestWireAndValidation(t *testing.T) {
	p := Profile{ID: "11111111-1111-4111-8111-111111111111", Protocol: 6, Source: "http://127.0.0.1:1080", Group: "A"}
	a := p
	a.ID = "22222222-2222-4222-8222-222222222222"
	a.Group = "B"
	b := a
	b.ID = "33333333-3333-4333-8333-333333333333"
	b.Group = "manual"
	r := Request{Version: Version, Command: "start", Profile: &p, Balance: &Balance{Mode: "balanced", Best: 2, Interval: 30, MaxRTT: 1500, Members: []Profile{a, b}}}
	if code := Validate(r); code != "" {
		t.Fatal(code)
	}
	var wire bytes.Buffer
	if e := WriteFrame(&wire, r); e != nil {
		t.Fatal(e)
	}
	got, e := ReadFrame[Request](&wire)
	if e != nil || !reflect.DeepEqual(got, r) {
		t.Fatal("pool snapshot changed at IPC boundary", e)
	}
	r.Balance.Automatic = true
	r.Balance.Best = 8
	if code := Validate(r); code != "" {
		t.Fatal("automatic candidate snapshot rejected", code)
	}
	wire.Reset()
	if err := WriteFrame(&wire, r); err != nil {
		t.Fatal(err)
	}
	got, e = ReadFrame[Request](&wire)
	if e != nil || !reflect.DeepEqual(got, r) {
		t.Fatal("automatic mode lost at IPC boundary", e)
	}
	r.Balance.Automatic = false
	r.Balance.Best = 2
	r.Balance.Members[1] = a
	if Validate(r) == "" {
		t.Fatal("duplicate pool identity accepted")
	}
	r.Balance.Members[1] = b
	r.Command = "stop"
	if Validate(r) == "" {
		t.Fatal("pool accepted on stop")
	}
	r.Command = "start"
	r.Balance.Best = 9
	if Validate(r) == "" {
		t.Fatal("pool limit bypass")
	}
}
