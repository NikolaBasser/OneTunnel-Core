package control

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestBundleBoundaryPreservesProfileOptions(t *testing.T) {
	profile := *testProfile()
	profile.Reliability = &ReliabilityOptions{AutoReconnect: true, UseFallbacks: true}
	profile.Transport = &protocol.TransportOptions{Fragment: true, FragmentLength: "100-200", FragmentInterval: "10-20", Mux: true, MuxConcurrency: 8}
	request := Request{Version: Version, Command: "start", Profile: &profile, FullDevice: true}
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, request); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame[Request](&buffer)
	if err != nil || !reflect.DeepEqual(got, request) {
		t.Fatal("IPC bundle boundary changed profile settings")
	}
}
