package embeddedawg

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAWG31EncryptedRoundTrip(t *testing.T) {
	a, b := startPairMode(t, true, true)
	listener, e := b.stack.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.2:8088"))
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		c, e := listener.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c, e := a.DialContext(ctx, "tcp", "10.77.0.2:8088")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	want := strings.Repeat("AWG31", 64)
	if _, e = c.Write([]byte(want)); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(want))
	if _, e = io.ReadFull(c, got); e != nil || string(got) != want {
		t.Fatal("encrypted AWG3.1 payload mismatch", e)
	}
}
func TestAWG31ImportUAPIPreservesFields(t *testing.T) {
	private, _ := testKeyPair(t)
	_, public := testKeyPair(t)
	source := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=10.77.0.1/32\nS1=16\nS2=16\nS3=16\nS4=16\nHeaderProtectionKey=%s\nContentPaddingAddition=0-16\nRekeyAfterTime=110-130\nRekeyTimeout=4-6\nRejectAfterTime=170-190\nKeepaliveTimeout=20-30\nMaxHandshakeAttempts=12-18\nRandomTrailers=on\nDisableCookies=off\n[Peer]\nPublicKey=%s\nAllowedIPs=10.77.0.2/32\nEndpoint=127.0.0.1:51820\n", private, private, public)
	p, e := Parse(source, 0, false)
	if e != nil {
		t.Fatal(e)
	}
	data, e := p.UAPI()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(data)
	for _, key := range []string{"header_protection_key=", "content_padding_addition=0-16", "rekey_after_time=110-130", "rekey_timeout=4-6", "reject_after_time=170-190", "keepalive_timeout=20-30", "max_handshake_attempts=12-18", "random_trailers=true", "disable_cookies=false"} {
		if !strings.Contains(string(data), key) {
			t.Fatal("AWG3.1 field lost", strings.Split(key, "=")[0])
		}
	}
	if _, e := Parse(source, 1, false); e == nil {
		t.Fatal("WG accepted AWG3.1 fields")
	}
}
