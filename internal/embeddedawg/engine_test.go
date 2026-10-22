package embeddedawg

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixtureKeys(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}
func fixtureSource(private, public, address, peer, extra string) string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nListenPort = 0\n%s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\nEndpoint = 127.0.0.1:9\n", private, address, extra, public, peer)
}
func listenPort(t *testing.T, e *Engine) int {
	t.Helper()
	text, err := e.instance.IpcGet()
	if err != nil {
		t.Fatal("unable to read sanitized fixture status")
	}
	for _, line := range strings.Split(text, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.Atoi(value)
			if err == nil && port > 0 {
				return port
			}
		}
	}
	t.Fatal("no UDP listen port")
	return 0
}

func TestWGAndAWGEncryptedPackets(t *testing.T) {
	for _, fixture := range []struct {
		name, extra string
		kind        int
	}{
		{"wireguard", "", 1},
		{"awg-headers-padding", "Jc=2\nJmin=32\nJmax=64\nS1=15\nS2=18\nS3=20\nS4=25\nH1=123456-123500\nH2=67543-67550\nH3=123123-123200\nH4=32345-32350", 0},
		{"awg-signatures", "Jc=1\nJmin=32\nJmax=64\nI1=<b 0xf6ab3267fa><r 10>\nI2=<b 0xf6ab><t><rc 10>\nI3=<rd 10>\nI4=<r 20>\nI5=<b 0x1234>", 0},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			priv0, pub0 := fixtureKeys(t)
			priv1, pub1 := fixtureKeys(t)
			plans := []string{fixtureSource(priv0, pub1, "10.254.20.1", "10.254.20.2", fixture.extra), fixtureSource(priv1, pub0, "10.254.20.2", "10.254.20.1", fixture.extra)}
			adapters := []*tuntest.ChannelTUN{tuntest.NewChannelTUN(), tuntest.NewChannelTUN()}
			engines := make([]*Engine, 2)
			for i := range engines {
				plan, err := Parse(plans[i], fixture.kind, false)
				if err != nil {
					t.Fatal(err)
				}
				engines[i], err = Start(plan, adapters[i].TUN(), conn.NewDefaultBind())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { engines[i].Close() })
			}
			for i := range engines {
				other := i ^ 1
				public := pub1
				if i == 1 {
					public = pub0
				}
				raw, _ := base64.StdEncoding.DecodeString(public)
				if err := engines[i].instance.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\n", hex.EncodeToString(raw), listenPort(t, engines[other]))); err != nil {
					t.Fatal("fixture endpoint update rejected")
				}
			}
			for i := range engines {
				other := i ^ 1
				src := netip.MustParseAddr(fmt.Sprintf("10.254.20.%d", i+1))
				dst := netip.MustParseAddr(fmt.Sprintf("10.254.20.%d", other+1))
				packet := tuntest.Ping(dst, src)
				select {
				case adapters[i].Outbound <- packet:
				case <-time.After(6 * time.Second):
					t.Fatal("packet queue timeout")
				}
				select {
				case received := <-adapters[other].Inbound:
					if !bytes.Equal(packet, received) {
						t.Fatal("decrypted payload mismatch")
					}
				case <-time.After(6 * time.Second):
					t.Fatal("encrypted packet did not transit")
				}
			}
			for _, engine := range engines {
				engine.Close()
				engine.Close()
				select {
				case <-engine.Done():
				default:
					t.Fatal("engine did not stop")
				}
			}
		})
	}
}

func TestAWGConfigConversion(t *testing.T) {
	private, public := fixtureKeys(t)
	source := fixtureSource(private, public, "10.254.20.1", "10.254.20.2", "S1=15\nH1=100-110\nI1=<b 0x1234><r 5>")
	plan, err := Parse(source, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := plan.UAPI()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	for _, field := range []string{"s1=15\n", "h1=100-110\n", "i1=<b 0x1234><r 5>\n", "allowed_ip=10.254.20.2/32\n"} {
		if !bytes.Contains(data, []byte(field)) {
			t.Fatal("conversion lost AWG setting")
		}
	}
	if bytes.Contains(data, []byte(private)) || bytes.Contains(data, []byte("address=")) {
		t.Fatal("metadata or base64 key leaked into UAPI")
	}
	if _, err = Parse(source, 1, false); err == nil {
		t.Fatal("AWG fields accepted as plain WG")
	}
	if err = plan.SetEndpoint("example.com:443"); err == nil {
		t.Fatal("unresolved endpoint accepted")
	}
}

func TestRejectedConfigurationClosesTun(t *testing.T) {
	private, public := fixtureKeys(t)
	plan, err := Parse(fixtureSource(private, public, "10.254.20.1", "10.254.20.2", "H1=2"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	adapter := tuntest.NewChannelTUN()
	if engine, err := Start(plan, adapter.TUN(), conn.NewDefaultBind()); err == nil {
		engine.Close()
		t.Fatal("overlapping headers accepted")
	}
	select {
	case _, open := <-adapter.TUN().Events():
		if open {
			t.Fatal("TUN not closed after rejection")
		}
	case <-time.After(time.Second):
		t.Fatal("rejected engine leaked TUN")
	}
}
