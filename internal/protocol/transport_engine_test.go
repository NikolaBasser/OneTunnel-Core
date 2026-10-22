package protocol

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"onetunnel/core/internal/embeddedxray"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Optional pinned-engine integration. All sockets bind loopback, all identities
// are synthetic, and no Windows route, DNS setting or firewall is changed.
func launchOptionEngine(t *testing.T, source string, kind int, o *TransportOptions) int {
	t.Helper()
	engine := os.Getenv("ONETUNNEL_TEST_XRAY")
	embedded := os.Getenv("ONETUNNEL_TEST_EMBEDDED_XRAY") == "1"
	if engine == "" && !embedded {
		t.Skip("set ONETUNNEL_TEST_XRAY for pinned-engine packet verification")
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	p, e := CompileWithOptions(source, kind, false, port+1, port, engine, o)
	if e != nil {
		t.Fatal(e)
	}
	if embedded {
		instance, err := embeddedxray.Start([]byte(p.Xray))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := instance.Close(); err != nil {
				t.Error(err)
			}
		})
		return port
	}
	file := filepath.Join(t.TempDir(), "fixture.json")
	if e = os.WriteFile(file, []byte(p.Xray), 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, engine, "run", "-config", file)
	if e = cmd.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	t.Cleanup(func() { cancel(); cmd.Wait() })
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if e == nil {
			c.Close()
			return port
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("fixture engine did not listen")
	return 0
}

func triggerSOCKS(t *testing.T, port int) net.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(6 * time.Second))
	c.Write([]byte{5, 1, 0})
	var auth [2]byte
	if _, e = io.ReadFull(c, auth[:]); e != nil || auth != [2]byte{5, 0} {
		t.Fatal("SOCKS greeting", e)
	}
	// CONNECT to a loopback-only dummy target. TLS/QUIC starts before the
	// configured proxy server can possibly authenticate this request.
	c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	return c
}

func TestPinnedEngineFragmentRecords(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	o := transportDefaults()
	o.Fragment = true
	o.FragmentLength = "64"
	o.FragmentInterval = "0"
	source := "vless://6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a@" + listener.Addr().String() + "?security=tls&sni=localhost"
	port := launchOptionEngine(t, source, 2, o)
	c := triggerSOCKS(t, port)
	defer c.Close()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	peer, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	total, records := 0, 0
	for {
		var header [5]byte
		if _, e = io.ReadFull(peer, header[:]); e != nil {
			t.Fatal(e)
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || length < 1 || length > 64 {
			t.Fatalf("unfragmented TLS record type=%d length=%d", header[0], length)
		}
		data := make([]byte, length)
		if _, e = io.ReadFull(peer, data); e != nil {
			t.Fatal(e)
		}
		if records == 0 {
			if length < 4 || data[0] != 1 {
				t.Fatal("missing ClientHello")
			}
			total = 4 + (int(data[1])<<16 | int(data[2])<<8 | int(data[3]))
		}
		records++
		total -= length
		if total <= 0 {
			break
		}
	}
	if records < 2 {
		t.Fatal("ClientHello was not split")
	}
	t.Logf("observed %d TLS records, each <=64 bytes", records)
}

func TestPinnedEngineUDPNoise(t *testing.T) {
	listener, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	o := transportDefaults()
	o.Noise = true
	o.NoiseLength = "64"
	o.NoiseDelay = "0"
	port := launchOptionEngine(t, "hy2://synthetic-password@"+listener.LocalAddr().String()+"?sni=localhost", 4, o)
	c := triggerSOCKS(t, port)
	defer c.Close()
	listener.SetReadDeadline(time.Now().Add(5 * time.Second))
	packet := make([]byte, 4096)
	n, addr, e := listener.ReadFrom(packet)
	if e != nil {
		t.Fatal(e)
	}
	if n != 64 {
		t.Fatalf("expected a 64-byte noise before QUIC; received %d", n)
	}
	first := append([]byte(nil), packet[:n]...)
	n, next, e := listener.ReadFrom(packet)
	if e != nil {
		t.Fatal(e)
	}
	if addr.String() != next.String() || n < 1200 || packet[0]&0xc0 != 0xc0 {
		t.Fatal("noise not followed by QUIC on the same connection")
	}
	allZero := true
	for _, v := range first {
		allZero = allZero && v == 0
	}
	if allZero {
		t.Fatal("noise not random")
	}
	t.Log("64-byte random UDP noise precedes QUIC Initial on the same socket")
}
