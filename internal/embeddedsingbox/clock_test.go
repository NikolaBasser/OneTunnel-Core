package embeddedsingbox

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

func fakeNTP(t *testing.T, offset time.Duration, valid bool) int {
	t.Helper()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	go func() {
		buffer := make([]byte, 512)
		for {
			n, peer, err := socket.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 48 {
				continue
			}
			response := make([]byte, 48)
			response[0] = 0x24
			response[1] = 1
			response[2] = 6
			response[3] = 236
			if !valid {
				response[1] = 0
			}
			now := time.Now().Add(offset)
			stamp := (uint64(now.Unix()+2208988800) << 32) | uint64(now.Nanosecond())*(1<<32)/1000000000
			binary.BigEndian.PutUint64(response[16:24], stamp)
			copy(response[24:32], buffer[40:48])
			binary.BigEndian.PutUint64(response[32:40], stamp)
			binary.BigEndian.PutUint64(response[40:48], stamp)
			socket.WriteTo(response, peer)
		}
	}()
	return socket.LocalAddr().(*net.UDPAddr).Port
}

func TestPrivateClock(t *testing.T) {
	port := fakeNTP(t, 2*time.Minute, true)
	engine := startJSON(t, map[string]any{"ntp": map[string]any{"enabled": true, "server": "127.0.0.1", "server_port": port}, "outbounds": []any{map[string]any{"type": "direct"}}})
	if !engine.ClockSynchronized() {
		t.Fatal("private clock not ready")
	}
	offset := engine.clock.TimeFunc()().Sub(time.Now())
	if offset < 119*time.Second || offset > 121*time.Second {
		t.Fatal("wrong private offset", offset)
	}
	invalidPort := fakeNTP(t, 0, false)
	data := []byte(fmt.Sprintf(`{"ntp":{"enabled":true,"server":"127.0.0.1","server_port":%d}}`, invalidPort))
	if invalid, err := Start(data); err == nil {
		invalid.Close()
		t.Fatal("invalid NTP accepted")
	}
	if invalid, err := Start([]byte(`{"ntp":{"enabled":true,"write_to_system":true,"server":"127.0.0.1"}}`)); err == nil {
		invalid.Close()
		t.Fatal("system clock write accepted")
	}
}
