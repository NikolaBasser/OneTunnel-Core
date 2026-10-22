package platform

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"math/bits"
	"net"
	"onetunnel/core/internal/control"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

const liveLockOwner = "OneTunnel.Embedded.LiveFixture.20261022"

// Built separately without embedded engine dependencies. Recovery is confined
// to this fixture's provider and journal, never the installed service's state.
func TestLiveIndependentRecovery(t *testing.T) {
	if os.Getenv("ONETUNNEL_LIVE_RECOVER") != "1" {
		t.Skip("independent elevated guard only")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("elevation required")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(filepath.Dir(exe), "private-runtime")
	if _, err = os.Stat(filepath.Join(root, "runtime")); err != nil {
		t.Fatal("fixture runtime unavailable")
	}
	r := &Runtime{root: root, directory: filepath.Dir(exe), lock: trafficLock{liveLockOwner, root}, update: func(control.State) {}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = r.recover(ctx); err != nil {
		t.Fatal("fixture recovery failed")
	}
	if r.recovery() {
		t.Fatal("fixture policy or journal remains")
	}
}

// A different executable identity from the embedded worker is essential:
// the service process itself is a deliberate WFP transport exception.
func TestLiveIndependentClient(t *testing.T) {
	mode := os.Getenv("ONETUNNEL_LIVE_CLIENT")
	if mode == "" {
		t.Skip("explicit client fixture only")
	}
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	var input struct{ Interface string }
	b, err := os.ReadFile(filepath.Join(dir, "client-input.json"))
	if err != nil || json.Unmarshal(b, &input) != nil {
		t.Fatal("client input missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 17*time.Second)
	defer cancel()
	begin := time.Now().UnixMilli()
	healthy := httpsCheck(ctx, 0) == nil
	blocked := map[string]bool{}
	codes := map[string]int{}
	globalV6 := false
	for _, kind := range []string{"tcp4", "tcp-dns4", "udp4", "tcp6"} {
		family := kind
		if kind == "tcp-dns4" {
			family = "tcp4"
		}
		address := "1.1.1.1:443"
		if family == "udp4" || kind == "tcp-dns4" {
			address = "1.1.1.1:53"
		}
		if family == "tcp6" {
			address = "[2606:4700:4700::1111]:443"
		}
		interfaces, buffer, e := adapters()
		if e != nil {
			t.Fatal("adapter query failed")
		}
		var idx uint32
		var source net.IP
		for _, a := range interfaces {
			if windows.UTF16PtrToString(a.FriendlyName) == input.Interface {
				idx = a.IfIndex
				if family == "tcp6" {
					idx = a.Ipv6IfIndex
				}
				for u := a.FirstUnicastAddress; u != nil; u = u.Next {
					ip := u.Address.IP()
					if family != "tcp6" && ip.To4() != nil {
						source = ip
						break
					}
					if family == "tcp6" && ip.To4() == nil && ip.IsGlobalUnicast() {
						source = ip
						globalV6 = true
						break
					}
				}
			}
		}
		keep(buffer)
		if idx == 0 {
			continue
		}
		d := net.Dialer{Timeout: time.Second, Control: func(_ string, _ string, raw syscall.RawConn) error {
			var e error
			outer := raw.Control(func(fd uintptr) {
				level := windows.IPPROTO_IP
				index := int(bits.ReverseBytes32(idx))
				if family == "tcp6" {
					level = windows.IPPROTO_IPV6
					index = int(idx)
				}
				e = windows.SetsockoptInt(windows.Handle(fd), level, 31, index)
			})
			if outer != nil {
				return outer
			}
			return e
		}}
		if source != nil {
			port := 60001
			if kind == "tcp-dns4" {
				port = 60002
			}
			if kind == "udp4" {
				port = 60003
			}
			if kind == "tcp6" {
				port = 60004
			}
			switch mode {
			case "baseline":
				port += 10
			case "connected":
				port += 20
			case "broken":
				port += 30
			case "restored":
				port += 40
			}
			if family == "udp4" {
				d.LocalAddr = &net.UDPAddr{IP: source, Port: port}
			} else {
				d.LocalAddr = &net.TCPAddr{IP: source, Port: port}
			}
		}
		c, e := d.DialContext(ctx, family, address)
		if e == nil {
			if family == "udp4" {
				_, e = c.Write([]byte{0x6f, 0x74, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1})
			}
			c.Close()
		}
		blocked[kind] = errors.Is(e, windows.WSAEACCES)
		var errno syscall.Errno
		if errors.As(e, &errno) {
			codes[kind] = int(errno)
		}
	}
	query := "onetunnel-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ".example.com"
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = net.DefaultResolver.LookupIPAddr(dnsCtx, query)
	dnsCancel()
	data, _ := json.Marshal(map[string]any{"HTTPS": healthy, "PhysicalDenied": blocked, "SocketErrors": codes, "GlobalIPv6Available": globalV6, "Mode": mode, "BeginMilliseconds": begin, "EndMilliseconds": time.Now().UnixMilli(), "DNSCanary": query})
	if os.WriteFile(filepath.Join(dir, "client-"+mode+".json"), data, 0600) != nil {
		t.Fatal("client report failed")
	}
}
