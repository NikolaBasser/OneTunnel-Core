package platform

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"onetunnel/core/internal/control"
	"onetunnel/core/internal/protocol"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var liveSocksFixture func(string) (control.Profile, func(), error)

// This phase deliberately uses proxy-only profiles. Native adapters and global
// routes are tested separately, after the independent recovery guard is armed.
func TestLiveSubscriptionProxy(t *testing.T) {
	root := os.Getenv("ONETUNNEL_LIVE_DIRECTORY")
	if root == "" {
		t.Skip("explicit protected subscription copy required")
	}
	encrypted, err := os.ReadFile(filepath.Join(root, "profiles-machine.bin"))
	if err != nil {
		t.Fatal("protected copy unavailable")
	}
	in := windows.DataBlob{Size: uint32(len(encrypted)), Data: &encrypted[0]}
	var out windows.DataBlob
	if windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out) != nil {
		t.Fatal("protected copy inaccessible")
	}
	plain := unsafe.Slice(out.Data, out.Size)
	var profiles []control.Profile
	err = json.Unmarshal(plain, &profiles)
	clear(plain)
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if err != nil {
		t.Fatal("invalid protected copy")
	}
	type result struct {
		Index       int
		Protocol    int
		Started     bool
		HTTPS       bool
		Cleanup     bool
		Stage       string
		ErrorCode   string
		Transport   string
		Security    string
		EndpointTCP *bool `json:",omitempty"`
	}
	results := []result{}
	for i := range profiles {
		p := profiles[i]
		if selected := os.Getenv("ONETUNNEL_LIVE_INDEX"); selected != "" && !strings.Contains(","+selected+",", ","+strconv.Itoa(i)+",") {
			continue
		}
		if p.Protocol < 2 || p.Protocol > 5 {
			continue
		}
		row := result{Index: i, Protocol: p.Protocol, Stage: "start"}
		if outbound, e := protocol.Outbound(p.Source, p.Protocol); e == nil {
			stream := jObject(outbound["streamSettings"])
			row.Transport = jString(stream["network"])
			row.Security = jString(stream["security"])
			if os.Getenv("ONETUNNEL_LIVE_ENDPOINT_CHECK") == "1" && p.Protocol == 2 {
				server := first(jObject(outbound["settings"])["vnext"])
				host := jString(server["address"])
				encoded, _ := json.Marshal(server["port"])
				port, _ := strconv.Atoi(string(encoded))
				connection, e := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 4*time.Second)
				ok := e == nil
				if connection != nil {
					connection.Close()
				}
				row.EndpointTCP = &ok
			}
		}
		runtimeRoot := filepath.Join(root, "proxy-runtime")
		if err = os.MkdirAll(filepath.Join(runtimeRoot, "runtime"), 0700); err != nil {
			t.Fatal("private runtime unavailable")
		}
		directory := root
		if app := os.Getenv("ONETUNNEL_LIVE_APP_DIRECTORY"); app != "" {
			directory = app
		}
		r := &Runtime{root: runtimeRoot, directory: directory, lock: trafficLock{root: runtimeRoot}, update: func(control.State) {}}
		ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
		err = r.start(ctx, control.Request{Version: 1, Command: "start", Profile: &p})
		row.Started = err == nil
		if err == nil {
			row.Stage = "https"
			_, err = r.probe(ctx)
			row.HTTPS = err == nil
		}
		cancel()
		if err != nil {
			row.ErrorCode = "request_failed"
			var ne net.Error
			var se syscall.Errno
			if errors.As(err, &ne) && ne.Timeout() {
				row.ErrorCode = "timeout"
			}
			if errors.As(err, &se) {
				row.ErrorCode = "socket_" + strconv.Itoa(int(se))
			}
			for _, safe := range []string{"embedded clock not ready", "embedded sing-box startup failed", "embedded sing-box initialization failed", "invalid embedded sing-box configuration", "embedded Xray startup failed", "clock", "NTP", "time synchronization"} {
				if strings.Contains(err.Error(), safe) {
					row.ErrorCode = safe
					break
				}
			}
		}
		cleanup, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
		e := r.disconnect(cleanup)
		cancelCleanup()
		row.Cleanup = e == nil && !r.recovery()
		if row.HTTPS && row.Cleanup {
			row.Stage = "passed"
		}
		results = append(results, row)
		data, _ := json.MarshalIndent(map[string]any{"GlobalNetworkChanged": false, "Results": results}, "", "  ")
		name := "proxy-results.json"
		if os.Getenv("ONETUNNEL_LIVE_APP_DIRECTORY") != "" {
			name = "proxy-external-results.json"
		}
		if os.WriteFile(filepath.Join(root, name), data, 0600) != nil {
			t.Fatal("report unavailable")
		}
		t.Logf("profile %d protocol %d: %s, cleanup=%v", i, p.Protocol, row.Stage, row.Cleanup)
		if !row.Cleanup {
			t.Fatal("cleanup failed; stopping further tests")
		}
	}
}

func TestLiveDeviceGuarded(t *testing.T) {
	if os.Getenv("ONETUNNEL_LIVE_DEVICE") != "1" {
		t.Skip("explicit guarded device fixture only")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("elevation required")
	}
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	deadline := time.Now().Add(8 * time.Second)
	for {
		b, _ := os.ReadFile(filepath.Join(dir, "guard-ready"))
		if string(b) == strconv.Itoa(os.Getpid()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("independent recovery guard not ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if os.Getenv("ONETUNNEL_LIVE_GUARD_DRILL") == "1" {
		time.Sleep(30 * time.Second)
		t.Fatal("guard did not terminate drill")
	}
	index, err := strconv.Atoi(os.Getenv("ONETUNNEL_LIVE_INDEX"))
	if err != nil {
		t.Fatal("profile index required")
	}
	b, err := os.ReadFile(filepath.Join(dir, "profiles-machine.bin"))
	if err != nil {
		t.Fatal("protected profiles missing")
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out) != nil {
		t.Fatal("profile decryption failed")
	}
	plain := unsafe.Slice(out.Data, out.Size)
	var profiles []control.Profile
	err = json.Unmarshal(plain, &profiles)
	clear(plain)
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if err != nil || index < 0 || index > len(profiles) {
		t.Fatal("invalid profile index")
	}
	physical, err := routeInterface("1.1.1.1")
	if err != nil || strings.HasPrefix(physical, "OneTunnel") {
		t.Fatal("physical baseline unavailable")
	}
	if index == len(profiles) {
		if liveSocksFixture == nil {
			t.Fatal("embedded SOCKS fixture unavailable")
		}
		p, closeFixture, e := liveSocksFixture(physical)
		if e != nil {
			t.Fatal("SOCKS fixture startup failed")
		}
		defer closeFixture()
		profiles = append(profiles, p)
	}
	adapter, e := net.InterfaceByName(physical)
	if e != nil {
		t.Fatal("physical adapter unavailable")
	}
	input, _ := json.Marshal(map[string]string{"Interface": physical, "MAC": adapter.HardwareAddr.String()})
	if os.WriteFile(filepath.Join(dir, "client-input.json"), input, 0600) != nil {
		t.Fatal("client setup failed")
	}
	client := func(mode string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(dir, "recovery.test.exe"), "-test.run=^TestLiveIndependentClient$", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), "ONETUNNEL_LIVE_CLIENT="+mode)
		if cmd.Run() != nil {
			return false
		}
		b, e := os.ReadFile(filepath.Join(dir, "client-"+mode+".json"))
		var result struct {
			HTTPS               bool
			PhysicalDenied      map[string]bool
			GlobalIPv6Available bool
		}
		if e != nil || json.Unmarshal(b, &result) != nil {
			return false
		}
		if mode == "baseline" || mode == "restored" {
			return result.HTTPS
		}
		if mode == "connected" && !result.HTTPS {
			return false
		}
		if mode == "broken" && result.HTTPS {
			return false
		}
		return result.PhysicalDenied["tcp4"] && result.PhysicalDenied["tcp-dns4"] && (!result.GlobalIPv6Available || result.PhysicalDenied["tcp6"])
	}
	if !client("baseline") {
		t.Fatal("ordinary HTTPS baseline failed")
	}
	root := filepath.Join(dir, "private-runtime")
	if err = privateDirectory(filepath.Join(root, "runtime")); err != nil {
		t.Fatal("private runtime setup failed")
	}
	r := &Runtime{root: root, directory: dir, lock: trafficLock{liveLockOwner, root}, update: func(control.State) {}}
	if r.recovery() {
		t.Fatal("stale fixture needs independent recovery")
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if r.disconnect(ctx) != nil || r.recovery() {
			t.Error("cleanup failed; guard remains armed")
			return
		}
		after, e := routeInterface("1.1.1.1")
		if e != nil || after != physical || !client("restored") {
			t.Error("network not restored; guard remains armed")
			return
		}
		if os.WriteFile(filepath.Join(dir, "guard-complete"), []byte("restored"), 0600) != nil {
			t.Error("guard completion failed")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err = r.start(ctx, control.Request{Version: 1, Command: "start", Profile: &profiles[index], FullDevice: true}); err != nil {
		t.Fatal("whole-device startup failed")
	}
	if !client("connected") {
		t.Fatal("connected HTTPS or physical bypass protection failed")
	}
	if os.Getenv("ONETUNNEL_LIVE_CRASH_DRILL") == "1" {
		if os.WriteFile(filepath.Join(dir, "crash-ready"), []byte("connected"), 0600) != nil {
			t.Fatal("crash setup failed")
		}
		time.Sleep(2 * time.Minute)
		t.Fatal("crash guard did not terminate worker")
	}
	if r.embeddedXray != nil {
		_ = r.embeddedXray.Close()
	} else if r.embeddedProxy != nil {
		_ = r.embeddedProxy.Close()
	} else if r.embeddedNative != nil {
		_ = r.embeddedNative.Close()
	} else {
		t.Fatal("external engine unexpectedly used")
	}
	r.poll()
	if !r.transportFailed || !r.lock.needed() {
		t.Fatal("engine failure lost protection")
	}
	if !client("broken") {
		t.Fatal("traffic escaped after engine stop")
	}
	result, _ := json.Marshal(map[string]any{"Index": index, "Protocol": profiles[index].Protocol, "ConnectedHTTPS": true, "PhysicalTCPv4Denied": true, "PhysicalTCPDNSv4Denied": true, "EngineStopFailClosed": true, "PacketCaptureRequiredForLeakConclusion": true})
	if os.WriteFile(filepath.Join(dir, "device-result-"+strconv.Itoa(index)+".json"), result, 0600) != nil {
		t.Fatal("device report failed")
	}
}
