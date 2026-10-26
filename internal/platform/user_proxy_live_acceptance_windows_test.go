//go:build windows && onetunnel_user_proxy_live_acceptance

package platform

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// This opt-in test changes the dedicated server user's real Internet Settings.
// The independent deadline process restores known owned values; unknown edits are preserved.
type liveProxySnapshot struct {
	Values   map[string]map[string]RawRegistryValue
	Deadline time.Time
	Flags    uint32
}

func liveProxyGuard(t *testing.T) {
	t.Helper()
	if os.Getenv("ONETUNNEL_LIVE_PROXY_ACCEPTANCE") != "dedicated-server-only" {
		t.Skip("real proxy acceptance requires explicit dedicated-server opt-in")
	}
	name, err := os.Hostname()
	if err != nil || !strings.EqualFold(name, "WIN-67BE833BA6F") || !strings.EqualFold(os.Getenv("USERNAME"), "codex") {
		t.Fatal("live proxy acceptance is restricted to the rented server's codex user")
	}
}

var liveProxyNames = map[string][]string{
	userProxyRegistryKey:                  {"ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"},
	userProxyRegistryKey + `\Connections`: {"DefaultConnectionSettings", "SavedLegacySettings"},
}

type liveProxyOwned map[string]map[string][]RawRegistryValue

func liveProxySnapshotRead() (liveProxySnapshot, error) {
	s := liveProxySnapshot{Values: map[string]map[string]RawRegistryValue{}, Deadline: time.Now().Add(40 * time.Second)}
	for path, names := range liveProxyNames {
		s.Values[path] = map[string]RawRegistryValue{}
		for _, name := range names {
			value, err := (windowsUserRegistry{}).Read(path, name)
			if err != nil {
				return s, err
			}
			s.Values[path][name] = value
		}
	}
	flags, err := queryWinINETProxyFlags()
	s.Flags = flags
	return s, err
}

func liveProxyOwnedRead(dir string) (liveProxyOwned, error) {
	data, err := os.ReadFile(filepath.Join(dir, "owned.json"))
	if err != nil {
		return nil, err
	}
	var owned liveProxyOwned
	err = json.Unmarshal(data, &owned)
	return owned, err
}

func liveProxyOwnedWrite(dir string, owned liveProxyOwned) error {
	data, err := json.Marshal(owned)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "owned.tmp"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(filepath.Join(dir, "owned.tmp"), filepath.Join(dir, "owned.json"))
}

func liveProxyValueOwned(owned liveProxyOwned, path, name string, current RawRegistryValue) bool {
	for _, candidate := range owned[path][name] {
		if sameRegistryValue(current, candidate) {
			return true
		}
		if path == userProxyRegistryKey+`\Connections` && (name == "DefaultConnectionSettings" || name == "SavedLegacySettings") && liveProxySameBlobConfiguration(current, candidate) {
			return true
		}
	}
	return false
}

// WinINET increments DWORD offset 4 when refreshing a connection blob. Every
// configuration byte, including flags, proxy endpoint, bypass and PAC URL, must match.
func liveProxySameBlobConfiguration(a, b RawRegistryValue) bool {
	return a.Exists && b.Exists && a.Type == registry.BINARY && b.Type == registry.BINARY && len(a.Data) >= 12 && len(a.Data) == len(b.Data) && bytes.Equal(a.Data[:4], b.Data[:4]) && bytes.Equal(a.Data[8:], b.Data[8:])
}

func TestUserProxyLiveBlobOwnership(t *testing.T) {
	baseline := RawRegistryValue{Exists: true, Type: registry.BINARY, Data: []byte{0x46, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 4, 5, 6}}
	for _, tc := range []struct {
		name   string
		offset int
		want   bool
	}{{"counter", 4, true}, {"version", 0, false}, {"flags", 8, false}, {"configuration", 12, false}} {
		t.Run(tc.name, func(t *testing.T) {
			changed := baseline
			changed.Data = append([]byte(nil), baseline.Data...)
			changed.Data[tc.offset]++
			if got := liveProxySameBlobConfiguration(changed, baseline); got != tc.want {
				t.Fatalf("ownership=%t want %t", got, tc.want)
			}
		})
	}
	wrongType := baseline
	wrongType.Type = registry.SZ
	if liveProxySameBlobConfiguration(wrongType, baseline) {
		t.Error("different registry type accepted")
	}
	shorter := baseline
	shorter.Data = shorter.Data[:len(shorter.Data)-1]
	if liveProxySameBlobConfiguration(shorter, baseline) {
		t.Error("different blob length accepted")
	}
}

func liveProxyBlobDescription(v RawRegistryValue) string {
	data := append([]byte(nil), v.Data...)
	header := len(data)
	if header > 12 {
		header = 12
	}
	if len(data) >= 8 {
		clear(data[4:8])
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("exists=%t type=%d len=%d header=%x maskedSHA256=%x", v.Exists, v.Type, len(v.Data), v.Data[:header], sum[:8])
}

func liveProxyLogBlobs(t *testing.T, dir string, s liveProxySnapshot) {
	t.Helper()
	owned, err := liveProxyOwnedRead(dir)
	if err != nil {
		t.Log("owned candidates unreadable:", err)
		return
	}
	path := userProxyRegistryKey + `\Connections`
	for _, name := range liveProxyNames[path] {
		current, err := (windowsUserRegistry{}).Read(path, name)
		if err != nil {
			t.Log(name, err)
			continue
		}
		t.Log(name, "baseline", liveProxyBlobDescription(s.Values[path][name]), "current", liveProxyBlobDescription(current))
		for i, candidate := range owned[path][name] {
			t.Logf("%s candidate %d %s", name, i, liveProxyBlobDescription(candidate))
		}
	}
}

func liveProxySetFlags(flags uint32) error {
	option := internetPerConnectionOption{Option: internetPerConnectionFlags, Value: uintptr(flags)}
	list := internetPerConnectionOptionList{Size: uint32(unsafe.Sizeof(internetPerConnectionOptionList{})), OptionCount: 1, Options: &option}
	ok, _, err := windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW").Call(0, internetOptionPerConnectionOption, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Sizeof(list)))
	if ok == 0 {
		return err
	}
	if list.OptionError != 0 {
		return syscall.Errno(list.OptionError)
	}
	return nil
}

func liveProxyChange(dir string, s liveProxySnapshot, change func() error) error {
	owned, err := liveProxyOwnedRead(dir)
	if err != nil {
		return err
	}
	before, err := liveProxySnapshotRead()
	if err != nil {
		return err
	}
	for path, values := range before.Values {
		for name, old := range values {
			if !sameRegistryValue(old, s.Values[path][name]) && !liveProxyValueOwned(owned, path, name, old) {
				return fmt.Errorf("unowned value blocks fixture notification: %s/%s", path, name)
			}
		}
	}
	if err = change(); err != nil {
		return err
	}
	after, err := liveProxySnapshotRead()
	if err != nil {
		return err
	}
	for path, values := range after.Values {
		if owned[path] == nil {
			owned[path] = map[string][]RawRegistryValue{}
		}
		for name, value := range values {
			owned[path][name] = append(owned[path][name], value)
		}
	}
	return liveProxyOwnedWrite(dir, owned)
}

func liveProxyNotify(dir string, s liveProxySnapshot) error {
	return liveProxyChange(dir, s, notifyWinINet)
}
func liveProxyRestore(dir string, s liveProxySnapshot) error {
	unlock, err := lockUserAutomationTimeout(5000)
	if err != nil {
		return err
	}
	defer unlock()
	owned, err := liveProxyOwnedRead(dir)
	if err != nil {
		return err
	}
	restore := func() error {
		var conflict error
		for path, values := range s.Values {
			for name, baseline := range values {
				current, err := (windowsUserRegistry{}).Read(path, name)
				if err != nil {
					return err
				}
				if sameRegistryValue(current, baseline) {
					continue
				}
				if !liveProxyValueOwned(owned, path, name, current) {
					conflict = fmt.Errorf("foreign value preserved: %s/%s", path, name)
					continue
				}
				if err = (windowsUserRegistry{}).Write(path, name, baseline); err != nil {
					return err
				}
			}
		}
		return conflict
	}
	firstErr := restore()
	notifyErr := liveProxyChange(dir, s, func() error {
		if err := liveProxySetFlags(s.Flags); err != nil {
			return err
		}
		return notifyWinINet()
	})
	owned, err = liveProxyOwnedRead(dir)
	if err != nil {
		return err
	}
	lastErr := restore()
	return errors.Join(firstErr, notifyErr, lastErr)
}
func liveProxyWait(path string, limit time.Duration) error {
	end := time.Now().Add(limit)
	for time.Now().Before(end) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", filepath.Base(path))
}

func liveProxyHelper(t *testing.T, dir, role string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestUserProxyLiveHelper$", "-test.timeout=50s")
	cmd.Env = append(os.Environ(), "ONETUNNEL_LIVE_PROXY_ROLE="+role, "ONETUNNEL_LIVE_PROXY_DIR="+dir)
	if role == "rollback" {
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: userProxyWatchdogCreationFlags()}
	}
	log, err := os.Create(filepath.Join(dir, role+".log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	return cmd
}

func liveProxyArm(lease string, pid uint32, created uint64, _ string) error {
	exe := os.Getenv("ONETUNNEL_LIVE_PROXY_HOST")
	if !filepath.IsAbs(exe) {
		return errors.New("absolute production profile-host executable required")
	}
	eventName := `Local\OneTunnel.ProxyWatchdogAck.` + lease
	name, err := windows.UTF16PtrFromString(eventName)
	if err != nil {
		return err
	}
	event, err := windows.CreateEvent(nil, 1, 0, name)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	cmd := exec.Command(exe, "--user-proxy-watchdog", lease, strconv.FormatUint(uint64(pid), 10), strconv.FormatUint(created, 10), eventName)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: userProxyWatchdogCreationFlags()}
	if err = cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	state, err := windows.WaitForSingleObject(event, 5000)
	if err != nil {
		return err
	}
	if state != windows.WAIT_OBJECT_0 {
		return errors.New("production watchdog did not acknowledge")
	}
	return nil
}

func TestUserProxyLiveHelper(t *testing.T) {
	role := os.Getenv("ONETUNNEL_LIVE_PROXY_ROLE")
	if role == "" {
		t.Skip("helper process")
	}
	liveProxyGuard(t)
	dir := os.Getenv("ONETUNNEL_LIVE_PROXY_DIR")
	if role == "rollback" {
		inJob, err := currentProcessInJob()
		if err = ensureWatchdogOutsideJob(inJob, err); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "baseline.json"))
		if err != nil {
			t.Fatal(err)
		}
		var s liveProxySnapshot
		if err = json.Unmarshal(data, &s); err != nil {
			t.Fatal(err)
		}
		if time.Until(s.Deadline) > 40*time.Second || time.Until(s.Deadline) < 5*time.Second {
			t.Fatal("invalid recovery deadline")
		}
		if err = os.WriteFile(filepath.Join(dir, "rollback-ready"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		for time.Now().Before(s.Deadline) {
			if _, err = os.Stat(filepath.Join(dir, "done")); err == nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err = liveProxyRestore(dir, s); err != nil {
			t.Fatal(err)
		}
		return
	}
	if role != "owner" {
		t.Fatal("unknown helper role")
	}
	data, err := os.ReadFile(filepath.Join(dir, "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s liveProxySnapshot
	if err = json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	p, err := NewUserProxy()
	if err != nil {
		t.Fatal(err)
	}
	p.armWatchdog = liveProxyArm
	p.notify = func() error { return liveProxyNotify(dir, s) }
	address, err := os.ReadFile(filepath.Join(dir, "listener"))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := p.Enable(string(address))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "owner-ready"), []byte(lease), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(35 * time.Second)
}

func liveProxyRequest() error {
	dll := windows.NewLazySystemDLL("wininet.dll")
	agent, _ := windows.UTF16PtrFromString("OneTunnel dedicated acceptance")
	h, _, e := dll.NewProc("InternetOpenW").Call(uintptr(unsafe.Pointer(agent)), 0, 0, 0, 0)
	if h == 0 {
		return e
	}
	defer dll.NewProc("InternetCloseHandle").Call(h)
	timeout := uint32(4000)
	for _, opt := range []uintptr{2, 5, 6} {
		ok, _, err := dll.NewProc("InternetSetOptionW").Call(h, opt, uintptr(unsafe.Pointer(&timeout)), 4)
		if ok == 0 {
			return err
		}
	}
	url, _ := windows.UTF16PtrFromString("https://example.com/?onetunnel=" + strconv.FormatInt(time.Now().UnixNano(), 10))
	r, _, err := dll.NewProc("InternetOpenUrlW").Call(h, uintptr(unsafe.Pointer(url)), 0, 0, 0x80000000|0x04000000|0x00200000, 0)
	if r == 0 {
		return err
	}
	defer dll.NewProc("InternetCloseHandle").Call(r)
	var status uint32
	size := uint32(unsafe.Sizeof(status))
	ok, _, queryErr := dll.NewProc("HttpQueryInfoW").Call(r, 19|0x20000000, uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&size)), 0)
	if ok == 0 {
		return queryErr
	}
	if status != 200 {
		return fmt.Errorf("HTTPS HTTP status %d", status)
	}
	buf := make([]byte, 1024)
	var n uint32
	ok, _, err = dll.NewProc("InternetReadFile").Call(r, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)))
	if ok == 0 {
		return err
	}
	if n == 0 {
		return errors.New("empty HTTPS response")
	}
	return nil
}

func TestUserProxyLiveAcceptance(t *testing.T) {
	liveProxyGuard(t)
	if _, err := os.Stat(os.Getenv("ONETUNNEL_LIVE_PROXY_HOST")); err != nil {
		t.Fatal("production profile host missing:", err)
	}
	for _, mode := range []string{"disconnect", "listener loss", "owner death", "foreign edit"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("ONETUNNEL_DATA_DIR", dir)
			s, err := liveProxySnapshotRead()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("original WinINET flags=%#x", s.Flags)
			data, _ := json.Marshal(s)
			if err = os.WriteFile(filepath.Join(dir, "baseline.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if err = liveProxyOwnedWrite(dir, liveProxyOwned{}); err != nil {
				t.Fatal(err)
			}
			rollback := liveProxyHelper(t, dir, "rollback")
			if err = liveProxyWait(filepath.Join(dir, "rollback-ready"), 3*time.Second); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := liveProxyRestore(dir, s); err != nil {
					t.Error("owned baseline recovery:", err)
					liveProxyLogBlobs(t, dir, s)
					// Keep recovery inputs until the independent deadline process finishes.
					if waitErr := rollback.Wait(); waitErr != nil {
						t.Error("deadline recovery:", waitErr)
					}
					return
				}
				after, readErr := liveProxySnapshotRead()
				t.Logf("restored WinINET flags=%#x (original %#x)", after.Flags, s.Flags)
				if readErr != nil || after.Flags != s.Flags || !reflect.DeepEqual(after.Values, s.Values) {
					t.Error("raw Internet Settings/Connections snapshot differs after recovery", readErr)
				}
				_ = os.WriteFile(filepath.Join(dir, "done"), nil, 0600)
				if err := rollback.Wait(); err != nil {
					t.Error("rollback helper:", err)
				}
			})
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var connects atomic.Int32
			var deny atomic.Bool
			var tunnelMu sync.Mutex
			var tunnels []net.Conn
			closeTunnels := func() {
				tunnelMu.Lock()
				defer tunnelMu.Unlock()
				for _, conn := range tunnels {
					_ = conn.Close()
				}
				tunnels = nil
			}
			defer closeTunnels()
			server := &http.Server{ReadHeaderTimeout: 2 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" || r.Host != "example.com:443" {
					http.Error(w, "target rejected", 403)
					return
				}
				connects.Add(1)
				if deny.Load() {
					http.Error(w, "test rejection", 502)
					return
				}
				up, err := net.DialTimeout("tcp", r.Host, 3*time.Second)
				if err != nil {
					http.Error(w, "upstream unavailable", 502)
					return
				}
				client, buffer, err := w.(http.Hijacker).Hijack()
				if err != nil {
					up.Close()
					return
				}
				tunnelMu.Lock()
				tunnels = append(tunnels, client, up)
				tunnelMu.Unlock()
				_ = client.SetDeadline(time.Now().Add(6 * time.Second))
				_ = up.SetDeadline(time.Now().Add(6 * time.Second))
				_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
				_ = buffer.Flush()
				go func() { defer client.Close(); defer up.Close(); _, _ = io.Copy(up, buffer) }()
				_, _ = io.Copy(client, up)
			})}
			go server.Serve(ln)
			defer server.Close()
			p, err := NewUserProxy()
			if err != nil {
				t.Fatal(err)
			}
			p.armWatchdog = liveProxyArm
			p.notify = func() error { return liveProxyNotify(dir, s) }
			owned := liveProxyOwned{userProxyRegistryKey: map[string][]RawRegistryValue{
				"ProxyEnable":   {{Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}}},
				"ProxyServer":   {{Exists: true, Type: registry.SZ, Data: registryStringBytes("http=" + ln.Addr().String() + ";https=" + ln.Addr().String())}, {Exists: true, Type: registry.SZ, Data: registryStringBytes("http=127.0.0.1:9")}},
				"AutoConfigURL": {{}},
				"AutoDetect":    {{}},
			}}
			for path, values := range s.Values {
				if owned[path] == nil {
					owned[path] = map[string][]RawRegistryValue{}
				}
				for name, value := range values {
					owned[path][name] = append(owned[path][name], value)
				}
			}
			if err = liveProxyOwnedWrite(dir, owned); err != nil {
				t.Fatal(err)
			}
			if time.Until(s.Deadline) < 25*time.Second {
				t.Fatal("insufficient independent recovery window before proxy mutation")
			}
			if s.Flags&winINETProxyAutoFlags != 0 {
				if _, err = p.Enable(ln.Addr().String()); err == nil {
					t.Fatal("baseline automatic proxy configuration was not refused")
				}
				after, e := liveProxySnapshotRead()
				if e != nil || after.Flags != s.Flags || !reflect.DeepEqual(after.Values, s.Values) {
					t.Fatal("refused activation changed baseline", e)
				}
				if _, e = os.Stat(p.journalPath); !os.IsNotExist(e) {
					t.Fatal("refused activation left journal")
				}
				t.Log("active automatic configuration safely refused without mutation")
			}
			if err = liveProxyChange(dir, s, func() error {
				if err := (windowsUserRegistry{}).Delete(userProxyRegistryKey, "AutoConfigURL"); err != nil {
					return err
				}
				if err := (windowsUserRegistry{}).Delete(userProxyRegistryKey, "AutoDetect"); err != nil {
					return err
				}
				if err := liveProxySetFlags(1); err != nil {
					return err
				}
				return notifyWinINet()
			}); err != nil {
				t.Fatal("temporary explicit DIRECT fixture:", err)
			}
			normalized, err := liveProxySnapshotRead()
			if err != nil {
				t.Fatal(err)
			}
			if normalized.Flags != 1 {
				t.Fatalf("DIRECT fixture flags=%#x", normalized.Flags)
			}
			var lease string
			var owner *exec.Cmd
			if mode == "owner death" {
				if err = os.WriteFile(filepath.Join(dir, "listener"), []byte(ln.Addr().String()), 0600); err != nil {
					t.Fatal(err)
				}
				owner = liveProxyHelper(t, dir, "owner")
				defer func() { _ = owner.Process.Kill(); _ = owner.Wait() }()
				if err = liveProxyWait(filepath.Join(dir, "owner-ready"), 8*time.Second); err != nil {
					t.Fatal(err)
				}
			} else {
				lease, err = p.Enable(ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
			}
			flags, err := queryWinINETProxyFlags()
			if err != nil || flags&2 == 0 {
				t.Fatalf("WinINET proxy flag absent: %#x %v", flags, err)
			}
			if mode == "disconnect" {
				if err = liveProxyRequest(); err != nil {
					t.Fatal("WinINET HTTPS via CONNECT:", err)
				}
				if connects.Load() == 0 {
					t.Fatal("HTTPS request bypassed proxy")
				}
				deny.Store(true)
				closeTunnels()
				before := connects.Load()
				if err = liveProxyRequest(); err == nil {
					t.Fatal("WinINET succeeded with proxy refusing CONNECT")
				}
				if connects.Load() <= before {
					t.Fatal("failed request did not reach refusing proxy")
				}
			}
			switch mode {
			case "disconnect":
				if _, err = p.Disable(lease); err != nil {
					t.Fatal(err)
				}
			case "listener loss":
				_ = ln.Close()
			case "owner death":
				if err = owner.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			case "foreign edit":
				foreign := RawRegistryValue{Exists: true, Type: registry.SZ, Data: registryStringBytes("http=127.0.0.1:9")}
				if err = (windowsUserRegistry{}).Write(userProxyRegistryKey, "ProxyServer", foreign); err != nil {
					t.Fatal(err)
				}
				conflict, e := p.Disable(lease)
				if e != nil || !conflict {
					t.Fatalf("foreign edit conflict missing: %t %v", conflict, e)
				}
				got, e := (windowsUserRegistry{}).Read(userProxyRegistryKey, "ProxyServer")
				if e != nil || !sameRegistryValue(got, foreign) {
					t.Fatal("foreign value overwritten")
				}
				return
			}
			end := time.Now().Add(8 * time.Second)
			for time.Now().Before(end) {
				matched := true
				for _, name := range []string{"ProxyEnable", "ProxyServer"} {
					got, e := (windowsUserRegistry{}).Read(userProxyRegistryKey, name)
					if e != nil || !sameRegistryValue(got, normalized.Values[userProxyRegistryKey][name]) {
						matched = false
					}
				}
				if matched {
					if _, e := os.Stat(p.journalPath); os.IsNotExist(e) {
						t.Log("production lease recovery and journal removal verified")
						return
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
			t.Fatal("production proxy restoration did not complete before independent deadline")
		})
	}
}
