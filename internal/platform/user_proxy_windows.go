//go:build windows

package platform

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const userProxyJournalSchema = 1
const userProxyRegistryKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
const userProxyRunKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const userProxyRunValue = "OneTunnel"
const userProxyRegistryMutex = `Global\OneTunnel.UserAutomation.v1`

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")
var isProcessInJobProc = kernel32.NewProc("IsProcessInJob")

const (
	internetOptionPerConnectionOption = 75
	internetPerConnectionFlags        = 1
	internetPerConnectionFlagsUI      = 10
	winINETProxyAutoURL               = 4
	winINETProxyAutoDetect            = 8
	winINETProxyAutoFlags             = winINETProxyAutoURL | winINETProxyAutoDetect
)

type internetPerConnectionOption struct {
	Option uint32
	Value  uintptr
}

type internetPerConnectionOptionList struct {
	Size        uint32
	Connection  *uint16
	OptionCount uint32
	OptionError uint32
	Options     *internetPerConnectionOption
}

func queryWinINETProxyFlags() (uint32, error) {
	query := windows.NewLazySystemDLL("wininet.dll").NewProc("InternetQueryOptionW")
	for _, optionID := range []uint32{internetPerConnectionFlagsUI, internetPerConnectionFlags} {
		option := internetPerConnectionOption{Option: optionID}
		list := internetPerConnectionOptionList{
			Size: uint32(unsafe.Sizeof(internetPerConnectionOptionList{})), OptionCount: 1, Options: &option,
		}
		size := uint32(unsafe.Sizeof(list))
		ok, _, callErr := query.Call(0, internetOptionPerConnectionOption, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
		if ok != 0 && list.OptionError == 0 {
			return uint32(option.Value), nil
		}
		if ok != 0 && list.OptionError != 0 {
			callErr = syscall.Errno(list.OptionError)
		}
		if optionID == internetPerConnectionFlags {
			if callErr == syscall.Errno(0) {
				callErr = errors.New("WinINET did not return proxy flags")
			}
			return 0, callErr
		}
	}
	return 0, errors.New("WinINET proxy option query failed")
}

// RawRegistryValue preserves missing values, their exact type, and raw bytes.
type RawRegistryValue struct {
	Exists bool   `json:"exists"`
	Type   uint32 `json:"type,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

// UserRegistry makes user-scope registry effects replaceable in tests.
type UserRegistry interface {
	Read(key, name string) (RawRegistryValue, error)
	Write(key, name string, value RawRegistryValue) error
	Delete(key, name string) error
}

type windowsUserRegistry struct{}

func (windowsUserRegistry) Read(key, name string) (RawRegistryValue, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.QUERY_VALUE)
	if err == registry.ErrNotExist {
		return RawRegistryValue{}, nil
	}
	if err != nil {
		return RawRegistryValue{}, err
	}
	defer k.Close()
	n, typ, err := k.GetValue(name, nil)
	if err == registry.ErrNotExist {
		return RawRegistryValue{}, nil
	}
	if err != nil {
		return RawRegistryValue{}, err
	}
	data := make([]byte, n)
	if n > 0 {
		got, gotType, readErr := k.GetValue(name, data)
		if readErr != nil {
			return RawRegistryValue{}, readErr
		}
		if gotType != typ || got != n {
			return RawRegistryValue{}, errors.New("registry value changed while reading")
		}
	}
	return RawRegistryValue{Exists: true, Type: typ, Data: data}, nil
}

func (windowsUserRegistry) Write(key, name string, value RawRegistryValue) error {
	if !value.Exists {
		return windowsUserRegistry{}.Delete(key, name)
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.SET_VALUE)
	if err == registry.ErrNotExist {
		k, _, err = registry.CreateKey(registry.CURRENT_USER, key, registry.SET_VALUE)
	}
	if err != nil {
		return err
	}
	defer k.Close()
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var dataPtr *byte
	if len(value.Data) > 0 {
		dataPtr = &value.Data[0]
	}
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegSetValueExW")
	result, _, _ := proc.Call(uintptr(k), uintptr(unsafe.Pointer(namePtr)), 0, uintptr(value.Type), uintptr(unsafe.Pointer(dataPtr)), uintptr(len(value.Data)))
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}

func (windowsUserRegistry) Delete(key, name string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.SET_VALUE)
	if err == registry.ErrNotExist {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	err = k.DeleteValue(name)
	if err == registry.ErrNotExist {
		return nil
	}
	return err
}

type proxyJournal struct {
	Schema       int                         `json:"schema"`
	LeaseID      string                      `json:"lease_id"`
	OwnerSID     string                      `json:"owner_sid"`
	OwnerPID     uint32                      `json:"owner_pid"`
	OwnerCreated uint64                      `json:"owner_created"`
	Listener     string                      `json:"listener"`
	Baseline     map[string]RawRegistryValue `json:"baseline"`
	Applied      map[string]RawRegistryValue `json:"applied"`
}

type UserProxy struct {
	registry        UserRegistry
	journalPath     string
	armWatchdog     func(string, uint32, uint64, string) error
	notify          func() error
	queryProxyFlags func() (uint32, error)
	lockAutomation  func() (func(), error)
	ownerIdentity   func() (string, uint32, uint64, error)
	writeJournalFn  func(proxyJournal) error
	probeListener   func(string, time.Duration) error
}

// NewUserProxy returns a current-user only lease manager. It never mutates HKLM or WinHTTP.
func NewUserProxy() (*UserProxy, error) {
	root, err := defaultUserProxyRoot()
	if err != nil {
		return nil, err
	}
	return NewUserProxyAt(root)
}

// NewUserProxyAt stores its journal under the configured application data root.
func NewUserProxyAt(root string) (*UserProxy, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("user proxy data root is required")
	}
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(root, `\\`) {
		return nil, errors.New("user proxy data root must be on a local drive")
	}
	expectedRoot, err := defaultUserProxyRoot()
	if err != nil {
		return nil, err
	}
	expectedRoot, err = filepath.Abs(filepath.Clean(expectedRoot))
	if err != nil || !strings.EqualFold(root, expectedRoot) {
		return nil, errors.New("user proxy data root does not match the configured application root")
	}
	if err = rejectReparsePath(root); err != nil {
		return nil, err
	}
	return &UserProxy{registry: windowsUserRegistry{}, journalPath: filepath.Join(root, "user-proxy.dpapi"), armWatchdog: armUserProxyWatchdog, notify: notifyWinINet, queryProxyFlags: queryWinINETProxyFlags, probeListener: probeLoopbackListener}, nil
}

// NewUserProxyAtRoot is retained as a descriptive alias for NewUserProxyAt.
func NewUserProxyAtRoot(root string) (*UserProxy, error) { return NewUserProxyAt(root) }

func defaultUserProxyRoot() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("ONETUNNEL_DATA_DIR")); configured != "" {
		return filepath.Abs(filepath.Clean(configured))
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Abs(filepath.Join(base, "OneTunnel"))
}

func (p *UserProxy) Enable(localAddress string) (string, error) {
	if p == nil || p.registry == nil || p.journalPath == "" {
		return "", errors.New("user proxy manager unavailable")
	}
	localAddress, err := canonicalLoopbackAddress(localAddress)
	if err != nil {
		return "", err
	}
	probe := p.probeListener
	if probe == nil {
		probe = probeLoopbackListener
	}
	if err = probe(localAddress, time.Second); err != nil {
		return "", errors.New("proxy listener is not accepting local connections")
	}
	unlock, err := p.userAutomationLock()
	if err != nil {
		return "", err
	}
	defer unlock()
	if _, err := os.Stat(p.journalPath); err == nil {
		return "", errors.New("an existing proxy lease must be reconciled first")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if p.queryProxyFlags == nil {
		return "", errors.New("WinINET proxy state cannot be verified")
	}
	if err = checkProxyAutoconfiguration(p.registry, p.queryProxyFlags); err != nil {
		return "", err
	}
	identity := p.ownerIdentity
	if identity == nil {
		identity = currentUserProxyIdentity
	}
	sid, pid, created, err := identity()
	if err != nil {
		return "", err
	}
	leaseBytes := make([]byte, 16)
	if _, err = rand.Read(leaseBytes); err != nil {
		return "", err
	}
	lease := hex.EncodeToString(leaseBytes)
	server := RawRegistryValue{Exists: true, Type: registry.SZ, Data: registryStringBytes("http=" + localAddress + ";https=" + localAddress)}
	applied := map[string]RawRegistryValue{"ProxyEnable": {Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}}, "ProxyServer": server}
	baseline := make(map[string]RawRegistryValue, len(applied))
	for name := range applied {
		baseline[name], err = p.registry.Read(userProxyRegistryKey, name)
		if err != nil {
			return "", err
		}
	}
	journal := proxyJournal{Schema: userProxyJournalSchema, LeaseID: lease, OwnerSID: sid, OwnerPID: pid, OwnerCreated: created, Listener: localAddress, Baseline: baseline, Applied: applied}
	writeJournal := p.writeJournalFn
	if writeJournal == nil {
		writeJournal = p.writeJournal
	}
	if err = writeJournal(journal); err != nil {
		return "", err
	}
	if p.armWatchdog == nil || p.armWatchdog(lease, pid, created, p.journalPath) != nil {
		_ = os.Remove(p.journalPath)
		return "", errors.New("proxy recovery watchdog could not be armed")
	}
	rollback := func(cause error) (string, error) {
		_, restoreErr := p.restore(journal)
		if restoreErr == nil && (p.notify == nil || p.notify() == nil) {
			_ = os.Remove(p.journalPath)
		}
		return "", cause
	}
	// Install the target before turning it on. If the previous configuration
	// was disabled, enabling first could briefly use the user's old server.
	for _, name := range []string{"ProxyServer", "ProxyEnable"} {
		current, readErr := p.registry.Read(userProxyRegistryKey, name)
		if readErr != nil || !sameRegistryValue(current, baseline[name]) {
			return rollback(errors.New("proxy settings changed during activation"))
		}
		if writeErr := p.registry.Write(userProxyRegistryKey, name, applied[name]); writeErr != nil {
			return rollback(errors.New("could not apply current-user proxy settings"))
		}
	}
	if p.notify != nil {
		if err = p.notify(); err != nil {
			return rollback(errors.New("Windows did not confirm proxy settings refresh"))
		}
	}
	return lease, nil
}

func (p *UserProxy) userAutomationLock() (func(), error) {
	lock := p.lockAutomation
	if lock == nil {
		lock = lockUserAutomation
	}
	return lock()
}

func currentUserProxyIdentity() (string, uint32, uint64, error) {
	sid, err := currentUserSID()
	if err != nil {
		return "", 0, 0, err
	}
	created, err := currentProcessCreationTime()
	if err != nil {
		return "", 0, 0, err
	}
	return sid, windows.GetCurrentProcessId(), created, nil
}

func (p *UserProxy) Disable(lease string) (bool, error) {
	unlock, err := p.userAutomationLock()
	if err != nil {
		return false, err
	}
	defer unlock()
	journal, err := p.readJournal()
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	created, identityErr := currentProcessCreationTime()
	if identityErr != nil {
		return false, identityErr
	}
	if journal.LeaseID != lease || lease == "" || journal.OwnerPID != windows.GetCurrentProcessId() || journal.OwnerCreated != created {
		return false, errors.New("proxy lease is stale")
	}
	conflict, err := p.restore(journal)
	if err != nil {
		return conflict, err
	}
	if p.notify != nil {
		if err = p.notify(); err != nil {
			return conflict, err
		}
	}
	if err = os.Remove(p.journalPath); err != nil && !os.IsNotExist(err) {
		return conflict, err
	}
	return conflict, nil
}

// Owns reports whether the validated current-user journal still belongs to lease.
// Missing or superseded leases are reported as false without changing any state.
func (p *UserProxy) Owns(lease string) (bool, error) {
	if p == nil || p.registry == nil || p.journalPath == "" {
		return false, errors.New("user proxy manager unavailable")
	}
	if lease == "" {
		return false, nil
	}
	journal, err := p.readJournal()
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return journal.LeaseID == lease, nil
}

func (p *UserProxy) Reconcile() (bool, error) {
	unlock, err := p.userAutomationLock()
	if err != nil {
		return false, err
	}
	defer unlock()
	journal, err := p.readJournal()
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	alive, err := userProcessIdentityAlive(journal.OwnerPID, journal.OwnerCreated)
	if err != nil {
		return false, err
	}
	if alive {
		return false, errors.New("proxy lease is still owned by an active user host")
	}
	conflict, err := p.restore(journal)
	if err != nil {
		return conflict, err
	}
	if p.notify != nil {
		if err = p.notify(); err != nil {
			return conflict, err
		}
	}
	if err = os.Remove(p.journalPath); err != nil && !os.IsNotExist(err) {
		return conflict, err
	}
	return conflict, nil
}

func restoreOwned(reg UserRegistry, journal proxyJournal) (bool, error) {
	conflict := false
	for _, name := range []string{"ProxyEnable", "ProxyServer"} {
		current, err := reg.Read(userProxyRegistryKey, name)
		if err != nil {
			return conflict, err
		}
		owned, ok := journal.Applied[name]
		if !ok {
			continue
		}
		if !sameRegistryValue(current, owned) {
			if sameRegistryValue(current, journal.Baseline[name]) {
				continue
			}
			conflict = true
			continue
		}
		if err = reg.Write(userProxyRegistryKey, name, journal.Baseline[name]); err != nil {
			return conflict, err
		}
	}
	return conflict, nil
}
func (p *UserProxy) restore(j proxyJournal) (bool, error) { return restoreOwned(p.registry, j) }

func checkProxyAutoconfiguration(reg UserRegistry, queryFlags func() (uint32, error)) error {
	pac, err := reg.Read(userProxyRegistryKey, "AutoConfigURL")
	if err != nil {
		return err
	}
	if pac.Exists {
		if pac.Type != registry.SZ && pac.Type != registry.EXPAND_SZ {
			return errors.New("PAC configuration has an unsupported registry type")
		}
		if decodeRegistryString(pac) != "" {
			return errors.New("manual proxy conflicts with an existing PAC configuration")
		}
	}
	auto, err := reg.Read(userProxyRegistryKey, "AutoDetect")
	if err != nil {
		return err
	}
	if auto.Exists && (auto.Type != registry.DWORD || len(auto.Data) != 4 || binary.LittleEndian.Uint32(auto.Data) != 0) {
		return errors.New("manual proxy conflicts with automatic proxy detection")
	}
	if queryFlags == nil {
		return errors.New("WinINET proxy state cannot be verified")
	}
	flags, err := queryFlags()
	if err != nil {
		return fmt.Errorf("WinINET proxy option query failed: %w", err)
	}
	if flags&winINETProxyAutoFlags != 0 {
		return errors.New("manual proxy conflicts with active WinINET PAC or auto-detect options")
	}
	return nil
}

func canonicalLoopbackAddress(address string) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.New("proxy listener must be a confirmed local loopback endpoint")
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return "", errors.New("proxy listener must be a confirmed local loopback endpoint")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func probeLoopbackListener(address string, timeout time.Duration) error {
	canonical, err := canonicalLoopbackAddress(address)
	if err != nil {
		return err
	}
	connection, err := net.DialTimeout("tcp", canonical, timeout)
	if err != nil {
		return err
	}
	return connection.Close()
}

// Registry restore is compare-before-write; Windows exposes no atomic value CAS.
func sameRegistryValue(a, b RawRegistryValue) bool {
	return a.Exists == b.Exists && a.Type == b.Type && bytes.Equal(a.Data, b.Data)
}
func registryStringBytes(s string) []byte {
	u := append([]uint16{}, syscall.StringToUTF16(s)...)
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}
func decodeRegistryString(v RawRegistryValue) string {
	if !v.Exists || (v.Type != registry.SZ && v.Type != registry.EXPAND_SZ) || len(v.Data)%2 != 0 {
		return ""
	}
	units := make([]uint16, len(v.Data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(v.Data[i*2:])
	}
	for i, c := range units {
		if c == 0 {
			units = units[:i]
			break
		}
	}
	return syscall.UTF16ToString(units)
}
func currentUserSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}
func currentProcessCreationTime() (uint64, error) {
	h, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	var created, exited, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}
func userProcessIdentityAlive(pid uint32, created uint64) (bool, error) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err == windows.ERROR_INVALID_PARAMETER {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	var born, exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(h, &born, &exit, &kernel, &user); err != nil {
		return false, err
	}
	if uint64(born.HighDateTime)<<32|uint64(born.LowDateTime) != created {
		return false, nil
	}
	state, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return false, err
	}
	return state == uint32(windows.WAIT_TIMEOUT), nil
}
func journalPath() (string, error) {
	root, e := defaultUserProxyRoot()
	if e != nil {
		return "", e
	}
	return filepath.Join(root, "user-proxy.dpapi"), nil
}
func (p *UserProxy) writeJournal(j proxyJournal) error {
	data, e := json.Marshal(j)
	if e != nil {
		return e
	}
	defer clear(data)
	protected, e := protectUserData(data)
	if e != nil {
		return e
	}
	defer clear(protected)
	if e = os.MkdirAll(filepath.Dir(p.journalPath), 0700); e != nil {
		return e
	}
	if e = rejectReparsePath(p.journalPath); e != nil {
		return e
	}
	nonce := make([]byte, 8)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	tmp := p.journalPath + ".tmp-" + hex.EncodeToString(nonce)
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer os.Remove(tmp)
	if _, e = f.Write(protected); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		_ = os.Remove(tmp)
		return e
	}
	// Publish the already-flushed file atomically and request metadata write-
	// through. Omitting REPLACE_EXISTING preserves any prior lease journal.
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(tmp), windows.StringToUTF16Ptr(p.journalPath), windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return e
	}
	return nil
}
func (p *UserProxy) readJournal() (proxyJournal, error) {
	var j proxyJournal
	if e := rejectReparsePath(p.journalPath); e != nil {
		return j, e
	}
	info, statErr := os.Stat(p.journalPath)
	if statErr != nil {
		return j, statErr
	}
	if info.Size() < 1 || info.Size() > 256*1024 {
		return j, errors.New("proxy journal exceeds limit")
	}
	b, e := os.ReadFile(p.journalPath)
	if e != nil {
		return j, e
	}
	defer clear(b)
	plain, e := unprotectUserData(b)
	if e != nil {
		return j, e
	}
	defer clear(plain)
	if len(plain) > 128*1024 {
		return j, errors.New("proxy journal exceeds limit")
	}
	if e = json.Unmarshal(plain, &j); e != nil {
		return j, e
	}
	if j.Schema != userProxyJournalSchema || j.LeaseID == "" || len(j.Applied) == 0 {
		return j, errors.New("proxy journal is invalid")
	}
	listener, err := canonicalLoopbackAddress(j.Listener)
	if err != nil || listener != j.Listener {
		return j, errors.New("proxy journal listener is invalid")
	}
	sid, err := currentUserSID()
	if err != nil {
		return j, err
	}
	if j.OwnerSID != sid {
		return j, errors.New("proxy journal belongs to another user")
	}
	return j, nil
}

func protectUserData(data []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if e := windows.CryptProtectData(&in, windows.StringToUTF16Ptr("OneTunnel user proxy lease"), nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); e != nil {
		return nil, e
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}
func unprotectUserData(data []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if e := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); e != nil {
		return nil, e
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

var errUserAutomationBusy = errors.New("another user automation operation is active")

func lockUserAutomation() (func(), error) { return lockUserAutomationTimeout(0) }

func lockUserAutomationTimeout(timeout uint32) (func(), error) {
	runtime.LockOSThread()
	sid, e := currentUserSID()
	if e != nil {
		runtime.UnlockOSThread()
		return nil, e
	}
	name, e := windows.UTF16PtrFromString(userProxyRegistryMutex + "." + strings.ReplaceAll(sid, "-", "_"))
	if e != nil {
		runtime.UnlockOSThread()
		return nil, e
	}
	h, e := windows.CreateMutex(nil, false, name)
	// CreateMutex returns ERROR_ALREADY_EXISTS with a valid handle when another
	// OneTunnel host already created the named mutex.
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		runtime.UnlockOSThread()
		return nil, e
	}
	result, e := windows.WaitForSingleObject(h, timeout)
	if e != nil || (result != windows.WAIT_OBJECT_0 && result != windows.WAIT_ABANDONED) {
		_ = windows.CloseHandle(h)
		runtime.UnlockOSThread()
		if e != nil {
			return nil, e
		}
		return nil, errUserAutomationBusy
	}
	return func() { _ = windows.ReleaseMutex(h); _ = windows.CloseHandle(h); runtime.UnlockOSThread() }, nil
}

func retryUserAutomationLock(acquire func() (func(), error), pause func(time.Duration), attempts int) (func(), error) {
	if attempts < 1 {
		return nil, errUserAutomationBusy
	}
	for i := 0; i < attempts; i++ {
		unlock, err := acquire()
		if err == nil {
			return unlock, nil
		}
		if !errors.Is(err, errUserAutomationBusy) {
			return nil, err
		}
		if i+1 < attempts {
			pause(5 * time.Second)
		}
	}
	return nil, errUserAutomationBusy
}

func rejectReparsePath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(abs)
	if volume == "" {
		return errors.New("user proxy path has no local volume")
	}
	current := volume + `\`
	for _, part := range strings.Split(strings.TrimLeft(abs[len(volume):], `\`), `\`) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		attrs, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if e == windows.ERROR_FILE_NOT_FOUND || e == windows.ERROR_PATH_NOT_FOUND {
			continue
		}
		if e != nil {
			return e
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("user-managed path contains a reparse point")
		}
	}
	return nil
}

func armUserProxyWatchdog(lease string, pid uint32, created uint64, journal string) error {
	journal, err := filepath.Abs(filepath.Clean(journal))
	expected, rootErr := journalPath()
	if err != nil || rootErr != nil || !strings.EqualFold(journal, expected) || strings.HasPrefix(journal, `\\`) {
		return errors.New("watchdog journal path is invalid")
	}
	if err = rejectReparsePath(journal); err != nil {
		return err
	}
	eventName := `Local\OneTunnel.ProxyWatchdogAck.` + lease
	name, e := windows.UTF16PtrFromString(eventName)
	if e != nil {
		return e
	}
	event, e := windows.CreateEvent(nil, 1, 0, name)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(event)
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	cmd := exec.Command(exe, "--user-proxy-watchdog", lease, strconv.FormatUint(uint64(pid), 10), strconv.FormatUint(created, 10), eventName)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: userProxyWatchdogCreationFlags()}
	if e = cmd.Start(); e != nil {
		return e
	}
	_ = cmd.Process.Release()
	result, e := windows.WaitForSingleObject(event, 5000)
	if e != nil {
		return e
	}
	if result != windows.WAIT_OBJECT_0 {
		return errors.New("watchdog acknowledgement timed out")
	}
	return nil
}

func userProxyWatchdogCreationFlags() uint32 {
	return windows.DETACHED_PROCESS | windows.CREATE_NO_WINDOW | windows.CREATE_BREAKAWAY_FROM_JOB
}

func ensureWatchdogOutsideJob(inJob bool, err error) error {
	if err != nil {
		return errors.New("watchdog job membership could not be verified")
	}
	if inJob {
		return errors.New("watchdog remained in a host job and cannot outlive the host")
	}
	return nil
}

func currentProcessInJob() (bool, error) {
	if err := isProcessInJobProc.Find(); err != nil {
		return false, err
	}
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return false, err
	}
	var inJob int32
	r, _, callErr := isProcessInJobProc.Call(uintptr(process), 0, uintptr(unsafe.Pointer(&inJob)))
	runtime.KeepAlive(&inJob)
	if r == 0 {
		if callErr == nil || callErr == syscall.Errno(0) {
			callErr = errors.New("IsProcessInJob failed without a system error")
		}
		return false, callErr
	}
	return inJob != 0, nil
}

// RunUserProxyWatchdog is dispatched by the Go profile host for its private watchdog mode.
// Args are lease ID, owner PID, creation FILETIME, and acknowledgement event name.
func RunUserProxyWatchdog(args []string) error {
	if len(args) != 4 {
		return errors.New("invalid watchdog arguments")
	}
	inJob, err := currentProcessInJob()
	if err = ensureWatchdogOutsideJob(inJob, err); err != nil {
		return err
	}
	pid64, e := strconv.ParseUint(args[1], 10, 32)
	if e != nil {
		return e
	}
	created, e := strconv.ParseUint(args[2], 10, 64)
	if e != nil {
		return e
	}
	path, e := journalPath()
	if e != nil {
		return e
	}
	proxy := &UserProxy{registry: windowsUserRegistry{}, journalPath: path, notify: notifyWinINet}
	journal, e := proxy.readJournal()
	if e != nil {
		return e
	}
	if journal.LeaseID != args[0] || journal.OwnerPID != uint32(pid64) || journal.OwnerCreated != created {
		return errors.New("watchdog owner mismatch")
	}
	process, e := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid64))
	if e != nil {
		return e
	}
	defer windows.CloseHandle(process)
	var born, exit, kernel, user windows.Filetime
	if e = windows.GetProcessTimes(process, &born, &exit, &kernel, &user); e != nil {
		return e
	}
	actual := uint64(born.HighDateTime)<<32 | uint64(born.LowDateTime)
	if actual != created {
		return errors.New("watchdog process identity mismatch")
	}
	listener, e := canonicalLoopbackAddress(journal.Listener)
	if e != nil || listener != journal.Listener {
		return errors.New("watchdog listener endpoint is invalid")
	}
	ackName, e := windows.UTF16PtrFromString(args[3])
	if e != nil {
		return e
	}
	ack, e := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, ackName)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(ack)
	if e = acknowledgeWatchdogReady(listener, func() error { return windows.SetEvent(ack) }); e != nil {
		return e
	}
	listenerFailed, e := monitorProxyLeaseOwnerAndListener(func(timeout time.Duration) (bool, error) {
		milliseconds := uint32(timeout / time.Millisecond)
		state, waitErr := windows.WaitForSingleObject(process, milliseconds)
		if waitErr != nil {
			return false, waitErr
		}
		if state == windows.WAIT_OBJECT_0 {
			return true, nil
		}
		if state != uint32(windows.WAIT_TIMEOUT) {
			return false, fmt.Errorf("watchdog process wait returned unexpected state %#x", state)
		}
		return false, nil
	}, func() (bool, error) {
		current, readErr := proxy.readJournal()
		if os.IsNotExist(readErr) {
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
		return current.LeaseID == args[0], nil
	}, probeLoopbackListener, listener, 2*time.Second, 3)
	_ = listenerFailed // Either owner exit or listener loss ends this lease.
	return finishProxyWatchdog(e, func() error {
		return restoreProxyLeaseAfterWatchEnd(proxy, args[0], func() (proxyJournal, error) {
			return proxy.readJournal()
		}, func() (func(), error) {
			return lockUserAutomationTimeout(5000)
		}, time.Sleep)
	})
}

func finishProxyWatchdog(monitorErr error, restore func() error) error {
	recoveryErr := restore()
	if monitorErr != nil && recoveryErr != nil {
		return errors.Join(monitorErr, recoveryErr)
	}
	if monitorErr != nil {
		return monitorErr
	}
	return recoveryErr
}

func acknowledgeWatchdogReady(listener string, signal func() error) error {
	canonical, err := canonicalLoopbackAddress(listener)
	if err != nil || canonical != listener {
		return errors.New("watchdog listener endpoint is invalid")
	}
	return signal()
}

func restoreProxyLeaseAfterWatchEnd(proxy *UserProxy, lease string, readJournal func() (proxyJournal, error), acquireLock func() (func(), error), pause func(time.Duration)) error {
	const attempts = 10
	if pause == nil {
		pause = time.Sleep
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		completed := false
		unlock, err := acquireLock()
		if err != nil {
			lastErr = err
		} else {
			lastErr = func() error {
				defer unlock()
				current, readErr := readJournal()
				if os.IsNotExist(readErr) || readErr == nil && current.LeaseID != lease {
					return nil
				}
				if readErr != nil {
					return readErr
				}
				conflict, restoreErr := proxy.restore(current)
				if restoreErr != nil {
					return restoreErr
				}
				if proxy.notify != nil {
					if notifyErr := proxy.notify(); notifyErr != nil {
						return notifyErr
					}
				}
				if removeErr := os.Remove(proxy.journalPath); removeErr != nil && !os.IsNotExist(removeErr) {
					return removeErr
				}
				completed = true
				if conflict {
					return fmt.Errorf("proxy settings were changed externally; owned values restored selectively")
				}
				return nil
			}()
		}
		if lastErr == nil || completed {
			return lastErr
		}
		if attempt+1 < attempts {
			pause(time.Second)
		}
	}
	return lastErr
}

func monitorProxyOwnerAndListener(waitForOwner func(time.Duration) (bool, error), probe func(string, time.Duration) error, listener string, interval time.Duration, failureLimit int) (bool, error) {
	if interval <= 0 || failureLimit < 1 {
		return false, errors.New("invalid watchdog monitor limits")
	}
	canonical, err := canonicalLoopbackAddress(listener)
	if err != nil || canonical != listener {
		return false, errors.New("watchdog listener must be a canonical loopback endpoint")
	}
	failures := 0
	for {
		exited, err := waitForOwner(interval)
		if err != nil {
			return false, err
		}
		if exited {
			return false, nil
		}
		if err = probe(listener, time.Second); err != nil {
			failures++
			if failures >= failureLimit {
				return true, nil
			}
		} else {
			failures = 0
		}
	}
}

func monitorProxyLeaseOwnerAndListener(waitForOwner func(time.Duration) (bool, error), leaseCurrent func() (bool, error), probe func(string, time.Duration) error, listener string, interval time.Duration, failureLimit int) (bool, error) {
	if interval <= 0 || failureLimit < 1 {
		return false, errors.New("invalid watchdog monitor limits")
	}
	canonical, err := canonicalLoopbackAddress(listener)
	if err != nil || canonical != listener {
		return false, errors.New("watchdog listener must be a canonical loopback endpoint")
	}
	failures := 0
	for {
		exited, waitErr := waitForOwner(interval)
		if waitErr != nil {
			return false, waitErr
		}
		if exited {
			return false, nil
		}
		current, leaseErr := leaseCurrent()
		if leaseErr != nil {
			return false, leaseErr
		}
		if !current {
			return false, nil
		}
		if probeErr := probe(listener, time.Second); probeErr != nil {
			failures++
			if failures >= failureLimit {
				return true, nil
			}
		} else {
			failures = 0
		}
	}
}

func notifyWinINet() error {
	dll := windows.NewLazySystemDLL("wininet.dll")
	proc := dll.NewProc("InternetSetOptionW")
	return notifyInternetOptions(func(option uintptr) error {
		ok, _, e := proc.Call(0, option, 0, 0)
		if ok != 0 {
			return nil
		}
		if e != syscall.Errno(0) {
			return e
		}
		return errors.New("InternetSetOptionW failed")
	})
}

func notifyInternetOptions(send func(uintptr) error) error {
	for _, option := range []uintptr{39, 37} {
		if err := send(option); err != nil {
			return err
		}
	}
	return nil
}
