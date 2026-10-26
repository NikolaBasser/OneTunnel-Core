package profiles

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"
)

type Document struct {
	UserSettings          *UserPreferences `json:",omitempty"`
	Version               int
	Profiles              []Profile
	FavoriteIDs           []string `json:",omitempty"`
	CollapsedGroups       []string
	SubscriptionSources   map[string]string
	SubscriptionMetadata  map[string]SubscriptionMetadata `json:",omitempty"`
	SubscriptionSchedules map[string]SubscriptionSchedule `json:",omitempty"`
}
type Store struct {
	Root     string
	revision [32]byte
	loaded   bool
}

func NewStore(root string) (*Store, error) {
	if root == "" {
		base, e := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
		if e != nil {
			return nil, e
		}
		root = filepath.Join(base, "OneTunnel")
	}
	root, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	for _, dir := range []string{root, filepath.Join(root, "runtime")} {
		if e = sealDirectory(dir); e != nil {
			return nil, e
		}
	}
	return &Store{Root: root}, nil
}
func sealDirectory(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	for p := path; ; p = filepath.Dir(p) {
		a, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(p))
		if e != nil {
			return e
		}
		if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("reparse storage refused")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
func Protect(data []byte, encrypt bool) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(data))}
	if len(data) > 0 {
		in.Data = &data[0]
	}
	var out windows.DataBlob
	var e error
	if encrypt {
		e = windows.CryptProtectData(&in, windows.StringToUTF16Ptr("OneTunnel profiles"), nil, 0, nil, 1, &out)
	} else {
		e = windows.CryptUnprotectData(&in, nil, nil, 0, nil, 1, &out)
	}
	runtime.KeepAlive(data)
	if e != nil {
		return nil, errors.New("Windows не смогла расшифровать или сохранить профили.")
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	if out.Size > 32*1024*1024 {
		return nil, errors.New("Хранилище слишком большое.")
	}
	view := unsafe.Slice(out.Data, int(out.Size))
	defer clear(view)
	return append([]byte(nil), view...), nil
}
func (s *Store) lock() (func(), error) {
	runtime.LockOSThread()
	sum := sha256.Sum256([]byte(strings.ToUpper(s.Root)))
	name := "Local\\OneTunnel.ProfileStore." + fmtHex(sum[:])
	h, e := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(name))
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		runtime.UnlockOSThread()
		return nil, e
	}
	result, e := windows.WaitForSingleObject(h, 5000)
	if e != nil || (result != windows.WAIT_OBJECT_0 && result != windows.WAIT_ABANDONED) {
		windows.CloseHandle(h)
		runtime.UnlockOSThread()
		return nil, errors.New("Хранилище занято другим процессом.")
	}
	return func() { windows.ReleaseMutex(h); windows.CloseHandle(h); runtime.UnlockOSThread() }, nil
}
func fmtHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = hex[v>>4]
		out[2*i+1] = hex[v&15]
	}
	return string(out)
}
func (s *Store) readEncrypted() ([]byte, error) {
	path := filepath.Join(s.Root, "profiles.bin")
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Size() > 32*1024*1024 {
		return nil, errors.New("Небезопасное или слишком большое хранилище.")
	}
	return os.ReadFile(path)
}
func (s *Store) Load() (Document, error) {
	unlock, e := s.lock()
	if e != nil {
		return Document{}, e
	}
	defer unlock()
	return s.load()
}
func (s *Store) load() (Document, error) {
	d := Document{Version: 1, Profiles: []Profile{}, CollapsedGroups: []string{}, SubscriptionSources: map[string]string{}}
	encrypted, e := s.readEncrypted()
	if e != nil {
		return d, e
	}
	defer clear(encrypted)
	if len(encrypted) == 0 {
		s.loaded = true
		s.revision = sha256.Sum256(nil)
		return d, nil
	}
	data, e := Protect(encrypted, false)
	if e != nil {
		return d, e
	}
	defer clear(data)
	if !boundedJSON(data) {
		return d, ErrImport
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		e = json.Unmarshal(data, &d.Profiles)
	} else {
		e = json.Unmarshal(data, &d)
	}
	if e != nil || d.Version != 1 || len(d.Profiles) > 2000 {
		return d, errors.New("Хранилище повреждено или его версия не поддерживается; исходный файл сохранён.")
	}
	if d.Profiles == nil {
		d.Profiles = []Profile{}
	}
	if d.CollapsedGroups == nil {
		d.CollapsedGroups = []string{}
	}
	if d.SubscriptionSources == nil {
		d.SubscriptionSources = map[string]string{}
	}
	for i := range d.Profiles {
		if d.Profiles[i].Group == "" {
			d.Profiles[i].Group = "Без группы"
		}
		network, normalizeErr := protocol.NormalizeNetworkOptions(d.Profiles[i].Network)
		if normalizeErr != nil || protocol.ValidateNetworkOptions(network, d.Profiles[i].Protocol, true) != nil {
			return d, errors.New("Хранилище содержит неподдерживаемые сетевые параметры; исходный файл сохранён.")
		}
		d.Profiles[i].Network = network
	}
	for group, url := range d.SubscriptionSources {
		if !SecureURL(url) {
			delete(d.SubscriptionSources, group)
		}
	}
	for group := range d.SubscriptionMetadata {
		if _, ok := d.SubscriptionSources[group]; !ok {
			delete(d.SubscriptionMetadata, group)
		}
	}
	d.SubscriptionSchedules = normalizeSubscriptionSchedules(d.SubscriptionSchedules, d.Profiles, d.SubscriptionSources)
	d.FavoriteIDs = normalizeFavoriteIDs(d.FavoriteIDs, d.Profiles)
	d.UserSettings = normalizeStoredUserPreferences(d.UserSettings, d)
	s.revision = sha256.Sum256(encrypted)
	s.loaded = true
	return d, nil
}
func (s *Store) Save(d Document) error {
	unlock, e := s.lock()
	if e != nil {
		return e
	}
	defer unlock()
	if !s.loaded {
		return errors.New("Сначала прочитай хранилище.")
	}
	old, e := s.readEncrypted()
	if e != nil {
		return e
	}
	defer clear(old)
	if sha256.Sum256(old) != s.revision {
		return errors.New("Профили изменены другой копией приложения. Перечитай список перед сохранением.")
	}
	if d.Version != 1 || len(d.Profiles) > 2000 {
		return ErrImport
	}
	seen := map[string]bool{}
	groups := map[string]bool{}
	for i := range d.Profiles {
		network, normalizeErr := protocol.NormalizeNetworkOptions(d.Profiles[i].Network)
		if normalizeErr != nil || protocol.ValidateNetworkOptions(network, d.Profiles[i].Protocol, true) != nil {
			return errors.New("Хранилище содержит неподдерживаемые сетевые параметры; исходный файл сохранён.")
		}
		d.Profiles[i].Network = network
		p := d.Profiles[i]
		if e := Validate(p); e != nil {
			return e
		}
		if seen[p.ID] {
			return ErrImport
		}
		seen[p.ID] = true
		groups[p.Group] = true
	}
	d.FavoriteIDs = normalizeFavoriteIDs(d.FavoriteIDs, d.Profiles)
	d.UserSettings = normalizeStoredUserPreferences(d.UserSettings, d)
	for _, schedule := range d.SubscriptionSchedules {
		if !validSchedule(schedule) {
			return ErrImport
		}
	}
	for group, source := range d.SubscriptionSources {
		if !groups[group] {
			delete(d.SubscriptionSources, group)
		} else if !SecureURL(source) {
			return ErrImport
		}
	}
	for group := range d.SubscriptionMetadata {
		if !groups[group] || d.SubscriptionSources[group] == "" {
			delete(d.SubscriptionMetadata, group)
		}
	}
	d.SubscriptionSchedules = normalizeSubscriptionSchedules(d.SubscriptionSchedules, d.Profiles, d.SubscriptionSources)
	data, e := json.Marshal(d)
	if e != nil || len(data) > 32*1024*1024 {
		return ErrImport
	}
	defer clear(data)
	encrypted, e := Protect(data, true)
	if e != nil {
		return e
	}
	defer clear(encrypted)
	path := filepath.Join(s.Root, "profiles.bin")
	if len(old) > 0 {
		backup, e := os.OpenFile(path+".before-go.bak", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e == nil {
			_, e = backup.Write(old)
			if e == nil {
				e = backup.Sync()
			}
			ce := backup.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		} else if !os.IsExist(e) {
			return e
		}
	}
	temp := path + ".new"
	if info, e := os.Lstat(temp); e == nil && info.Mode()&os.ModeSymlink != 0 {
		return ErrImport
	}
	f, e := os.OpenFile(temp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer os.Remove(temp)
	_, e = io.Copy(f, bytes.NewReader(encrypted))
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return e
	}
	s.revision = sha256.Sum256(encrypted)
	return nil
}
