package profiles

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/sys/windows"
)

const (
	backupHeader      = "ONTBKUP1"
	backupMaxPlain    = 4 << 20
	backupMaxEnvelope = backupMaxPlain + 128
)

var errBackupUnavailable = errors.New("backup could not be opened or saved")

type BackupExportResult struct{ ProfileCount int }
type BackupRestorePreview struct {
	Token               string
	CurrentProfiles     int
	ReplacementProfiles int
	EnabledSchedules    int
	CanApply            bool
	ExpiresAt           string
}
type pendingBackupRestore struct {
	token     string
	candidate Document
	baseline  [32]byte
	expires   time.Time
}

func backupKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, 32)
}

func sealBackup(plain, password []byte) ([]byte, error) {
	if len(plain) == 0 || len(plain) > backupMaxPlain || len(password) < 12 || len(password) > 1024 || !utf8.Valid(password) {
		return nil, errBackupUnavailable
	}
	salt, nonce := make([]byte, 16), make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, errBackupUnavailable
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, errBackupUnavailable
	}
	key, err := backupKey(password, salt)
	if err != nil {
		return nil, errBackupUnavailable
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errBackupUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errBackupUnavailable
	}
	header := append([]byte(backupHeader), salt...)
	out := append([]byte(nil), header...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, header)
	return out, nil
}

func openBackup(envelope, password []byte) ([]byte, error) {
	if len(envelope) < len(backupHeader)+16+12+16 || len(envelope) > backupMaxEnvelope || len(password) < 12 || len(password) > 1024 || !utf8.Valid(password) || string(envelope[:len(backupHeader)]) != backupHeader {
		return nil, errBackupUnavailable
	}
	const headerLen = len(backupHeader) + 16
	header := envelope[:headerLen]
	salt := envelope[len(backupHeader):headerLen]
	nonce := envelope[headerLen : headerLen+12]
	key, err := backupKey(password, salt)
	if err != nil {
		return nil, errBackupUnavailable
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errBackupUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errBackupUnavailable
	}
	plain, err := gcm.Open(nil, nonce, envelope[headerLen+12:], header)
	if err != nil || len(plain) == 0 || len(plain) > backupMaxPlain {
		clear(plain)
		return nil, errBackupUnavailable
	}
	return plain, nil
}

func backupPath(path string) (string, error) {
	if path == "" || len(path) > 32767 || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) {
		return "", errBackupUnavailable
	}
	if strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return "", errBackupUnavailable
	}
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return "", errBackupUnavailable
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", errBackupUnavailable
	}
	clean := filepath.Clean(abs)
	volume := filepath.VolumeName(clean)
	current := volume + string(filepath.Separator)
	rest := strings.TrimLeft(strings.TrimPrefix(clean, current), string(filepath.Separator))
	parts := strings.Split(rest, string(filepath.Separator))
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) && i == len(parts)-1 {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return "", errBackupUnavailable
		}
		attrs, attrErr := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if attrErr != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return "", errBackupUnavailable
		}
		if i < len(parts)-1 && !info.IsDir() {
			return "", errBackupUnavailable
		}
	}
	return clean, nil
}

func openBackupFile(path string) (*os.File, error) {
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errBackupUnavailable
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errBackupUnavailable
	}
	return os.NewFile(uintptr(handle), path), nil
}

func (a *Application) exportBackup(path, password string) (BackupExportResult, error) {
	if a == nil || a.Store == nil {
		return BackupExportResult{}, errBackupUnavailable
	}
	path, err := backupPath(path)
	if err != nil {
		return BackupExportResult{}, errBackupUnavailable
	}
	doc, err := a.Store.Load()
	if err != nil {
		return BackupExportResult{}, errBackupUnavailable
	}
	plain, err := json.Marshal(doc)
	if err != nil || len(plain) == 0 || len(plain) > backupMaxPlain {
		clear(plain)
		return BackupExportResult{}, errBackupUnavailable
	}
	defer clear(plain)
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	envelope, err := sealBackup(plain, passwordBytes)
	if err != nil {
		return BackupExportResult{}, errBackupUnavailable
	}
	defer clear(envelope)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return BackupExportResult{}, errBackupUnavailable
	}
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	n, err := f.Write(envelope)
	if err != nil || n != len(envelope) || f.Sync() != nil {
		return BackupExportResult{}, errBackupUnavailable
	}
	if err = f.Close(); err != nil {
		return BackupExportResult{}, errBackupUnavailable
	}
	keep = true
	return BackupExportResult{ProfileCount: len(doc.Profiles)}, nil
}

func decodeBackupDocument(plain []byte) (doc Document, err error) {
	defer func() {
		if err != nil {
			eraseDocument(&doc)
		}
	}()
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return doc, errBackupUnavailable
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return doc, errBackupUnavailable
	}
	if doc.Version != 1 || len(doc.Profiles) > 2000 {
		return doc, errBackupUnavailable
	}
	seen, groups := map[string]bool{}, map[string]bool{}
	for i := range doc.Profiles {
		p := &doc.Profiles[i]
		if p.Group == "" {
			p.Group = "Без группы"
		}
		if err := Validate(*p); err != nil || seen[p.ID] {
			return doc, errBackupUnavailable
		}
		seen[p.ID], groups[p.Group] = true, true
		network, err := protocol.NormalizeNetworkOptions(p.Network)
		if err != nil || protocol.ValidateNetworkOptions(network, p.Protocol, true) != nil {
			return doc, errBackupUnavailable
		}
		p.Network = network
	}
	if normalizeRoutingProfiles(&doc) != nil {
		return doc, errBackupUnavailable
	}
	if doc.FavoriteIDs == nil {
		doc.FavoriteIDs = []string{}
	}
	doc.FavoriteIDs = normalizeFavoriteIDs(doc.FavoriteIDs, doc.Profiles)
	if doc.SubscriptionSources == nil {
		doc.SubscriptionSources = map[string]string{}
	}
	for group, source := range doc.SubscriptionSources {
		if !groups[group] || !SecureURL(source) {
			return doc, errBackupUnavailable
		}
	}
	for group := range doc.SubscriptionMetadata {
		if !groups[group] || doc.SubscriptionSources[group] == "" {
			return doc, errBackupUnavailable
		}
	}
	for _, name := range doc.CollapsedGroups {
		if !ValidName(name) {
			return doc, errBackupUnavailable
		}
	}
	for group, schedule := range doc.SubscriptionSchedules {
		if !groups[group] || doc.SubscriptionSources[group] == "" || !validSchedule(schedule) {
			return doc, errBackupUnavailable
		}
	}
	if _, err := normalizedUserPreferences(doc.UserSettings, doc); err != nil {
		return doc, errBackupUnavailable
	}
	return doc, nil
}

func (a *Application) previewBackupRestore(path, password string) (BackupRestorePreview, error) {
	a.clearBackupRestore("")
	if a == nil || a.Store == nil || !a.refreshAllowed() {
		return BackupRestorePreview{}, errBackupUnavailable
	}
	path, err := backupPath(path)
	if err != nil {
		return BackupRestorePreview{}, errBackupUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > backupMaxEnvelope {
		return BackupRestorePreview{}, errBackupUnavailable
	}
	file, err := openBackupFile(path)
	if err != nil {
		return BackupRestorePreview{}, errBackupUnavailable
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() > backupMaxEnvelope {
		_ = file.Close()
		return BackupRestorePreview{}, errBackupUnavailable
	}
	envelope, err := readBounded(file, backupMaxEnvelope)
	_ = file.Close()
	if err != nil {
		clear(envelope)
		return BackupRestorePreview{}, errBackupUnavailable
	}
	defer clear(envelope)
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	plain, err := openBackup(envelope, passwordBytes)
	if err != nil {
		return BackupRestorePreview{}, errBackupUnavailable
	}
	defer clear(plain)
	candidate, err := decodeBackupDocument(plain)
	if err != nil {
		return BackupRestorePreview{}, errBackupUnavailable
	}
	current, err := a.Store.Load()
	if err != nil {
		eraseDocument(&candidate)
		return BackupRestorePreview{}, errBackupUnavailable
	}
	baseline := a.Store.revision
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		eraseDocument(&candidate)
		return BackupRestorePreview{}, errBackupUnavailable
	}
	token := base64.RawURLEncoding.EncodeToString(random[:])
	expires := a.now().Add(10 * time.Minute)
	a.backupPreview = &pendingBackupRestore{token: token, candidate: candidate, baseline: baseline, expires: expires}
	enabledSchedules := 0
	for _, schedule := range candidate.SubscriptionSchedules {
		if schedule.Enabled {
			enabledSchedules++
		}
	}
	return BackupRestorePreview{Token: token, CurrentProfiles: len(current.Profiles), ReplacementProfiles: len(candidate.Profiles), EnabledSchedules: enabledSchedules, CanApply: true, ExpiresAt: expires.Format(time.RFC3339)}, nil
}

func (a *Application) clearBackupRestore(token string) {
	if a == nil || a.backupPreview == nil || (token != "" && token != a.backupPreview.token) {
		return
	}
	eraseDocument(&a.backupPreview.candidate)
	a.backupPreview = nil
}

// Expiration is swept on serialized commands; RunHost exit also clears the candidate.
func (a *Application) expireBackupRestore() {
	if a != nil && a.backupPreview != nil && !a.now().Before(a.backupPreview.expires) {
		a.clearBackupRestore("")
	}
}

func eraseDocument(doc *Document) {
	if doc == nil {
		return
	}
	if doc.UserSettings != nil {
		*doc.UserSettings = UserPreferences{}
		doc.UserSettings = nil
	}
	for i := range doc.Profiles {
		profile := &doc.Profiles[i]
		if profile.Network != nil {
			if profile.Network.DNS != nil {
				*profile.Network.DNS = protocol.DNSOptions{}
			}
			clear(profile.Network.Rules)
			clear(profile.Network.Resolvers)
			clear(profile.Network.DNSRules)
			*profile.Network = protocol.NetworkOptions{}
		}
		if profile.Transport != nil {
			*profile.Transport = protocol.TransportOptions{}
		}
		if profile.Reliability != nil {
			*profile.Reliability = control.ReliabilityOptions{}
		}
		profile.Source, profile.Name, profile.Group, profile.Label, profile.ID = "", "", "", "", ""
		doc.Profiles[i] = Profile{}
	}
	clear(doc.Profiles)
	doc.Profiles = nil
	for key := range doc.SubscriptionSources {
		delete(doc.SubscriptionSources, key)
	}
	for key := range doc.SubscriptionMetadata {
		delete(doc.SubscriptionMetadata, key)
	}
	for key := range doc.SubscriptionSchedules {
		delete(doc.SubscriptionSchedules, key)
	}
	clear(doc.FavoriteIDs)
	clear(doc.RoutingProfiles)
	clear(doc.CollapsedGroups)
	*doc = Document{}
}

func (a *Application) applyBackupRestore(token string, restoreSchedules bool) (Document, error) {
	pending := a.backupPreview
	if pending == nil || token == "" || token != pending.token {
		return Document{}, errBackupUnavailable
	}
	if !a.now().Before(pending.expires) {
		a.clearBackupRestore("")
		return Document{}, errBackupUnavailable
	}
	if !a.refreshAllowed() {
		a.clearBackupRestore("")
		return Document{}, errBackupUnavailable
	}
	if _, err := a.Store.Load(); err != nil {
		a.clearBackupRestore("")
		return Document{}, errBackupUnavailable
	}
	if a.Store.revision != pending.baseline {
		a.clearBackupRestore("")
		return Document{}, errBackupUnavailable
	}
	// Replacing preferences must not leave an owned or unreconciled proxy behind.
	if a.UserAutomation != nil && a.UserAutomation.initializationErr != nil {
		return Document{}, errBackupUnavailable
	}
	if err := a.releaseUserProxy(); err != nil {
		return Document{}, errBackupUnavailable
	}
	candidate := pending.candidate
	disableRestoredUserAutomation(&candidate)
	if !restoreSchedules {
		for group, schedule := range candidate.SubscriptionSchedules {
			schedule.Enabled = false
			candidate.SubscriptionSchedules[group] = schedule
		}
	}
	a.backupPreview = nil
	if err := a.Store.Save(candidate); err != nil {
		eraseDocument(&candidate)
		eraseDocument(&pending.candidate)
		return Document{}, errBackupUnavailable
	}
	if a.pendingPreview != nil {
		eraseDocument(&a.pendingPreview.candidate)
		a.pendingPreview = nil
	}
	a.scheduleNext = nil
	a.scheduleLastNow = time.Time{}
	result, err := a.Store.Load()
	eraseDocument(&candidate)
	eraseDocument(&pending.candidate)
	if err != nil {
		return Document{}, errBackupUnavailable
	}
	return result, nil
}
