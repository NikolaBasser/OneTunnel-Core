package profiles

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

type Request struct {
	Reliability    *control.ReliabilityOptions
	Version        int
	Command        string
	Name           string
	Source         string
	Group          string
	Subscription   bool
	Expanded       bool
	Requested      *int
	Profile        *Profile
	Existing       []Profile
	Incoming       []Profile
	Document       *Document
	ID             string
	Token          string
	Transport      *protocol.TransportOptions
	Data           []byte
	Encrypt        bool
	Path           string
	FullDevice     bool
	TransportInput *TransportInput
	Observation    *platform.ServiceObservation
	Context        *DesktopContext
	Retained       *DesktopReply
}
type Applied struct {
	Document   Document
	Selected   *Profile
	Added      int
	Updated    int
	Removed    int
	Duplicates int
	Skipped    int
	Batch      bool
	Offline    bool
	Retired    bool
}
type Environment struct {
	MaxImportBytes int
	Root           string
	Administrator  bool
	NeedsRecovery  bool
	Awg            bool
	Xray           bool
	SingBox        bool
}
type Application struct {
	Store           *Store
	Directory       string
	Downloader      func(context.Context, string) (ImportResult, error)
	ServiceCall     ServiceCaller
	desktopState    DesktopReply
	desktopContext  DesktopContext
	desktopChecked  uint64
	desktopRevision uint64
	desktopRetired  map[string]bool
	pendingPreview  *pendingSubscriptionPreview
}

type pendingSubscriptionPreview struct {
	token, group                                 string
	baseline                                     [32]byte
	candidate                                    Document
	expires                                      time.Time
	added, updated, removed, duplicates, skipped int
}

type SubscriptionSummary struct {
	Group        string
	ProfileCount int
	UpdatedAt    string
	Usage        string
	Expiry       string
	CanRefresh   bool
}
type SubscriptionChange struct{ Name, Protocol, Kind string }
type SubscriptionPreview struct {
	Token, Group, Usage, Expiry, ExpiresAt       string
	Added, Updated, Removed, Duplicates, Skipped int
	Changes                                      []SubscriptionChange
	CanApply                                     bool
}

func recordSubscriptionMetadata(d *Document, group string, metadata *SubscriptionMetadata) {
	if d.SubscriptionMetadata == nil {
		d.SubscriptionMetadata = map[string]SubscriptionMetadata{}
	}
	value := SubscriptionMetadata{UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	if metadata != nil {
		value.Upload, value.Download, value.Total, value.Expire = metadata.Upload, metadata.Download, metadata.Total, metadata.Expire
	}
	d.SubscriptionMetadata[group] = value
}

func formatBytes(value uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB"}
	n := float64(value)
	i := 0
	for n >= 1000 && i < len(units)-1 {
		n /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", value)
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}

func metadataDisplay(m SubscriptionMetadata) (string, string) {
	usage := "Unknown · provider did not report usage"
	quota := m.Total != nil && *m.Total > 0
	var used uint64
	usedKnown := false
	if m.Upload != nil && m.Download != nil {
		if ^uint64(0)-*m.Upload >= *m.Download {
			used = *m.Upload + *m.Download
			usedKnown = true
		}
	}
	if usedKnown {
		if quota {
			remaining := uint64(0)
			if *m.Total > used {
				remaining = *m.Total - used
			}
			usage = fmt.Sprintf("%s used · %s remaining of %s · reported by provider", formatBytes(used), formatBytes(remaining), formatBytes(*m.Total))
		} else {
			usage = fmt.Sprintf("%s used · reported by provider", formatBytes(used))
		}
	} else if m.Upload != nil || m.Download != nil || quota {
		parts := []string{}
		if m.Upload != nil {
			parts = append(parts, "upload "+formatBytes(*m.Upload))
		} else {
			parts = append(parts, "upload unknown")
		}
		if m.Download != nil {
			parts = append(parts, "download "+formatBytes(*m.Download))
		} else {
			parts = append(parts, "download unknown")
		}
		if quota {
			parts = append(parts, "quota "+formatBytes(*m.Total))
		}
		usage = strings.Join(parts, " · ") + " · reported by provider"
	}
	expiry := "Unknown · provider did not report expiry"
	if m.Expire != nil && *m.Expire > 0 && *m.Expire <= 253402300799 {
		expiry = time.Unix(int64(*m.Expire), 0).UTC().Format("02 Jan 2006") + " · reported by provider"
	}
	return usage, expiry
}

func (a *Application) refreshAllowed() bool {
	state := a.desktopState.Response.State
	if state.Active || state.Reconnecting || state.NeedsRecovery || state.TrafficLocked {
		return false
	}
	return !existsProfileFile(a.Store.Root, "session.json") && !existsProfileFile(a.Store.Root, "kill-switch.json")
}

func (a *Application) subscriptionList() ([]SubscriptionSummary, error) {
	d, err := a.Store.Load()
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, p := range d.Profiles {
		counts[p.Group]++
	}
	groups := make([]string, 0, len(d.SubscriptionSources))
	for group := range d.SubscriptionSources {
		if counts[group] > 0 {
			groups = append(groups, group)
		}
	}
	sort.Strings(groups)
	out := make([]SubscriptionSummary, 0, len(groups))
	for _, group := range groups {
		m := d.SubscriptionMetadata[group]
		usage, expiry := metadataDisplay(m)
		out = append(out, SubscriptionSummary{Group: group, ProfileCount: counts[group], UpdatedAt: m.UpdatedAt, Usage: usage, Expiry: expiry, CanRefresh: a.refreshAllowed()})
	}
	return out, nil
}

func (a *Application) refreshPreview(ctx context.Context, group string) (SubscriptionPreview, error) {
	a.pendingPreview = nil
	d, err := a.Store.Load()
	if err != nil {
		return SubscriptionPreview{}, err
	}
	if !a.refreshAllowed() {
		return SubscriptionPreview{}, errors.New("Обновление подписок временно недоступно.")
	}
	source := d.SubscriptionSources[group]
	hasGroup := false
	for _, p := range d.Profiles {
		if p.Group == group {
			hasGroup = true
			break
		}
	}
	if source == "" || !hasGroup {
		return SubscriptionPreview{}, errors.New("Сохранённая подписка не найдена. Обнови список.")
	}
	baseline := a.Store.revision
	original := append([]Profile(nil), d.Profiles...)
	batch, err := a.Downloader(ctx, source)
	if err != nil {
		return SubscriptionPreview{}, err
	}
	merged, err := Merge(d.Profiles, batch.Profiles, group)
	if err != nil {
		return SubscriptionPreview{}, ErrImport
	}
	if len(batch.Profiles) == 0 || len(merged.Profiles) > 2000 {
		return SubscriptionPreview{}, ErrImport
	}
	for _, p := range merged.Profiles {
		if err := Validate(p); err != nil {
			return SubscriptionPreview{}, err
		}
	}
	d.Profiles = merged.Profiles
	recordSubscriptionMetadata(&d, group, batch.Metadata)
	changes := make([]SubscriptionChange, 0, merged.Added+merged.Updated+merged.Removed)
	oldByID, newByID := map[string]Profile{}, map[string]Profile{}
	for _, p := range original {
		oldByID[p.ID] = p
	}
	for _, p := range merged.Profiles {
		newByID[p.ID] = p
	}
	for _, candidate := range merged.Profiles {
		if candidate.Group != group {
			continue
		}
		if old, ok := oldByID[candidate.ID]; !ok {
			changes = append(changes, SubscriptionChange{Name: candidate.Name, Protocol: protocolName(candidate.Protocol), Kind: "added"})
		} else if old.Source != candidate.Source || old.Name != candidate.Name {
			changes = append(changes, SubscriptionChange{Name: candidate.Name, Protocol: protocolName(candidate.Protocol), Kind: "updated"})
		}
	}
	for _, old := range original {
		if old.Group == group {
			if _, ok := newByID[old.ID]; !ok {
				// Merge retains protocol families absent from the response; removed IDs are exact merge removals.
				changes = append(changes, SubscriptionChange{Name: old.Name, Protocol: protocolName(old.Protocol), Kind: "removed"})
			}
		}
	}
	var tokenBytes [24]byte
	if _, err = rand.Read(tokenBytes[:]); err != nil {
		return SubscriptionPreview{}, errors.New("Не удалось подготовить просмотр обновления.")
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes[:])
	expires := time.Now().UTC().Add(10 * time.Minute)
	usage, expiry := metadataDisplay(d.SubscriptionMetadata[group])
	pending := &pendingSubscriptionPreview{token: token, group: group, baseline: baseline, candidate: d, expires: expires,
		added: merged.Added, updated: merged.Updated, removed: merged.Removed, duplicates: batch.Duplicates, skipped: batch.Skipped}
	a.pendingPreview = pending
	return SubscriptionPreview{Token: token, Group: group, Usage: usage, Expiry: expiry, ExpiresAt: expires.Format(time.RFC3339),
		Added: merged.Added, Updated: merged.Updated, Removed: merged.Removed, Duplicates: batch.Duplicates, Skipped: batch.Skipped,
		Changes: changes, CanApply: a.refreshAllowed()}, nil
}

func protocolName(kind int) string {
	if kind >= 0 && kind < len(protocol.Names) {
		return protocol.Names[kind]
	}
	return "Unknown"
}

func (a *Application) applyRefresh(token string) (Applied, error) {
	pending := a.pendingPreview
	if pending == nil || token == "" || token != pending.token {
		return Applied{}, errors.New("Просмотр обновления недействителен. Получи новый.")
	}
	a.pendingPreview = nil
	if time.Now().After(pending.expires) {
		return Applied{}, errors.New("Срок просмотра обновления истёк. Получи новый.")
	}
	if !a.refreshAllowed() {
		return Applied{}, errors.New("Обновление подписок временно недоступно.")
	}
	if _, err := a.Store.Load(); err != nil {
		return Applied{}, err
	}
	if a.Store.revision != pending.baseline {
		return Applied{}, errors.New("Профили изменились после просмотра. Получи новый просмотр обновления.")
	}
	metadata := pending.candidate.SubscriptionMetadata[pending.group]
	metadata.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	pending.candidate.SubscriptionMetadata[pending.group] = metadata
	if err := a.Store.Save(pending.candidate); err != nil {
		return Applied{}, err
	}
	return Applied{Document: pending.candidate, Added: pending.added, Updated: pending.updated, Removed: pending.removed,
		Duplicates: pending.duplicates, Skipped: pending.skipped, Batch: true}, nil
}

func (a *Application) apply(batch ImportResult, source, group string) (Applied, error) {
	d, e := a.Store.Load()
	if e != nil {
		return Applied{}, e
	}
	r := Applied{Batch: true, Duplicates: batch.Duplicates, Skipped: batch.Skipped}
	if IsURL(source) {
		if !SecureURL(source) {
			return r, ErrImport
		}
		merged, e := Merge(d.Profiles, batch.Profiles, group)
		if e != nil {
			return r, e
		}
		d.Profiles = merged.Profiles
		r.Added = merged.Added
		r.Updated = merged.Updated
		r.Removed = merged.Removed
		d.SubscriptionSources[group] = source
		recordSubscriptionMetadata(&d, group, batch.Metadata)
	} else {
		seen := map[string]bool{}
		for _, p := range d.Profiles {
			id, e := Identity(p)
			if e != nil {
				return r, e
			}
			seen[id] = true
		}
		for _, p := range batch.Profiles {
			id, e := Identity(p)
			if e != nil {
				return r, e
			}
			if seen[id] {
				r.Duplicates++
				continue
			}
			seen[id] = true
			p.Group = group
			d.Profiles = append(d.Profiles, p)
			r.Added++
			if r.Selected == nil {
				selected := p
				r.Selected = &selected
			}
		}
	}
	if e = a.Store.Save(d); e != nil {
		return r, e
	}
	r.Document = d
	return r, nil
}
func (a *Application) SaveEditor(ctx context.Context, r Request) (Applied, error) {
	if r.TransportInput != nil {
		parsed, err := r.TransportInput.Parse()
		if err != nil {
			return Applied{}, err
		}
		r.Transport = &parsed
	}
	source := strings.TrimSpace(r.Source)
	batch := IsURL(source) || strings.HasPrefix(source, "[") && !strings.Contains(strings.ToLower(source), "[interface]") || strings.HasPrefix(source, "{") && !strings.Contains(source, `"protocol"`) && !strings.Contains(source, `"type"`) || strings.Contains(source, "\n") && !strings.Contains(strings.ToLower(source), "[interface]") && !strings.HasPrefix(source, "{") || !strings.Contains(source, "://") && !strings.HasPrefix(source, "[") && !strings.HasPrefix(source, "{")
	if strings.HasPrefix(source, "{") && strings.Contains(source, `"outbounds"`) {
		batch = true
	}
	group, e := GroupName(r.Group, r.Name, source, batch)
	if e != nil {
		return Applied{}, e
	}
	if batch {
		if r.Reliability != nil && (r.Reliability.AutoReconnect || r.Reliability.UseFallbacks) {
			return Applied{}, errors.New("Сначала импортируй подписку, затем настрой восстановление у нужного профиля.")
		}
		if r.ID != "" {
			return Applied{}, errors.New("Для импорта подписки нажми «Добавить».")
		}
		if o := r.Transport; o != nil && (o.Fragment || o.Noise || o.Mux) {
			return Applied{}, errors.New("Сначала импортируй подписку с выключенными дополнительными настройками. Затем измени нужный профиль.")
		}
		var imported ImportResult
		if IsURL(source) {
			imported, e = a.Downloader(ctx, source)
		} else {
			imported, e = ParseSubscription(source)
		}
		if e != nil {
			return Applied{}, e
		}
		return a.apply(imported, source, group)
	}
	p, e := Parse(r.Name, source, nil)
	if e != nil {
		return Applied{}, e
	}
	p.Group = group
	p.Transport = r.Transport
	p.Reliability = r.Reliability
	if p.Reliability != nil && !p.Reliability.AutoReconnect {
		p.Reliability = &control.ReliabilityOptions{}
	}
	if e = Validate(p); e != nil {
		return Applied{}, e
	}
	d, e := a.Store.Load()
	if e != nil {
		return Applied{}, e
	}
	if r.ID == "" {
		d.Profiles = append(d.Profiles, p)
	} else {
		found := false
		for i, old := range d.Profiles {
			if old.ID == r.ID {
				p.ID = r.ID
				d.Profiles[i] = p
				found = true
				break
			}
		}
		if !found {
			return Applied{}, errors.New("Профиль удалён другой копией приложения. Обнови список.")
		}
	}
	if e = a.Store.Save(d); e != nil {
		return Applied{}, e
	}
	return Applied{Document: d, Selected: &p}, nil
}
func (a *Application) Prepare(ctx context.Context, id string) (Applied, error) {
	d, e := a.Store.Load()
	if e != nil {
		return Applied{}, e
	}
	var selected *Profile
	for _, p := range d.Profiles {
		if p.ID == id {
			copy := p
			selected = &copy
			break
		}
	}
	if selected == nil {
		return Applied{}, ErrImport
	}
	r := Applied{Document: d, Selected: selected}
	source := d.SubscriptionSources[selected.Group]
	if source == "" || selected.Protocol < 2 {
		return r, nil
	}
	batch, e := a.Downloader(ctx, source)
	if e != nil {
		r.Offline = true
		return r, nil
	}
	merged, e := Merge(d.Profiles, batch.Profiles, selected.Group)
	if e != nil {
		return r, e
	}
	d.Profiles = merged.Profiles
	recordSubscriptionMetadata(&d, selected.Group, batch.Metadata)
	if e = a.Store.Save(d); e != nil {
		return r, e
	}
	r.Document = d
	r.Selected = nil
	for _, p := range d.Profiles {
		if p.ID == id {
			copy := p
			r.Selected = &copy
			break
		}
	}
	r.Retired = r.Selected == nil
	return r, nil
}
func (a *Application) Handle(ctx context.Context, r Request) (any, error) {
	if r.Version != 1 {
		return nil, errors.New("Несовместимая версия ядра профилей. Используй полную новую сборку.")
	}
	if a.desktopState.Response.Instance == "" && r.Retained != nil {
		a.consumeDesktop(platform.ServiceObservation{Available: true, Response: r.Retained.Response, PeerStarted: r.Retained.PeerStarted, CheckedAt: r.Retained.CheckedAt})
		// A new user host retains protection facts but must reauthenticate
		// connectivity with the real service before enabling network actions.
		a.desktopState.Available = false
	}
	if r.Context != nil {
		a.desktopContext = *r.Context
	}
	if strings.HasPrefix(r.Command, "ui.") {
		r.Command = strings.TrimPrefix(r.Command, "ui.")
		value, err := a.Handle(ctx, r)
		return presentationValue(value), err
	}
	if strings.HasPrefix(r.Command, "connection.") {
		return a.desktop(ctx, r)
	}
	switch r.Command {
	case "diagnostics.report":
		report, err := a.diagnosticsReport()
		if err != nil {
			return nil, err
		}
		return report, nil
	case "desktop.context", "desktop.observe", "desktop.unavailable":
		return a.desktopProjectionCommand(r)
	case "editor.load":
		d, err := a.Store.Load()
		if err != nil {
			return nil, err
		}
		for _, p := range d.Profiles {
			if p.ID == r.ID {
				return p, nil
			}
		}
		return nil, ErrImport
	case "transport.defaults":
		return defaults(), nil
	case "profile.view":
		if r.Requested == nil || *r.Requested < 0 || *r.Requested > protocol.MaxKind {
			return nil, ErrImport
		}
		return profileView(*r.Requested), nil
	case "service.start":
		deadline, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := platform.StartPublicService(deadline); err != nil {
			return nil, err
		}
		return a.desktopCall(ctx, "status", nil, false), nil
	case "service.install":
		state := a.desktopCall(ctx, "status", nil, false)
		if state.Available && (state.Response.State.Active || state.Response.State.NeedsRecovery || state.Response.State.TrafficLocked) {
			code := "recovery_required"
			state.Response.Error = &code
			state.Message = platform.ServiceErrorMessage(code)
			return state, nil
		}
		if existsProfileFile(a.Store.Root, "session.json") || existsProfileFile(a.Store.Root, "kill-switch.json") {
			return nil, errors.New("Сначала восстанови подключение прежней версии.")
		}
		if err := platform.ElevateInstall(a.Directory); err != nil {
			return nil, err
		}
		return a.desktopCall(ctx, "status", nil, false), nil
	case "hello":
		embedded := embeddedCapabilities(a.Directory)
		has := func(name string) bool {
			_, e := os.Stat(filepath.Join(a.Directory, "engines", name))
			return embedded[name] || e == nil
		}
		legacy := false
		for _, name := range []string{"session.json", "kill-switch.json"} {
			if _, e := os.Stat(filepath.Join(a.Store.Root, name)); e == nil {
				legacy = true
			}
		}
		return Environment{Root: a.Store.Root, Administrator: windows.GetCurrentProcessToken().IsElevated(), NeedsRecovery: legacy, Awg: has("amneziawg.exe"), Xray: has("xray.exe"), SingBox: has("sing-box.exe"), MaxImportBytes: MaxBytes}, nil
	case "editor.preview":
		return importPreview(r.Source, r.Name), nil
	case "editor.import":
		value, err := a.Handle(ctx, Request{Version: 1, Command: "file.read", Path: r.Path})
		if err != nil {
			return nil, err
		}
		return importPreview(value.(string), strings.TrimSuffix(filepath.Base(r.Path), filepath.Ext(r.Path))), nil
	case "parse":
		return Parse(r.Name, r.Source, r.Requested)
	case "validate":
		if r.Profile == nil {
			return nil, ErrImport
		}
		return nil, Validate(*r.Profile)
	case "url":
		return IsURL(r.Source), nil
	case "group":
		return GroupName(r.Group, r.Name, r.Source, r.Subscription)
	case "identity":
		if r.Profile == nil {
			return nil, ErrImport
		}
		return Identity(*r.Profile)
	case "subscription.parse":
		return ParseSubscription(r.Source)
	case "subscription.download":
		return a.Downloader(ctx, r.Source)
	case "subscription.merge":
		return Merge(r.Existing, r.Incoming, r.Group)
	case "subscription.apply":
		return a.apply(ImportResult{Profiles: r.Incoming}, r.Source, r.Group)
	case "subscription.list":
		return a.subscriptionList()
	case "subscription.refresh.preview":
		return a.refreshPreview(ctx, r.Group)
	case "subscription.refresh.apply":
		return a.applyRefresh(r.Token)
	case "subscription.refresh.cancel":
		if a.pendingPreview != nil && r.Token != "" && r.Token == a.pendingPreview.token {
			a.pendingPreview = nil
		}
		return nil, nil
	case "subscription.prepare":
		return a.Prepare(ctx, r.ID)
	case "group.check":
		return a.checkGroup(ctx, r.Group)
	case "editor.save":
		return a.SaveEditor(ctx, r)
	case "store.load":
		return a.Store.Load()
	case "store.save":
		if r.Document == nil {
			return nil, ErrImport
		}
		return nil, a.Store.Save(*r.Document)
	case "store.protect":
		return Protect(r.Data, r.Encrypt)
	case "delete":
		d, e := a.Store.Load()
		if e != nil {
			return nil, e
		}
		var kept []Profile
		for _, p := range d.Profiles {
			if p.ID != r.ID {
				kept = append(kept, p)
			}
		}
		if kept == nil {
			kept = []Profile{}
		}
		d.Profiles = kept
		if e = a.Store.Save(d); e != nil {
			return nil, e
		}
		return d, nil
	case "group.expansion":
		d, e := a.Store.Load()
		if e != nil {
			return nil, e
		}
		exists := false
		for _, p := range d.Profiles {
			if p.Group == r.Group {
				exists = true
				break
			}
		}
		if !exists {
			return nil, ErrImport
		}
		var collapsed []string
		for _, group := range d.CollapsedGroups {
			if group != r.Group {
				collapsed = append(collapsed, group)
			}
		}
		if !r.Expanded {
			collapsed = append(collapsed, r.Group)
		}
		if collapsed == nil {
			collapsed = []string{}
		}
		d.CollapsedGroups = collapsed
		if e = a.Store.Save(d); e != nil {
			return nil, e
		}
		return d, nil
	case "file.read":
		f, e := os.Open(r.Path)
		if e != nil {
			return nil, errors.New("Не удалось прочитать файл.")
		}
		defer f.Close()
		b, e := readBounded(f, MaxBytes)
		if e != nil {
			return nil, e
		}
		defer clear(b)
		if len(b) >= 2 && ((b[0] == 0xff && b[1] == 0xfe) || (b[0] == 0xfe && b[1] == 0xff)) {
			if len(b)%2 != 0 {
				return nil, ErrImport
			}
			units := make([]uint16, (len(b)-2)/2)
			for i := range units {
				if b[0] == 0xff {
					units[i] = binary.LittleEndian.Uint16(b[2+2*i:])
				} else {
					units[i] = binary.BigEndian.Uint16(b[2+2*i:])
				}
			}
			return string(utf16.Decode(units)), nil
		}
		if !utf8.Valid(b) {
			return nil, ErrImport
		}
		return strings.TrimPrefix(string(b), "\ufeff"), nil
	case "legacy.recover":
		return nil, platform.LegacyUserRecovery(ctx, a.Store.Root, a.Directory)
	default:
		return nil, errors.New("Неизвестная команда ядра профилей.")
	}
}
