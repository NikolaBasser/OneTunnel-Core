package profiles

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"onetunnel/core/internal/platform"
	"onetunnel/core/internal/protocol"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type Request struct {
	Version      int
	Command      string
	Name         string
	Source       string
	Group        string
	Subscription bool
	Expanded     bool
	Requested    *int
	Profile      *Profile
	Existing     []Profile
	Incoming     []Profile
	Document     *Document
	ID           string
	Transport    *protocol.TransportOptions
	Data         []byte
	Encrypt      bool
	Path         string
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
	Root          string
	Administrator bool
	NeedsRecovery bool
	Awg           bool
	Xray          bool
	SingBox       bool
}
type Application struct {
	Store      *Store
	Directory  string
	Downloader func(context.Context, string) (ImportResult, error)
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
	source := strings.TrimSpace(r.Source)
	batch := IsURL(source) || strings.HasPrefix(source, "[") && !strings.Contains(strings.ToLower(source), "[interface]") || strings.HasPrefix(source, "{") && !strings.Contains(source, `"protocol"`) || strings.Contains(source, "\n") && !strings.Contains(strings.ToLower(source), "[interface]") && !strings.HasPrefix(source, "{") || !strings.Contains(source, "://") && !strings.HasPrefix(source, "[") && !strings.HasPrefix(source, "{")
	if strings.HasPrefix(source, "{") && strings.Contains(source, `"outbounds"`) {
		batch = true
	}
	group, e := GroupName(r.Group, r.Name, source, batch)
	if e != nil {
		return Applied{}, e
	}
	if batch {
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
	if source == "" || (selected.Protocol != 2 && selected.Protocol != 4 && selected.Protocol != 5) {
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
	switch r.Command {
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
		return Environment{Root: a.Store.Root, Administrator: windows.GetCurrentProcessToken().IsElevated(), NeedsRecovery: legacy, Awg: has("amneziawg.exe"), Xray: has("xray.exe"), SingBox: has("sing-box.exe")}, nil
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
	case "subscription.prepare":
		return a.Prepare(ctx, r.ID)
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
