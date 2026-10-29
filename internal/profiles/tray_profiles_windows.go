package profiles

import (
	"errors"
)

const trayProfileLimit = 50

type TrayProfileItem struct{ ID, Name, Group string }
type TrayProfilesView struct {
	Token      string
	SelectedID string
	Message    string
	Profiles   []TrayProfileItem
	CanSelect  bool
	Truncated  bool
}

func (a *Application) trayProfilesView() (TrayProfilesView, error) {
	if a == nil || a.Store == nil {
		return TrayProfilesView{}, errors.New("profile library unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return TrayProfilesView{}, errors.New("profile library unavailable")
	}
	count := len(doc.Profiles)
	shown := count
	if shown > trayProfileLimit {
		shown = trayProfileLimit
	}
	items := make([]TrayProfileItem, 0, shown)
	for _, p := range doc.Profiles[:shown] {
		items = append(items, TrayProfileItem{ID: p.ID, Name: p.Name, Group: p.Group})
	}
	view := TrayProfilesView{Token: fmtHex(a.Store.revision[:]), SelectedID: a.desktopContext.SelectedID, Profiles: items,
		CanSelect: a.traySelectionAllowed(), Truncated: count > shown, Message: "Selecting a profile only opens it in the main window; it does not connect."}
	return view, nil
}

func (a *Application) traySelect(id, token string) (string, error) {
	if a == nil || a.Store == nil || !a.traySelectionAllowed() {
		return "", errors.New("profile selection is unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return "", errors.New("profile library unavailable")
	}
	if token == "" || token != fmtHex(a.Store.revision[:]) {
		return "", errors.New("profile list changed; reload before selecting")
	}
	for _, p := range doc.Profiles {
		if id != "" && p.ID == id {
			return id, nil
		}
	}
	return "", errors.New("profile not found")
}

func (a *Application) traySelectionAllowed() bool {
	return a != nil && !a.desktopContext.Busy && a.desktopContext.StorageReady
}
