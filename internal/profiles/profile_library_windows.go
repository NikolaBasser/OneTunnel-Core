package profiles

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

var favoriteProfileIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type LibraryView struct {
	IDs []string `json:"ids"`
}

func normalizeFavoriteIDs(favoriteIDs []string, profiles []Profile) []string {
	existing := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		existing[profile.ID] = true
	}
	seen := make(map[string]bool, min(len(favoriteIDs), len(profiles)))
	var result []string
	for _, id := range favoriteIDs {
		if existing[id] && !seen[id] {
			result = append(result, id)
			seen[id] = true
		}
	}
	return result
}

func (a *Application) setFavorite(id string, favorite bool) (Document, error) {
	if a.Store == nil {
		return Document{}, errors.New("profile library unavailable")
	}
	if !favoriteProfileIDPattern.MatchString(id) {
		return Document{}, errors.New("invalid profile ID")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return Document{}, errors.New("profile library unavailable")
	}
	found := false
	for _, profile := range doc.Profiles {
		if profile.ID == id {
			found = true
			break
		}
	}
	if !found {
		return Document{}, errors.New("profile not found")
	}
	wasFavorite := false
	for _, favoriteID := range doc.FavoriteIDs {
		if favoriteID == id {
			wasFavorite = true
			break
		}
	}
	if wasFavorite == favorite {
		return doc, nil
	}
	if favorite {
		doc.FavoriteIDs = append(doc.FavoriteIDs, id)
	} else {
		kept := doc.FavoriteIDs[:0]
		for _, favoriteID := range doc.FavoriteIDs {
			if favoriteID != id {
				kept = append(kept, favoriteID)
			}
		}
		doc.FavoriteIDs = kept
	}
	if err := a.Store.Save(doc); err != nil {
		return Document{}, errors.New("profile favorite could not be saved")
	}
	return doc, nil
}

func (a *Application) libraryView(mode string, favoritesOnly bool) (LibraryView, error) {
	if mode == "" {
		mode = "stored"
	}
	if mode != "stored" && mode != "name" && mode != "protocol" {
		return LibraryView{}, errors.New("invalid library sort mode")
	}
	if a.Store == nil {
		return LibraryView{}, errors.New("profile library unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return LibraryView{}, errors.New("profile library unavailable")
	}
	return projectLibraryView(doc, mode, favoritesOnly), nil
}

func projectLibraryView(doc Document, mode string, favoritesOnly bool) LibraryView {
	favorites := make(map[string]bool, len(doc.FavoriteIDs))
	for _, id := range doc.FavoriteIDs {
		favorites[id] = true
	}
	indexes := make([]int, 0, len(doc.Profiles))
	for i, profile := range doc.Profiles {
		if !favoritesOnly || favorites[profile.ID] {
			indexes = append(indexes, i)
		}
	}
	switch mode {
	case "name":
		// Lowercase Unicode names compare case-insensitively; stable ties retain stored order.
		names := make([]string, len(doc.Profiles))
		for _, index := range indexes {
			names[index] = strings.ToLower(doc.Profiles[index].Name)
		}
		sort.SliceStable(indexes, func(i, j int) bool {
			return names[indexes[i]] < names[indexes[j]]
		})
	case "protocol":
		sort.SliceStable(indexes, func(i, j int) bool {
			return doc.Profiles[indexes[i]].Protocol < doc.Profiles[indexes[j]].Protocol
		})
	}
	ids := make([]string, len(indexes))
	for i, index := range indexes {
		ids[i] = doc.Profiles[index].ID
	}
	return LibraryView{IDs: ids}
}
