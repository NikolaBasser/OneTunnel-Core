package profiles

import (
	"errors"
	"strings"
)

type GroupSummary struct {
	Name           string
	ProfileCount   int
	IsSubscription bool
	Token          string
}

func (a *Application) groupList() ([]GroupSummary, error) {
	if a.Store == nil {
		return nil, errors.New("profile library unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return nil, errors.New("profile library unavailable")
	}
	token := fmtHex(a.Store.revision[:])
	indexes := make(map[string]int)
	groups := make([]GroupSummary, 0)
	for _, profile := range doc.Profiles {
		index, exists := indexes[profile.Group]
		if !exists {
			index = len(groups)
			indexes[profile.Group] = index
			_, subscription := doc.SubscriptionSources[profile.Group]
			groups = append(groups, GroupSummary{Name: profile.Group, IsSubscription: subscription, Token: token})
		}
		groups[index].ProfileCount++
	}
	return groups, nil
}

func (a *Application) groupMutationAllowed() bool {
	return a != nil && a.Store != nil && a.refreshAllowed()
}

func (a *Application) renameGroup(group, name, token string) (Document, error) {
	if !a.groupMutationAllowed() {
		return Document{}, errors.New("group changes are unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return Document{}, errors.New("profile library unavailable")
	}
	if token == "" || token != fmtHex(a.Store.revision[:]) {
		return Document{}, errors.New("group list changed; reload before retrying")
	}
	name = strings.TrimSpace(name)
	if name == "" || !ValidName(name) {
		return Document{}, errors.New("invalid group name")
	}
	found := false
	for _, profile := range doc.Profiles {
		if profile.Group == group {
			found = true
			break
		}
	}
	if !found {
		return Document{}, errors.New("group not found")
	}
	if group == name {
		return doc, nil
	}
	for _, profile := range doc.Profiles {
		if profile.Group == name {
			return Document{}, errors.New("target group already exists")
		}
	}
	if _, exists := doc.SubscriptionSources[name]; exists {
		return Document{}, errors.New("target group already exists")
	}
	if _, exists := doc.SubscriptionMetadata[name]; exists {
		return Document{}, errors.New("target group already exists")
	}
	for i := range doc.Profiles {
		if doc.Profiles[i].Group == group {
			doc.Profiles[i].Group = name
		}
	}
	if source, exists := doc.SubscriptionSources[group]; exists {
		delete(doc.SubscriptionSources, group)
		doc.SubscriptionSources[name] = source
	}
	if metadata, exists := doc.SubscriptionMetadata[group]; exists {
		delete(doc.SubscriptionMetadata, group)
		doc.SubscriptionMetadata[name] = metadata
	}
	if schedule, exists := doc.SubscriptionSchedules[group]; exists {
		delete(doc.SubscriptionSchedules, group)
		doc.SubscriptionSchedules[name] = schedule
	}
	wasCollapsed := false
	for _, current := range doc.CollapsedGroups {
		wasCollapsed = wasCollapsed || current == group
	}
	collapsed := make([]string, 0, len(doc.CollapsedGroups))
	for _, current := range doc.CollapsedGroups {
		if current != group && current != name {
			collapsed = append(collapsed, current)
		}
	}
	if wasCollapsed {
		collapsed = append(collapsed, name)
	}
	doc.CollapsedGroups = collapsed
	if err := a.Store.Save(doc); err != nil {
		return Document{}, errors.New("group rename could not be saved")
	}
	return doc, nil
}

func (a *Application) deleteGroup(group, token string) (Document, error) {
	if !a.groupMutationAllowed() {
		return Document{}, errors.New("group changes are unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return Document{}, errors.New("profile library unavailable")
	}
	if token == "" || token != fmtHex(a.Store.revision[:]) {
		return Document{}, errors.New("group list changed; reload before retrying")
	}
	found := false
	kept := make([]Profile, 0, len(doc.Profiles))
	for _, profile := range doc.Profiles {
		if profile.Group == group {
			found = true
			continue
		}
		kept = append(kept, profile)
	}
	if !found {
		return Document{}, errors.New("group not found")
	}
	doc.Profiles = kept
	delete(doc.SubscriptionSources, group)
	delete(doc.SubscriptionMetadata, group)
	delete(doc.SubscriptionSchedules, group)
	collapsed := make([]string, 0, len(doc.CollapsedGroups))
	for _, current := range doc.CollapsedGroups {
		if current != group {
			collapsed = append(collapsed, current)
		}
	}
	doc.CollapsedGroups = collapsed
	if err := a.Store.Save(doc); err != nil {
		return Document{}, errors.New("group deletion could not be saved")
	}
	return doc, nil
}

func (a *Application) setAllGroupsExpanded(expanded bool) (Document, error) {
	if a == nil || a.Store == nil {
		return Document{}, errors.New("group changes are unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return Document{}, errors.New("profile library unavailable")
	}
	if expanded {
		if len(doc.CollapsedGroups) == 0 {
			return doc, nil
		}
		doc.CollapsedGroups = []string{}
	} else {
		collapsed := make([]string, 0)
		seen := make(map[string]bool)
		for _, profile := range doc.Profiles {
			if !seen[profile.Group] {
				collapsed = append(collapsed, profile.Group)
				seen[profile.Group] = true
			}
		}
		if sameCollapsedGroups(doc.CollapsedGroups, collapsed) {
			return doc, nil
		}
		doc.CollapsedGroups = collapsed
	}
	if err := a.Store.Save(doc); err != nil {
		return Document{}, errors.New("group expansion state could not be saved")
	}
	return doc, nil
}

func (a *Application) setGroupExpanded(group string, expanded bool) (Document, error) {
	if a == nil || a.Store == nil {
		return Document{}, errors.New("group changes are unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return Document{}, errors.New("profile library unavailable")
	}
	found, collapsed := false, false
	for _, profile := range doc.Profiles {
		found = found || profile.Group == group
	}
	for _, current := range doc.CollapsedGroups {
		collapsed = collapsed || current == group
	}
	if !found {
		return Document{}, errors.New("group not found")
	}
	if expanded == !collapsed {
		return doc, nil
	}
	updated := make([]string, 0, len(doc.CollapsedGroups)+1)
	for _, current := range doc.CollapsedGroups {
		if current != group {
			updated = append(updated, current)
		}
	}
	if !expanded {
		updated = append(updated, group)
	}
	doc.CollapsedGroups = updated
	if err := a.Store.Save(doc); err != nil {
		return Document{}, errors.New("group expansion state could not be saved")
	}
	return doc, nil
}

func sameCollapsedGroups(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	members := make(map[string]bool, len(right))
	for _, name := range right {
		members[name] = true
	}
	for _, name := range left {
		if !members[name] {
			return false
		}
		delete(members, name)
	}
	return len(members) == 0
}
