package profiles

import (
	"errors"
	"strings"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"github.com/rivo/uniseg"
)

type ProfileOrganizationView struct {
	ID, Name, Group, SuggestedName, SuggestedGroup, Token string
	ManualTargets                                         []string
	CanDuplicate, CanMove                                 bool
}

func (a *Application) profileOrganization(id string) (ProfileOrganizationView, error) {
	if a == nil || a.Store == nil {
		return ProfileOrganizationView{}, errors.New("profile library unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return ProfileOrganizationView{}, errors.New("profile library unavailable")
	}
	var selected *Profile
	managed := make(map[string]bool, len(doc.SubscriptionSources)+len(doc.SubscriptionMetadata))
	for group := range doc.SubscriptionSources {
		managed[group] = true
	}
	for group := range doc.SubscriptionMetadata {
		managed[group] = true
	}
	targets := make([]string, 0)
	seen := make(map[string]bool)
	for i := range doc.Profiles {
		profile := &doc.Profiles[i]
		if profile.ID == id {
			selected = profile
		}
		if !managed[profile.Group] && !seen[profile.Group] {
			seen[profile.Group] = true
			targets = append(targets, profile.Group)
		}
	}
	if selected == nil {
		return ProfileOrganizationView{}, errors.New("profile not found")
	}
	available := a.refreshAllowed() && a.desktopContext.StorageReady && a.desktopContext.SelectedID == id
	suggestedGroup := selected.Group
	canMove := available && !managed[selected.Group]
	if managed[selected.Group] {
		suggestedGroup = "Local copies"
	}
	return ProfileOrganizationView{
		ID: selected.ID, Name: selected.Name, Group: selected.Group,
		SuggestedName: suggestedCopyName(selected.Name), SuggestedGroup: suggestedGroup,
		Token: fmtHex(a.Store.revision[:]), ManualTargets: targets,
		CanDuplicate: available, CanMove: canMove,
	}, nil
}

func suggestedCopyName(name string) string {
	const suffix = " (copy)"
	base := strings.TrimSpace(name)
	clusters := make([]string, 0, uniseg.GraphemeClusterCount(base))
	g := uniseg.NewGraphemes(base)
	for g.Next() {
		clusters = append(clusters, g.Str())
	}
	for len(clusters) > 0 {
		candidate := strings.Join(clusters, "") + suffix
		if ValidName(candidate) {
			return candidate
		}
		clusters = clusters[:len(clusters)-1]
	}
	return "Profile copy"
}

func (a *Application) duplicateProfile(id, name, group, token string) (Applied, error) {
	doc, profile, err := a.loadOrganizationProfile(id, token)
	if err != nil {
		return Applied{}, err
	}
	if !a.organizationMutationAllowed() {
		return Applied{}, errors.New("profile changes are unavailable")
	}
	name, group = strings.TrimSpace(name), strings.TrimSpace(group)
	if name == "" || !ValidName(name) {
		return Applied{}, errors.New("invalid profile name")
	}
	if err := validateManualDestination(doc, group); err != nil {
		return Applied{}, err
	}
	copy := cloneOrganizationProfile(profile)
	copy.ID, copy.Name, copy.Group = newID(), name, group
	doc.Profiles = append(doc.Profiles, copy)
	if state, ok := doc.RoutingProfiles[profile.ID]; ok {
		doc.RoutingProfiles[copy.ID] = state
	}
	if err := a.Store.Save(doc); err != nil {
		return Applied{}, errors.New("profile copy could not be saved")
	}
	selected := cloneOrganizationProfile(copy)
	return Applied{Document: doc, Selected: &selected, Added: 1}, nil
}

func (a *Application) moveProfile(id, group, token string) (Applied, error) {
	doc, profile, err := a.loadOrganizationProfile(id, token)
	if err != nil {
		return Applied{}, err
	}
	if !a.organizationMutationAllowed() {
		return Applied{}, errors.New("profile changes are unavailable")
	}
	if isManagedGroup(doc, profile.Group) {
		return Applied{}, errors.New("subscription profiles must be copied, not moved")
	}
	group = strings.TrimSpace(group)
	if err := validateManualDestination(doc, group); err != nil {
		return Applied{}, err
	}
	if group == profile.Group {
		selected := cloneOrganizationProfile(profile)
		return Applied{Document: doc, Selected: &selected}, nil
	}
	oldGroup := profile.Group
	for i := range doc.Profiles {
		if doc.Profiles[i].ID == id {
			doc.Profiles[i].Group = group
			break
		}
	}
	oldGroupRemains := false
	for _, candidate := range doc.Profiles {
		if candidate.Group == oldGroup {
			oldGroupRemains = true
			break
		}
	}
	if !oldGroupRemains {
		collapsed := make([]string, 0, len(doc.CollapsedGroups))
		for _, current := range doc.CollapsedGroups {
			if current != oldGroup {
				collapsed = append(collapsed, current)
			}
		}
		doc.CollapsedGroups = collapsed
	}
	if err := a.Store.Save(doc); err != nil {
		return Applied{}, errors.New("profile move could not be saved")
	}
	for i := range doc.Profiles {
		if doc.Profiles[i].ID == id {
			selected := cloneOrganizationProfile(doc.Profiles[i])
			return Applied{Document: doc, Selected: &selected}, nil
		}
	}
	return Applied{}, errors.New("profile not found")
}

func (a *Application) loadOrganizationProfile(id, token string) (Document, Profile, error) {
	if a == nil || a.Store == nil {
		return Document{}, Profile{}, errors.New("profile library unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return Document{}, Profile{}, errors.New("profile library unavailable")
	}
	if token == "" || token != fmtHex(a.Store.revision[:]) {
		return Document{}, Profile{}, errors.New("profile list changed; reload before retrying")
	}
	for _, profile := range doc.Profiles {
		if profile.ID == id {
			return doc, profile, nil
		}
	}
	return Document{}, Profile{}, errors.New("profile not found")
}

func (a *Application) organizationMutationAllowed() bool {
	return a != nil && a.Store != nil && a.refreshAllowed()
}

func isManagedGroup(doc Document, group string) bool {
	_, source := doc.SubscriptionSources[group]
	_, metadata := doc.SubscriptionMetadata[group]
	return source || metadata
}

func validateManualDestination(doc Document, group string) error {
	if group == "" || !ValidName(group) {
		return errors.New("invalid destination group")
	}
	if isManagedGroup(doc, group) {
		return errors.New("choose a manual destination group")
	}
	return nil
}

func cloneOrganizationProfile(profile Profile) Profile {
	copy := profile
	if profile.Transport != nil {
		transport := *profile.Transport
		copy.Transport = &transport
	}
	if profile.Reliability != nil {
		reliability := *profile.Reliability
		copy.Reliability = &reliability
	}
	copy.Network = protocol.CloneNetworkOptions(profile.Network)
	return copy
}
