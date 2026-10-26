package profiles

import (
	"context"
	"errors"
	"sort"
	"time"
)

type SubscriptionSchedule struct {
	Enabled         bool
	IntervalMinutes int
}

type SubscriptionScheduleView struct {
	Group           string
	Token           string
	NextCheckAt     string
	Message         string
	Enabled         bool
	CanEdit         bool
	IntervalMinutes int
}

type ScheduledSubscriptionResult struct {
	Preview *SubscriptionPreview
	Message string
}

type scheduledSubscriptionDue struct {
	interval int
	next     time.Time
}

func validSchedule(schedule SubscriptionSchedule) bool {
	return schedule.IntervalMinutes >= 15 && schedule.IntervalMinutes <= 10080
}

func normalizeSubscriptionSchedules(input map[string]SubscriptionSchedule, profiles []Profile, sources map[string]string) map[string]SubscriptionSchedule {
	if len(input) == 0 {
		return input
	}
	eligible := make(map[string]bool)
	for _, p := range profiles {
		eligible[p.Group] = true
	}
	out := make(map[string]SubscriptionSchedule)
	for group, schedule := range input {
		if eligible[group] && sources[group] != "" && validSchedule(schedule) {
			out[group] = schedule
		}
	}
	return out
}

func (a *Application) scheduleView(group string) (SubscriptionScheduleView, error) {
	if a == nil || a.Store == nil {
		return SubscriptionScheduleView{}, errors.New("profile library unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return SubscriptionScheduleView{}, errors.New("profile library unavailable")
	}
	schedule := doc.SubscriptionSchedules[group]
	eligible := doc.SubscriptionSources[group] != ""
	hasGroup := false
	for _, p := range doc.Profiles {
		hasGroup = hasGroup || p.Group == group
	}
	eligible = eligible && hasGroup
	interval := schedule.IntervalMinutes
	if !validSchedule(SubscriptionSchedule{IntervalMinutes: interval}) {
		interval = 1440
	}
	view := SubscriptionScheduleView{Group: group, Token: fmtHex(a.Store.revision[:]), Enabled: schedule.Enabled,
		IntervalMinutes: interval, CanEdit: eligible && a.refreshAllowed(),
		Message: "Scheduling runs only while this window is open; refreshes create a review preview and never apply automatically."}
	if !eligible {
		view.Enabled, view.IntervalMinutes = false, 0
		view.Message = "Saved subscription group not found."
		return view, nil
	}
	if schedule.Enabled {
		due := a.dueFor(group, schedule)
		view.NextCheckAt = due.UTC().Format(time.RFC3339)
	}
	return view, nil
}

func (a *Application) saveSchedule(group, token string, schedule SubscriptionSchedule) (Document, error) {
	if a == nil || a.Store == nil || !a.refreshAllowed() {
		return Document{}, errors.New("schedule changes are unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return Document{}, errors.New("profile library unavailable")
	}
	if token == "" || token != fmtHex(a.Store.revision[:]) {
		return Document{}, errors.New("profile list changed; reload before retrying")
	}
	eligible := doc.SubscriptionSources[group] != ""
	hasGroup := false
	for _, p := range doc.Profiles {
		hasGroup = hasGroup || p.Group == group
	}
	eligible = eligible && hasGroup
	if !eligible {
		return Document{}, errors.New("saved subscription group not found")
	}
	if schedule.Enabled && !validSchedule(schedule) {
		return Document{}, errors.New("invalid schedule interval")
	}
	current, exists := doc.SubscriptionSchedules[group]
	original := current
	if !schedule.Enabled && !exists {
		return doc, nil
	}
	if !schedule.Enabled {
		if validSchedule(schedule) {
			current.IntervalMinutes = schedule.IntervalMinutes
		}
		if !validSchedule(current) {
			current.IntervalMinutes = 1440
		}
		current.Enabled = false
		schedule = current
	}
	if exists && original == schedule {
		return doc, nil
	}
	if doc.SubscriptionSchedules == nil {
		doc.SubscriptionSchedules = map[string]SubscriptionSchedule{}
	}
	doc.SubscriptionSchedules[group] = schedule
	if err := a.Store.Save(doc); err != nil {
		return Document{}, errors.New("schedule could not be saved")
	}
	if a.scheduleNext != nil {
		delete(a.scheduleNext, group)
	}
	return doc, nil
}

func (a *Application) dueFor(group string, schedule SubscriptionSchedule) time.Time {
	if a.scheduleNext == nil {
		a.scheduleNext = make(map[string]scheduledSubscriptionDue)
	}
	a.observeScheduleClock(a.now())
	due, exists := a.scheduleNext[group]
	if !exists || due.interval != schedule.IntervalMinutes || a.now().Before(due.next) {
		if !exists || due.interval != schedule.IntervalMinutes {
			due = scheduledSubscriptionDue{interval: schedule.IntervalMinutes, next: a.now().Add(time.Duration(schedule.IntervalMinutes) * time.Minute)}
			a.scheduleNext[group] = due
		} else if a.now().Before(due.next.Add(-time.Duration(schedule.IntervalMinutes) * time.Minute)) {
			// A backwards clock jump resets the interval instead of causing a burst.
			due.next = a.now().Add(time.Duration(schedule.IntervalMinutes) * time.Minute)
			a.scheduleNext[group] = due
		}
	}
	return due.next
}

func (a *Application) observeScheduleClock(now time.Time) {
	if !a.scheduleLastNow.IsZero() && now.Before(a.scheduleLastNow) {
		for group, due := range a.scheduleNext {
			due.next = now.Add(time.Duration(due.interval) * time.Minute)
			a.scheduleNext[group] = due
		}
	}
	a.scheduleLastNow = now
}

func (a *Application) scheduleTick(ctx context.Context) (ScheduledSubscriptionResult, error) {
	if a == nil || a.Store == nil {
		return ScheduledSubscriptionResult{}, errors.New("profile library unavailable")
	}
	if !a.refreshAllowed() {
		return ScheduledSubscriptionResult{Message: "Scheduled refresh is unavailable while protection or recovery is active."}, nil
	}
	doc, err := a.Store.Load()
	if err != nil {
		return ScheduledSubscriptionResult{Message: "Scheduled refresh could not read the profile library."}, nil
	}
	groups := make([]string, 0, len(doc.SubscriptionSchedules))
	for group, schedule := range doc.SubscriptionSchedules {
		if schedule.Enabled {
			groups = append(groups, group)
		}
	}
	sort.Strings(groups)
	now := a.now()
	a.observeScheduleClock(now)
	for _, group := range groups {
		schedule := doc.SubscriptionSchedules[group]
		dueAt := a.dueFor(group, schedule)
		if now.Before(dueAt) {
			continue
		}
		if a.scheduleNext == nil {
			a.scheduleNext = map[string]scheduledSubscriptionDue{}
		}
		a.scheduleNext[group] = scheduledSubscriptionDue{interval: schedule.IntervalMinutes, next: now.Add(time.Duration(schedule.IntervalMinutes) * time.Minute)}
		if a.pendingPreview != nil {
			if now.Before(a.pendingPreview.expires) {
				return ScheduledSubscriptionResult{Message: "A subscription review is already waiting."}, nil
			}
			eraseDocument(&a.pendingPreview.candidate)
			a.pendingPreview = nil
		}
		if a.Downloader == nil {
			return ScheduledSubscriptionResult{Message: "Scheduled refresh is unavailable."}, nil
		}
		preview, err := a.refreshPreview(ctx, group)
		if err != nil {
			return ScheduledSubscriptionResult{Message: "Scheduled refresh could not be previewed."}, nil
		}
		return ScheduledSubscriptionResult{Preview: &preview, Message: "Scheduled refresh is ready for review; it was not applied."}, nil
	}
	return ScheduledSubscriptionResult{Message: "No scheduled subscription is due."}, nil
}
