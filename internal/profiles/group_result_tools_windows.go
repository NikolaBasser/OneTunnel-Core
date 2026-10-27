package profiles

import (
	"errors"
	"fmt"
	"sort"
)

type completedGroupResults struct {
	result   GroupCheckResult
	revision [32]byte
	token    string
}

type GroupResultDisplayRow struct {
	ID, Name, Message        string
	Success, NetworkTest     bool
	Milliseconds             int64
	HTTPSLatencyMilliseconds *int64 `json:",omitempty"`
	DNSLatencyMilliseconds   *int64 `json:",omitempty"`
	TimingLabel              string
	Quality                  *GroupQualitySummary `json:",omitempty"`
}

type GroupResultsView struct {
	Group, CheckedAt                    string
	Rows                                []GroupResultDisplayRow
	HasResults, Stale, CanSelectFastest bool
	Token, Message                      string
}

func eligibleGroupResult(row GroupCheckRow) bool {
	return row.Success && row.NetworkTest && row.Milliseconds >= 0
}

func eligibleGroupSelection(row GroupCheckRow) bool {
	return eligibleGroupResult(row) && row.DNSLatencyMilliseconds == nil
}

func (a *Application) groupResultsView(sortMode, filter string) (GroupResultsView, error) {
	if sortMode == "" {
		sortMode = "stored"
	}
	if filter == "" {
		filter = "all"
	}
	if sortMode != "stored" && sortMode != "duration" {
		return GroupResultsView{}, errors.New("Недопустимый порядок результатов.")
	}
	if filter != "all" && filter != "reachable" && filter != "failed" && filter != "config-only" {
		return GroupResultsView{}, errors.New("Недопустимый фильтр результатов.")
	}
	view := GroupResultsView{Rows: []GroupResultDisplayRow{}, Message: "Проверок ещё нет."}
	batch := a.groupResults
	if batch == nil {
		return view, nil
	}
	view.Group, view.CheckedAt, view.Token = batch.result.Group, batch.result.CheckedAt, batch.token
	view.HasResults = len(batch.result.Rows) > 0
	rows := cloneGroupCheckRows(batch.result.Rows)
	if sortMode == "duration" {
		sort.SliceStable(rows, func(i, j int) bool {
			iOK, jOK := eligibleGroupResult(rows[i]), eligibleGroupResult(rows[j])
			if iOK != jOK {
				return iOK
			}
			return iOK && rows[i].Milliseconds < rows[j].Milliseconds
		})
	}
	view.Rows = make([]GroupResultDisplayRow, 0, len(rows))
	for _, row := range rows {
		if !row.Success || !row.NetworkTest || row.HTTPSLatencyMilliseconds != nil && *row.HTTPSLatencyMilliseconds < 0 {
			row.HTTPSLatencyMilliseconds = nil
		}
		if !row.Success || !row.NetworkTest || row.DNSLatencyMilliseconds != nil && *row.DNSLatencyMilliseconds < 0 {
			row.DNSLatencyMilliseconds = nil
		}
		eligible := eligibleGroupResult(row)
		switch filter {
		case "reachable":
			if !eligible {
				continue
			}
		case "failed":
			if row.Success {
				continue
			}
		case "config-only":
			if row.NetworkTest {
				continue
			}
		}
		label := "Configuration only · no network check"
		if row.NetworkTest {
			label = "Check duration unavailable"
			if row.Milliseconds >= 0 {
				label = formatCheckDuration(row.Milliseconds)
			}
			if row.Success && row.HTTPSLatencyMilliseconds != nil && *row.HTTPSLatencyMilliseconds >= 0 {
				label += fmt.Sprintf(" · %d ms HTTPS latency (not ICMP RTT)", *row.HTTPSLatencyMilliseconds)
			}
			if row.Success && row.DNSLatencyMilliseconds != nil {
				label += fmt.Sprintf(" · %d ms DNS exchange latency (may include initial handshake; not public internet access)", *row.DNSLatencyMilliseconds)
			}
		}
		quality := a.groupQualitySummary(row, a.now())
		if quality != nil {
			label += " · " + quality.Label
		}
		view.Rows = append(view.Rows, GroupResultDisplayRow{
			ID: row.ID, Name: row.Name, Message: row.Message, Success: row.Success,
			NetworkTest: row.NetworkTest, Milliseconds: row.Milliseconds, TimingLabel: label, HTTPSLatencyMilliseconds: row.HTTPSLatencyMilliseconds, DNSLatencyMilliseconds: row.DNSLatencyMilliseconds, Quality: quality,
		})
	}
	view.Stale = a.Store == nil
	if a.Store != nil {
		if _, err := a.Store.Load(); err != nil {
			view.Stale = true
		} else {
			view.Stale = a.Store.revision != batch.revision
		}
	}
	if view.Stale {
		view.Message = "Хранилище изменилось. Запусти проверку группы снова."
		return view, nil
	}
	view.Message = ""
	view.CanSelectFastest = a.refreshAllowed() && hasEligibleGroupResult(rows)
	if !view.CanSelectFastest && !view.HasResults {
		view.Message = "В проверке нет результатов."
	} else if !view.CanSelectFastest {
		view.Message = "Нет подходящего результата для выбора."
	}
	return view, nil
}

func hasEligibleGroupResult(rows []GroupCheckRow) bool {
	for _, row := range rows {
		if eligibleGroupSelection(row) {
			return true
		}
	}
	return false
}

func (a *Application) groupResultsFastest(token string) (string, error) {
	batch := a.groupResults
	if batch == nil || token == "" || token != batch.token || a.Store == nil {
		return "", errors.New("Результаты проверки устарели. Запусти проверку группы снова.")
	}
	document, err := a.Store.Load()
	if err != nil || a.Store.revision != batch.revision || !a.refreshAllowed() {
		return "", errors.New("Результаты проверки устарели или выбор сейчас недоступен.")
	}
	var fastest *GroupCheckRow
	for i := range batch.result.Rows {
		row := &batch.result.Rows[i]
		if eligibleGroupSelection(*row) && (fastest == nil || row.Milliseconds < fastest.Milliseconds) {
			fastest = row
		}
	}
	if fastest == nil {
		return "", errors.New("Нет подходящего результата для выбора.")
	}
	for _, profile := range document.Profiles {
		if profile.ID == fastest.ID {
			return fastest.ID, nil
		}
	}
	return "", errors.New("Результаты проверки устарели. Запусти проверку группы снова.")
}

func formatCheckDuration(milliseconds int64) string {
	return fmt.Sprintf("%d ms check duration", milliseconds)
}
