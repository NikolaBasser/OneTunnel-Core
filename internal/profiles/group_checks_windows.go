package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
	"time"
)

type GroupCheckRow struct {
	ID, Name, Message        string
	Success, NetworkTest     bool
	Milliseconds             int64
	HTTPSLatencyMilliseconds *int64 `json:",omitempty"`
	DNSLatencyMilliseconds   *int64 `json:",omitempty"`
}
type GroupCheckResult struct {
	Group     string
	CheckedAt string
	Rows      []GroupCheckRow
}

func (a *Application) checkGroup(ctx context.Context, group string) (GroupCheckResult, error) {
	a.groupResults = nil
	result := GroupCheckResult{Group: group, CheckedAt: time.Now().Format(time.RFC3339), Rows: []GroupCheckRow{}}
	status := a.desktopCall(ctx, "status", nil, false)
	if !status.Available || status.Response.State.Active || status.Response.State.TrafficLocked || status.Response.State.NeedsRecovery || status.Response.State.Reconnecting {
		return result, errors.New("Отключи подключение перед проверкой группы")
	}
	document, err := a.Store.Load()
	if err != nil {
		return result, err
	}
	revision := a.Store.revision
	call := a.ServiceCall
	if call == nil {
		call = platform.CallService
	}
	count := 0
	for _, p := range document.Profiles {
		if p.Group == group {
			count++
		}
	}
	if count == 0 || count > 64 {
		return result, errors.New("Выбери группу от 1 до 64 профилей для одной проверки")
	}
	for _, p := range document.Profiles {
		if p.Group != group {
			continue
		}
		deadline, cancel := context.WithTimeout(ctx, 25*time.Second)
		response, _, err := call(deadline, control.Request{Version: 1, Command: "check-profile", Profile: &p})
		cancel()
		if err != nil || response.Error != nil || response.Result == nil {
			return GroupCheckResult{}, errors.New("Проверка прервана: служба недоступна или подключение занято")
		}
		var check control.ProfileCheck
		if json.Unmarshal([]byte(*response.Result), &check) != nil {
			return GroupCheckResult{}, errors.New("Обнови службу для проверки групп")
		}
		if !check.Success || !check.NetworkTest || check.HTTPSLatencyMilliseconds != nil && *check.HTTPSLatencyMilliseconds < 0 {
			check.HTTPSLatencyMilliseconds = nil
		}
		if !check.Success || !check.NetworkTest || check.DNSLatencyMilliseconds != nil && *check.DNSLatencyMilliseconds < 0 {
			check.DNSLatencyMilliseconds = nil
		}
		result.Rows = append(result.Rows, GroupCheckRow{ID: p.ID, Name: p.Name, Success: check.Success, NetworkTest: check.NetworkTest, Milliseconds: check.Milliseconds, Message: check.Message, HTTPSLatencyMilliseconds: check.HTTPSLatencyMilliseconds, DNSLatencyMilliseconds: check.DNSLatencyMilliseconds})
	}
	if err := ctx.Err(); err != nil {
		return GroupCheckResult{}, errors.New("Проверка прервана: служба недоступна или подключение занято")
	}
	rows := cloneGroupCheckRows(result.Rows)
	a.groupResults = &completedGroupResults{result: GroupCheckResult{Group: result.Group, CheckedAt: result.CheckedAt, Rows: rows}, revision: revision, token: newID()}
	return result, nil
}

func cloneGroupCheckRows(rows []GroupCheckRow) []GroupCheckRow {
	copy := append([]GroupCheckRow(nil), rows...)
	for i := range copy {
		if copy[i].HTTPSLatencyMilliseconds != nil {
			value := *copy[i].HTTPSLatencyMilliseconds
			copy[i].HTTPSLatencyMilliseconds = &value
		}
		if copy[i].DNSLatencyMilliseconds != nil {
			value := *copy[i].DNSLatencyMilliseconds
			copy[i].DNSLatencyMilliseconds = &value
		}
	}
	return copy
}
