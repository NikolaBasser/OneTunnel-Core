package profiles

import (
	"context"
	"errors"
	"fmt"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
	"strconv"
)

// UI context describes view inputs only. All connection decisions stay in Go.
type DesktopContext struct {
	Busy, StorageReady bool
	SelectedID         string
	CheckingGroup      bool
}
type DesktopActions struct {
	CanCancelGroup                                                bool
	CanCheckGroup                                                 bool
	CanConnect, CanDisconnect, CanToggle, CanProbe, CanRecover    bool
	CanAdd, CanEdit, CanDelete, CanSelect, CanChangeMode, CanSave bool
	CanInstallService, CanStartService, CanClose                  bool
	ConnectCaption                                                string
}
type DesktopDisplay struct {
	Status, ConnectionInfo, ConnectionHint, RecoveryHint                                          string
	Uploaded, Downloaded, UploadRate, DownloadRate, Elapsed, StatisticsScopeHint, ErrorDiagnostic string
	ShowSession, ShowStatistics                                                                   bool
	ModeIndex                                                                                     int
}

// RunHost serializes commands and observations. No GUI reducer or second
// independent state authority may overwrite this retained service snapshot.
func (a *Application) consumeDesktop(observation platform.ServiceObservation) {
	old := a.desktopState
	incoming := observation.Response.Instance
	current := old.Response.Instance
	olderCheck := observation.CheckedAt != 0 && observation.CheckedAt < a.desktopChecked
	newerRevision := observation.Available && incoming != "" && incoming == current && observation.Response.Revision > a.desktopRevision
	// A later service revision can arrive before an older command response.
	// Keep its state facts, but an older check cannot restore connectivity.
	if olderCheck && !newerRevision {
		return
	}
	if observation.PeerStarted != 0 && old.PeerStarted != 0 && observation.PeerStarted < old.PeerStarted {
		return
	}
	if incoming != "" && a.desktopRetired[incoming] {
		return
	}
	if !observation.Available {
		if incoming != "" && current != "" && incoming != current {
			return
		}
		a.desktopState.Available = false
		if observation.CheckedAt > a.desktopChecked {
			a.desktopChecked = observation.CheckedAt
		}
		// Unavailability never changes Active/TrafficLocked or releases protection.
		return
	}
	if observation.Response.Version != control.Version || incoming == "" {
		return
	}
	if incoming == current {
		if observation.Response.Revision < a.desktopRevision {
			return
		}
	} else {
		if a.desktopRetired == nil {
			a.desktopRetired = map[string]bool{}
		}
		if current != "" {
			a.desktopRetired[current] = true
		}
		a.desktopRevision = 0
	}
	a.desktopRevision = observation.Response.Revision
	if observation.CheckedAt > a.desktopChecked {
		a.desktopChecked = observation.CheckedAt
	}
	available := true
	if olderCheck {
		available = old.Available
	}
	a.desktopState = DesktopReply{Available: available, Response: observation.Response, PeerStarted: observation.PeerStarted, Prepared: old.Prepared}
	a.desktopState.Response.Error = nil
	a.desktopState.Response.Result = nil
}

func (a *Application) projectDesktop(reply DesktopReply, env Environment) DesktopReply {
	c := a.desktopContext
	s := reply.Response.State
	idle := !s.Active && !s.NeedsRecovery && !s.TrafficLocked && !s.Reconnecting && !env.NeedsRecovery
	actions := DesktopActions{ConnectCaption: "Подключить", CanClose: !c.Busy}
	actions.CanCancelGroup = c.Busy && c.CheckingGroup
	if !c.Busy {
		actions.CanConnect = c.StorageReady && reply.Available && idle && c.SelectedID != ""
		actions.CanDisconnect = reply.Available && (s.Active || s.Reconnecting)
		actions.CanProbe = reply.Available && s.Active && !s.NeedsRecovery && !s.Reconnecting
		actions.CanRecover = reply.Available || c.StorageReady && env.NeedsRecovery
		actions.CanAdd = c.StorageReady && idle
		actions.CanCheckGroup = actions.CanConnect
		actions.CanEdit = actions.CanAdd && c.SelectedID != ""
		actions.CanDelete = actions.CanEdit
		actions.CanSelect = idle
		actions.CanChangeMode = idle
		actions.CanSave = actions.CanAdd
		actions.CanInstallService = idle
		actions.CanStartService = !reply.Available
	}
	if s.Active || s.Reconnecting {
		actions.ConnectCaption = "Отключить"
	}
	actions.CanToggle = actions.CanConnect || actions.CanDisconnect
	display := DesktopDisplay{Status: s.Status, ShowSession: reply.Available && (s.Active || s.Reconnecting)}
	display.ErrorDiagnostic = formatErrorDiagnostic(reply.Response.ErrorInfo)
	if display.ShowSession && s.Statistics != nil && s.Statistics.SchemaVersion == 1 {
		stats := s.Statistics
		display.ShowStatistics = true
		display.Uploaded = optionalBytes(stats.UploadedBytes)
		display.Downloaded = optionalBytes(stats.DownloadedBytes)
		display.UploadRate = optionalRate(stats.UploadBytesPerSecond)
		display.DownloadRate = optionalRate(stats.DownloadBytesPerSecond)
		display.Elapsed = formatElapsed(stats.ElapsedMilliseconds)
		display.StatisticsScopeHint = statisticsScopeHint(stats.Scope)
	}
	if !reply.Available {
		display.Status = "Служба недоступна · состояние сети не подтверждено"
	}
	if display.ShowSession {
		display.ConnectionInfo = fmt.Sprintf("127.0.0.1:%d", s.LocalPort)
		if s.WholeDevice {
			display.ConnectionInfo = "Системный туннель · по конфигурации"
			if s.FullDeviceMode {
				display.ConnectionInfo = "Всё устройство · системный туннель"
			}
		}
		if s.FullDeviceMode {
			display.ModeIndex = 1
		}
		display.ConnectionHint = "Соединением управляет служба. Закрытие окна его не прерывает."
		if s.TrafficLocked {
			display.ConnectionHint = "Kill switch включён. Закрытие окна сохраняет подключение; явное отключение возвращает обычную сеть."
		}
	}
	if s.NeedsRecovery || s.TrafficLocked && !s.Active || env.NeedsRecovery {
		display.RecoveryHint = "Незавершённое подключение. Доступно восстановление собственного сетевого состояния."
	}
	if !reply.Available && (s.TrafficLocked || s.Active || s.NeedsRecovery) {
		display.RecoveryHint = "Нет связи со службой. Последнее состояние защиты сохранено; запусти службу и проверь восстановление."
	}
	reply.Actions = actions
	reply.CheckedAt = a.desktopChecked
	reply.Display = display
	reply.Environment = &env
	return reply
}

func optionalBytes(value *uint64) string {
	if value == nil {
		return "—"
	}
	return formatByteCount(*value)
}
func optionalRate(value *uint64) string {
	if value == nil {
		return "—"
	}
	return formatByteCount(*value) + "/s"
}
func formatByteCount(value uint64) string {
	units := [...]string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	if value < 1024 {
		return strconv.FormatUint(value, 10) + " " + units[0]
	}
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	return strconv.FormatUint(value, 10) + " " + units[unit]
}
func formatElapsed(milliseconds uint64) string {
	seconds := milliseconds / 1000
	days := seconds / 86400
	seconds %= 86400
	hours, minutes := seconds/3600, (seconds%3600)/60
	seconds %= 60
	if days > 0 {
		return fmt.Sprintf("%dd %02d:%02d:%02d", days, hours, minutes, seconds)
	}
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}
func statisticsScopeHint(scope string) string {
	switch scope {
	case "proxy-payload":
		return "Local proxy payload, including connection checks; current attempt. Not a provider billing counter."
	case "proxy-payload-and-packets":
		return "TUN ingress only: proxy payload plus fast-flow packet bytes; local connection checks are excluded. Not a provider billing counter."
	case "native-transport":
		return "Native tunnel transport counters for the current attempt; not device-wide totals or provider billing."
	default:
		return "Connection traffic counters for the current attempt."
	}
}

func formatErrorDiagnostic(info *control.ErrorInfo) string {
	if info == nil {
		return ""
	}
	stage := map[string]string{"configuration": "configuration", "bootstrap": "bootstrap", "engine": "engine", "probe": "probe"}[info.Stage]
	code := map[string]string{"dns": "DNS", "tls": "TLS", "auth": "authentication", "timeout": "timeout", "network": "network", "unsupported": "unsupported", "unknown": "unknown"}[info.Code]
	if stage == "" || code == "" {
		return ""
	}
	text := "Stage: " + stage + " · Category: " + code
	if info.Retryable {
		text += " · Retryable"
	}
	return text
}
func (a *Application) desktopProjectionCommand(r Request) (any, error) {
	switch r.Command {
	case "desktop.context":
		if r.Context == nil {
			return nil, errors.New("missing desktop context")
		}
		a.desktopContext = *r.Context
	case "desktop.observe":
		if r.Observation == nil {
			return nil, errors.New("missing service observation")
		}
		a.consumeDesktop(*r.Observation)
	case "desktop.unavailable":
		a.consumeDesktop(platform.ServiceObservation{Available: false, CheckedAt: platform.ObservationClock()})
	}
	value, err := a.Handle(context.Background(), Request{Version: 1, Command: "hello"})
	if err != nil {
		return nil, err
	}
	return a.projectDesktop(a.desktopState, value.(Environment)), nil
}
