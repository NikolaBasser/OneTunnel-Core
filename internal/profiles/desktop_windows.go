package profiles

import (
	"context"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type DesktopReply struct {
	Environment *Environment `json:",omitempty"`
	Available   bool
	Response    control.Response
	PeerStarted int64
	CheckedAt   uint64
	Message     string
	Prepared    *Applied `json:",omitempty"`
	Actions     DesktopActions
	Display     DesktopDisplay
}
type ServiceCaller func(context.Context, control.Request) (control.Response, int64, error)

func (a *Application) desktopCall(ctx context.Context, command string, p *Profile, full bool) (reply DesktopReply) {
	defer func() {
		value, err := a.Handle(ctx, Request{Version: 1, Command: "hello"})
		if err == nil {
			if env, ok := value.(Environment); ok {
				reply.Environment = &env
				reply = a.projectDesktop(reply, env)
			}
		}
	}()
	call := a.ServiceCall
	if call == nil {
		call = platform.CallService
	}
	request := control.Request{Version: control.Version, Command: command, Profile: p, FullDevice: full}
	var transportSkipped []string
	var transportDocument Document
	if command == "start" && p != nil {
		var err error
		transportDocument, err = a.Store.Load()
		if err != nil {
			reply = a.desktopState
			code := "profile_store_unavailable"
			reply.Response.Error = &code
			reply.Message = "Не удалось прочитать общие настройки подключения."
			return reply
		}
		effective, skipped, err := globalTransportProfile(*p, preferencesValue(transportDocument.UserSettings))
		if err != nil {
			reply = a.desktopState
			code := "invalid_profile"
			reply.Response.Error = &code
			reply.Message = "Проверьте общие настройки фрагментации, шумов и MUX."
			return reply
		}
		p = &effective
		request.Profile = p
		transportSkipped = skipped
		pool, err := preferencesValue(transportDocument.UserSettings).Balance.snapshot(transportDocument)
		if err != nil {
			reply = a.desktopState
			code := "invalid_configuration"
			reply.Response.Error = &code
			reply.Message = err.Error()
			return reply
		}
		if pool != nil {
			request.Balance = pool
			effective.Reliability = &control.ReliabilityOptions{AutoReconnect: true}
			p = &effective
			request.Profile = p
		}
	}
	if request.Balance == nil && command == "start" && p != nil && p.Reliability != nil && p.Reliability.AutoReconnect && p.Reliability.UseFallbacks {
		for _, stored := range transportDocument.Profiles {
			candidate, _, err := globalTransportProfile(stored, preferencesValue(transportDocument.UserSettings))
			if err != nil {
				continue
			}
			if candidate.ID != p.ID && candidate.Group == p.Group && control.CompatibleFallback(*p, candidate, full) && len(request.Fallbacks) < 8 {
				request.Fallbacks = append(request.Fallbacks, candidate)
			}
		}
	}
	response, epoch, err := call(ctx, request)
	if err != nil {
		a.consumeDesktop(platform.ServiceObservation{Available: false, CheckedAt: platform.ObservationClock()})
		code := "service_unavailable"
		reply = a.desktopState
		reply.Response.Error = &code
		reply.Message = platform.ServiceErrorMessage(code)
		return reply
	}
	if command == "stop" || command == "recover" {
		a.desktopState.Prepared = nil
	}
	a.consumeDesktop(platform.ServiceObservation{Available: true, Response: response, PeerStarted: epoch, CheckedAt: platform.ObservationClock()})
	reply = a.desktopState
	reply.Response.Error = response.Error
	reply.Response.Result = response.Result
	reply.Response.ErrorInfo = response.ErrorInfo
	if response.Error != nil {
		reply.Message = platform.ServiceErrorMessage(*response.Error)
	} else {
		switch command {
		case "start":
			reply.Message = "Соединение запущено. Проверка доступа доступна отдельно."
			if reply.Response.State.ClockSynchronized {
				reply.Message = "Время скорректировано внутри движка; часы Windows не изменены."
			}
		case "stop":
			reply.Message = "Подключение остановлено."
		case "recover":
			reply.Message = "Подключение очищено, блокировка kill switch снята. Обычная сеть восстановлена."
		}
	}
	if command == "start" && response.Error == nil && len(transportSkipped) > 0 {
		reply.Message += " Не применены к этому транспорту: " + strings.Join(transportSkipped, ", ") + "."
	}
	return reply
}
func (a *Application) desktop(ctx context.Context, r Request) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	command := strings.TrimPrefix(r.Command, "connection.")
	switch command {
	case "toggle":
		before := a.desktopCall(ctx, "status", nil, false)
		if !before.Available || before.Response.Error != nil {
			return before, nil
		}
		if before.Response.State.Active || before.Response.State.Reconnecting {
			if err := a.inhibitUserAutoConnect(); err != nil {
				a.automation().notice = "Automatic connection was inhibited, but current-user state could not be fully restored. Review user settings after disconnect."
			}
			return a.desktopCall(ctx, "stop", nil, false), nil
		}
		r.Command = "connection.start"
		return a.desktop(ctx, r)
	case "status", "stop", "probe":
		if command == "stop" {
			if err := a.inhibitUserAutoConnect(); err != nil {
				a.automation().notice = "Automatic connection was inhibited, but current-user state could not be fully restored. Review user settings after disconnect."
			}
		}
		return a.desktopCall(ctx, command, nil, false), nil
	case "recover":
		if err := a.inhibitUserAutoConnect(); err != nil {
			a.automation().notice = "Automatic connection was inhibited, but current-user state could not be fully restored. Review user settings after recovery."
		}
		for _, name := range []string{"session.json", "kill-switch.json"} {
			if existsProfileFile(a.Store.Root, name) {
				var err error
				if isAdmin() {
					err = platform.LegacyUserRecovery(ctx, a.Store.Root, a.Directory)
				} else {
					err = platform.ElevateLegacyRecovery(a.Directory)
				}
				if err != nil {
					return nil, err
				}
				reply := a.desktopCall(ctx, "status", nil, false)
				if !reply.Available {
					reply.Response.Error = nil
					reply.Message = "Прежнее подключение очищено. Служба пока недоступна."
				}
				return reply, nil
			}
		}
		return a.desktopCall(ctx, "recover", nil, false), nil
	case "start":
		a.desktopState.Prepared = nil
		before := a.desktopCall(ctx, "status", nil, false)
		if !before.Available || before.Response.Error != nil {
			return before, nil
		}
		if before.Response.State.Active || before.Response.State.NeedsRecovery || before.Response.State.TrafficLocked {
			code := "recovery_required"
			before.Response.Error = &code
			before.Message = platform.ServiceErrorMessage(code)
			return before, nil
		}
		if r.autoConnectPreferences != nil {
			if err := a.recheckAutoConnectNetwork(*r.autoConnectPreferences); err != nil {
				return nil, err
			}
		}
		prepared, err := a.Prepare(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		if prepared.Retired || prepared.Selected == nil {
			code := "profile_retired"
			before.Response.Error = &code
			before.Message = "Сервер удалён из подписки. Выбери актуальный узел."
			view := presentationApplied(prepared)
			before.Prepared = &view
			a.desktopState.Prepared = &view
			return before, nil
		}
		var reply DesktopReply
		if r.autoConnectPreferences != nil {
			token := fmtHex(a.Store.revision[:])
			u := a.automation()
			if err := u.Transaction(func() error {
				current, err := a.validateUserSettingsToken(token)
				if err != nil || preferencesValue(current.UserSettings) != *r.autoConnectPreferences ||
					!preferencesValue(current.UserSettings).AutoConnect || u.inhibited || u.inhibitionErr != nil {
					return errUserSettings
				}
				if err := a.recheckAutoConnectNetwork(*r.autoConnectPreferences); err != nil {
					return err
				}
				reply = a.desktopCall(ctx, "start", prepared.Selected, r.FullDevice)
				return nil
			}); err != nil {
				return nil, err
			}
		} else {
			reply = a.desktopCall(ctx, "start", prepared.Selected, r.FullDevice)
		}
		view := presentationApplied(prepared)
		reply.Prepared = &view
		a.desktopState.Prepared = &view
		return reply, nil
	default:
		return nil, errors.New("Неизвестная команда подключения.")
	}
}

// List/operation responses expose metadata only. Credentials are loaded by Go
// for connection, and sent to WPF only on an explicit editor.load request.
func presentationDocument(document Document) Document {
	view := document
	view.RoutingProfiles = nil
	view.ImportedRouting = nil
	if document.UserSettings != nil {
		preferences := *document.UserSettings
		view.UserSettings = &preferences
	}
	view.Profiles = make([]Profile, len(document.Profiles))
	copy(view.Profiles, document.Profiles)
	view.FavoriteIDs = normalizeFavoriteIDs(document.FavoriteIDs, document.Profiles)
	for i := range view.Profiles {
		view.Profiles[i].Network = protocol.CloneNetworkOptions(document.Profiles[i].Network)
		if view.Profiles[i].Network != nil {
			for j := range view.Profiles[i].Network.Targets {
				view.Profiles[i].Network.Targets[j].Source = ""
			}
		}
		view.Profiles[i].Source = ""
	}
	view.SubscriptionSources = map[string]string{}
	return view
}
func presentationApplied(applied Applied) Applied {
	view := applied
	view.Document = presentationDocument(applied.Document)
	if view.Selected != nil {
		p := *view.Selected
		p.Network = protocol.CloneNetworkOptions(view.Selected.Network)
		if p.Network != nil {
			for i := range p.Network.Targets {
				p.Network.Targets[i].Source = ""
			}
		}
		p.Source = ""
		view.Selected = &p
	}
	return view
}
func presentationValue(value any) any {
	switch v := value.(type) {
	case Document:
		return presentationDocument(v)
	case Applied:
		return presentationApplied(v)
	default:
		return value
	}
}

type ProfileView struct {
	ModeLabel      string
	ConnectionInfo string
	ConnectionHint string
	ConfigHelp     string
	FullHelp       string
}

func profileView(kind int) ProfileView {
	if kind == 0 || kind == 1 {
		return ProfileView{"По конфигурации · маршруты из AllowedIPs", "Маршрутизация из конфигурации", "Полные маршруты создаются временно; сохранённый профиль не меняется.", "Используются AllowedIPs из профиля. Частичные маршруты не защищают весь трафик устройства.", "Полные маршруты применяются временно. Kill switch сохраняет блокировку при обрыве. Отключение возвращает обычную сеть."}
	}
	if kind == protocol.HTTP || kind == protocol.Naive {
		return ProfileView{"Локальный прокси · TCP", "Режим подключения", "HTTP CONNECT и NaiveProxy передают TCP. UDP не отправляется напрямую; DNS в режиме всего устройства идёт через защищённый HTTPS-транспорт.", "HTTP(S): http://user:password@host:port или https://user:password@host:port. NaiveProxy: naive+https://user:password@host:port. Прокси без авторизации: явно укажи порт. Для подписки используй полный URL ресурса.", "TCP направляется через туннель; UDP блокируется. Kill switch сохраняет защиту при обрыве. Явное отключение возвращает обычную сеть."}
	}
	return ProfileView{"Локальный прокси · только выбранные приложения", "Режим подключения", "Локальный прокси не меняет настройки Windows. В режиме всего устройства kill switch сохраняет защиту при обрыве и аварии службы.", "Локальный адрес прокси используется браузером или другим выбранным приложением.", "Трафик направляется через туннель. Kill switch сохраняет блокировку при обрыве; явное отключение возвращает обычную сеть."}
}
func defaults() protocol.TransportOptions {
	return protocol.TransportOptions{FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", MuxConcurrency: 8}
}

type ImportPreview struct {
	Source, Name string
	Protocol     *int
	Subscription bool
	Description  string
}

func importPreview(source, name string) ImportPreview {
	result := ImportPreview{Source: source, Name: name, Description: "Подписка или конфигурация · проверка при импорте"}
	if len(source) > MaxBytes {
		result.Description = "Конфигурация превышает допустимый размер"
		return result
	}
	if IsURL(source) {
		result.Subscription = true
		result.Description = "HTTPS-подписка · отдельная группа"
		return result
	}
	p, err := Parse(name, source, nil)
	if err != nil {
		return result
	}
	result.Protocol = &p.Protocol
	result.Name = p.Name
	result.Source = p.Source
	result.Description = "Распознано: " + protocol.Names[p.Protocol]
	return result
}

func existsProfileFile(root, name string) bool {
	_, err := os.Stat(filepath.Join(root, name))
	return err == nil || !os.IsNotExist(err)
}
func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

type TransportInput struct {
	Fragment                                                                     bool
	FragmentLength, FragmentInterval                                             string
	Noise                                                                        bool
	NoiseLength, NoiseDelay                                                      string
	Mux                                                                          bool
	MuxConcurrency                                                               string
	MuxProtocol, MuxMaxConnections, MuxMinStreams, XUDPConcurrency, UDP443Policy string
	MuxPadding                                                                   bool
}

func (input TransportInput) Parse() (protocol.TransportOptions, error) {
	concurrency, err := strconv.Atoi(strings.TrimSpace(input.MuxConcurrency))
	if err != nil || concurrency < 1 || concurrency > 128 {
		return protocol.TransportOptions{}, errors.New("Укажи число потоков MUX от 1 до 128.")
	}
	parse := func(raw string) (int, error) {
		if strings.TrimSpace(raw) == "" {
			return 0, nil
		}
		return strconv.Atoi(strings.TrimSpace(raw))
	}
	max, err := parse(input.MuxMaxConnections)
	if err != nil {
		return protocol.TransportOptions{}, protocol.ErrConfiguration
	}
	min, err := parse(input.MuxMinStreams)
	if err != nil {
		return protocol.TransportOptions{}, protocol.ErrConfiguration
	}
	xudp, err := parse(input.XUDPConcurrency)
	if err != nil {
		return protocol.TransportOptions{}, protocol.ErrConfiguration
	}
	return protocol.TransportOptions{Fragment: input.Fragment, FragmentLength: strings.TrimSpace(input.FragmentLength), FragmentInterval: strings.TrimSpace(input.FragmentInterval), Noise: input.Noise, NoiseLength: strings.TrimSpace(input.NoiseLength), NoiseDelay: strings.TrimSpace(input.NoiseDelay), Mux: input.Mux, MuxConcurrency: concurrency, MuxProtocol: strings.ToLower(strings.TrimSpace(input.MuxProtocol)), MuxMaxConnections: max, MuxMinStreams: min, MuxPadding: input.MuxPadding, XUDPConcurrency: xudp, UDP443Policy: strings.ToLower(strings.TrimSpace(input.UDP443Policy))}, nil
}
