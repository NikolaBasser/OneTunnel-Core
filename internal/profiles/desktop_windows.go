package profiles

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"onetunnel/core/internal/control"
	"onetunnel/core/internal/platform"
	"onetunnel/core/internal/protocol"
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
	response, epoch, err := call(ctx, control.Request{Version: control.Version, Command: command, Profile: p, FullDevice: full})
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
		if before.Response.State.Active {
			return a.desktopCall(ctx, "stop", nil, false), nil
		}
		r.Command = "connection.start"
		return a.desktop(ctx, r)
	case "status", "stop", "probe":
		return a.desktopCall(ctx, command, nil, false), nil
	case "recover":
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
		reply := a.desktopCall(ctx, "start", prepared.Selected, r.FullDevice)
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
	view.Profiles = make([]Profile, len(document.Profiles))
	copy(view.Profiles, document.Profiles)
	for i := range view.Profiles {
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
	result.Description = "Распознано: " + []string{"AmneziaWG", "WireGuard", "VLESS", "SOCKS5", "Hysteria2", "Shadowsocks"}[p.Protocol]
	return result
}

func existsProfileFile(root, name string) bool {
	_, err := os.Stat(filepath.Join(root, name))
	return err == nil || !os.IsNotExist(err)
}
func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

type TransportInput struct {
	Fragment                         bool
	FragmentLength, FragmentInterval string
	Noise                            bool
	NoiseLength, NoiseDelay          string
	Mux                              bool
	MuxConcurrency                   string
}

func (input TransportInput) Parse() (protocol.TransportOptions, error) {
	concurrency, err := strconv.Atoi(strings.TrimSpace(input.MuxConcurrency))
	if err != nil || concurrency < 1 || concurrency > 128 {
		return protocol.TransportOptions{}, errors.New("Укажи число потоков MUX от 1 до 128.")
	}
	return protocol.TransportOptions{Fragment: input.Fragment, FragmentLength: strings.TrimSpace(input.FragmentLength), FragmentInterval: strings.TrimSpace(input.FragmentInterval), Noise: input.Noise, NoiseLength: strings.TrimSpace(input.NoiseLength), NoiseDelay: strings.TrimSpace(input.NoiseDelay), Mux: input.Mux, MuxConcurrency: concurrency}, nil
}
