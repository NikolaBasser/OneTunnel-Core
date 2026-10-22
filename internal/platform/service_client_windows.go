package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"onetunnel/core/internal/control"
)

// UI clients use only the user Go host. It authenticates the service before
// sending any profile, including when an attacker creates a matching pipe name.
func serviceHandle(access uint32) (windows.Handle, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(manager)
	return windows.OpenService(manager, windows.StringToUTF16Ptr(control.ServiceName), access)
}
func serviceProcess() (uint32, error) {
	handle, err := serviceHandle(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(handle)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err = windows.QueryServiceStatusEx(handle, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed); err != nil {
		return 0, err
	}
	if status.CurrentState != windows.SERVICE_RUNNING || status.ProcessId == 0 {
		return 0, errors.New("service not running")
	}
	return status.ProcessId, nil
}
func trustedServicePipe(ctx context.Context) (net.Conn, int64, error) {
	pipe, err := winio.DialPipeAccess(ctx, control.PipeName, 0x12019b)
	if err != nil {
		return nil, 0, fmt.Errorf("dial service pipe: %w", err)
	}
	success := false
	defer func() {
		if !success {
			pipe.Close()
		}
	}()
	expected, err := serviceProcess()
	if err != nil {
		return nil, 0, fmt.Errorf("query service identity: %w", err)
	}
	file, ok := pipe.(interface{ Fd() uintptr })
	if !ok {
		return nil, 0, errors.New("pipe identity unavailable")
	}
	var actual uint32
	if windows.GetNamedPipeServerProcessId(windows.Handle(file.Fd()), &actual) != nil || actual != expected {
		return nil, 0, errors.New("untrusted service pipe")
	}
	// SCM and the pipe server PID authenticate LocalSystem without requesting
	// rights to its process object. Older installations deny those rights.
	var born windows.Filetime
	if process, openErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, actual); openErr == nil {
		var exited, kernel, user windows.Filetime
		_ = windows.GetProcessTimes(process, &born, &exited, &kernel, &user)
		windows.CloseHandle(process)
	}
	// Recheck SCM after opening the process, so PID reuse/restart cannot bind us
	// to an unrelated process between the two identity checks.
	current, err := serviceProcess()
	if err != nil || current != actual {
		return nil, 0, errors.New("service changed during authentication")
	}
	success = true
	return pipe, int64(uint64(born.HighDateTime)<<32 | uint64(born.LowDateTime)), nil
}

func callServiceFrame(ctx context.Context, request control.Request) (control.Response, int64, error) {
	connect, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	pipe, epoch, err := trustedServicePipe(connect)
	if err != nil {
		return control.Response{}, 0, err
	}
	defer pipe.Close()
	if deadline, ok := ctx.Deadline(); ok {
		pipe.SetDeadline(deadline)
	} else {
		pipe.SetDeadline(time.Now().Add(185 * time.Second))
	}
	if err = control.WriteFrame(pipe, request); err != nil {
		return control.Response{}, epoch, err
	}
	reply, err := control.ReadFrame[control.Response](pipe)
	if err != nil {
		return control.Response{}, epoch, err
	}
	if reply.Version != control.Version {
		return control.Response{}, epoch, errors.New("incompatible service")
	}
	return reply, epoch, nil
}

func StartPublicService(ctx context.Context) error {
	handle, err := serviceHandle(windows.SERVICE_START | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return errors.New("Сначала установи службу OneTunnel.")
	}
	defer windows.CloseServiceHandle(handle)
	if err = windows.StartService(handle, 0, nil); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return errors.New("Не удалось запустить службу OneTunnel.")
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err = serviceProcess(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("Служба не запустилась вовремя.")
		case <-ticker.C:
		}
	}
}

func ServiceErrorMessage(code string) string {
	switch code {
	case "incompatible_version":
		return "Версия службы несовместима с ядром приложения. Обнови службу."
	case "transport_upgrade_required":
		return "Профиль сохранён, но параметры KCP требуют адаптации: congestion, readBufferSize и writeBufferSize удалены upstream; допустимый TTI — 10–1000 мс. Сетевые изменения не применялись."
	case "invalid_configuration":
		return "Служба отклонила конфигурацию. Проверь профиль."
	case "operation_timeout":
		return "Операция не завершилась вовремя. Проверь состояние службы."
	case "network_timeout":
		return "Сервер не ответил вовремя. Проверь доступность подключения."
	case "network_error":
		return "Проверочный запрос не прошёл. Проверь доступность сервера и DNS."
	case "backend_unavailable":
		return "Сетевое ядро остановилось. Требуется восстановление; защита не снимается автоматически."
	case "recovery_required":
		return "Сначала отключи подключение или выполни восстановление."
	case "service_unavailable":
		return "Нет связи со службой OneTunnel. Последнее состояние сохранено; блокировка может оставаться активной."
	default:
		return "Операция не выполнена. Проверь состояние подключения и необходимость восстановления."
	}
}
