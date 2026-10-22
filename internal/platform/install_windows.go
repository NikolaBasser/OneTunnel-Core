package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"onetunnel/core/internal/control"
)

var interactiveSID = regexp.MustCompile(`^S-1-5-21-\d+-\d+-\d+-\d+$`)

func checkedTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		attributes, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
		if e != nil {
			return e
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("reparse installation path forbidden")
		}
		return nil
	})
}
func sealInstallDirectory(path, owner string, read bool) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("unsafe installation directory")
	}
	descriptor := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if read {
		descriptor += "(A;OICI;GRGX;;;" + owner + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func copyInstallTree(source, destination string) error {
	if err := checkedTree(source); err != nil {
		return err
	}
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return errors.New("unsafe package path")
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		// Never follow an existing reparse target while replacing package files.
		if attributes, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(target)); e == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("unsafe installed file")
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		if attributes, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(target)); e == nil && attributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
			if e = windows.SetFileAttributes(windows.StringToUTF16Ptr(target), attributes&^windows.FILE_ATTRIBUTE_READONLY); e != nil {
				return e
			}
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(output, input)
		if err == nil {
			err = output.Sync()
		}
		closeErr := output.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
}
func waitServiceState(ctx context.Context, service *mgr.Service, want svc.State) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := service.Query()
		if err != nil {
			return err
		}
		if state.State == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func installIdle(root string) bool {
	return !exists(filepath.Join(root, "session.json")) && !exists(filepath.Join(root, "kill-switch.json"))
}

// The elevated bootstrap is intentionally independent of the public service.
// It can install a missing service and replace an idle one without network RPC.
func InstallPublicService(ctx context.Context, directory, owner string) (result error) {
	if !windows.GetCurrentProcessToken().IsElevated() || !interactiveSID.MatchString(owner) {
		return errors.New("administrative installation and interactive owner required")
	}
	mutex, mutexErr := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(`Global\OneTunnel.Service.Install.v1`))
	if mutexErr != nil && !errors.Is(mutexErr, windows.ERROR_ALREADY_EXISTS) {
		return mutexErr
	}
	defer windows.CloseHandle(mutex)
	wait, err := windows.WaitForSingleObject(mutex, 5000)
	if err != nil || (wait != windows.WAIT_OBJECT_0 && wait != windows.WAIT_ABANDONED) {
		return errors.New("another installation is running")
	}
	defer windows.ReleaseMutex(mutex)
	if _, err := windows.StringToSid(owner); err != nil {
		return err
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return err
	}
	source := filepath.Join(directory, "service")
	if err = checkedTree(source); err != nil {
		return err
	}
	metadata, err := os.ReadFile(filepath.Join(source, "go-runtime.json"))
	if err != nil {
		return err
	}
	var info struct {
		Runtime                                                 string
		ApiVersion                                              int
		EmbeddedAWG, EmbeddedXray, EmbeddedSingBox, EmbeddedTun bool
	}
	if json.Unmarshal(bytes.TrimPrefix(metadata, []byte{0xef, 0xbb, 0xbf}), &info) != nil || info.Runtime != "go" || info.ApiVersion != control.Version || !info.EmbeddedAWG || !info.EmbeddedXray || !info.EmbeddedSingBox || !info.EmbeddedTun {
		return errors.New("complete embedded service package required")
	}
	executable := filepath.Join(source, "OneTunnel.Service.exe")
	if st, e := os.Stat(executable); e != nil || !st.Mode().IsRegular() {
		return errors.New("service executable missing")
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return err
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return err
	}
	base := filepath.Join(programFiles, "OneTunnel")
	destination := filepath.Join(base, "Core")
	root := filepath.Join(programData, "OneTunnel", "Service", owner)
	if !installIdle(root) {
		return errors.New("Отключи подключение или выполни восстановление перед обновлением службы.")
	}
	previousOwner, err := os.ReadFile(filepath.Join(destination, "service-owner.json"))
	if err == nil {
		var old struct{ OwnerSid string }
		if json.Unmarshal(bytes.TrimPrefix(previousOwner, []byte{0xef, 0xbb, 0xbf}), &old) != nil || old.OwnerSid != owner {
			return errors.New("installed service owner differs")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, path := range []string{base, destination, filepath.Join(programData, "OneTunnel"), filepath.Join(programData, "OneTunnel", "Service"), root} {
		if err = sealInstallDirectory(path, owner, strings.HasPrefix(strings.ToLower(path), strings.ToLower(programFiles)+`\`)); err != nil {
			return err
		}
	}
	for _, path := range []string{destination, root} {
		if err = checkedTree(path); err != nil {
			return err
		}
	}
	// Explicit child ACLs cannot override the sealed private runtime ancestry.
	if err = filepath.WalkDir(root, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
		if e != nil {
			return e
		}
		acl, _, e := sd.DACL()
		if e != nil {
			return e
		}
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	}); err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(control.ServiceName)
	existing := err == nil
	var original mgr.Config
	if existing {
		defer service.Close()
		original, err = service.Config()
		if err != nil {
			return err
		}
		expected := `"` + filepath.Join(destination, "OneTunnel.Service.exe") + `"`
		if !strings.EqualFold(strings.TrimSpace(original.BinaryPathName), expected) && !strings.EqualFold(strings.TrimSpace(original.BinaryPathName), filepath.Join(destination, "OneTunnel.Service.exe")) {
			return errors.New("unexpected registered service path")
		}
		state, e := service.Query()
		if e != nil {
			return e
		}
		if state.State != svc.Stopped {
			if _, e = service.Control(svc.Stop); e != nil {
				return e
			}
			if e = waitServiceState(ctx, service, svc.Stopped); e != nil {
				return e
			}
		}
		if !installIdle(root) {
			_ = service.Start()
			return errors.New("service became active during installation; recovery required")
		}
	} else if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return err
	}
	backup := ""
	if existing {
		backup = filepath.Join(base, "Rollback", time.Now().UTC().Format("20060102-150405.000000000"))
		if err = sealInstallDirectory(filepath.Dir(backup), owner, false); err != nil {
			_ = service.Start()
			return err
		}
		if err = sealInstallDirectory(backup, owner, false); err != nil {
			_ = service.Start()
			return err
		}
		if err = copyInstallTree(destination, backup); err != nil {
			_ = service.Start()
			return err
		}
	}
	defer func() {
		if result == nil {
			return
		}
		if existing && backup != "" {
			_, _ = service.Control(svc.Stop)
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if waitServiceState(rollbackCtx, service, svc.Stopped) == nil && copyInstallTree(backup, destination) == nil {
				_ = service.UpdateConfig(original)
				_ = service.Start()
			}
		} else if !existing && service != nil {
			_, _ = service.Control(svc.Stop)
			_ = service.Delete()
		}
	}()
	if err = copyInstallTree(source, destination); err != nil {
		return err
	}
	if err = atomicJSON(filepath.Join(destination, "service-owner.json"), map[string]string{"OwnerSid": owner}); err != nil {
		return err
	}
	entries, err := os.ReadDir(destination)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext == ".dll" || ext == ".pdb" || strings.HasPrefix(name, "OneTunnel.Adapter") || strings.HasSuffix(name, ".deps.json") || strings.HasSuffix(name, ".runtimeconfig.json") {
			if err = os.Remove(filepath.Join(destination, name)); err != nil {
				return err
			}
		}
	}
	for _, name := range []string{"wireguard.exe", "wg.exe", "amneziawg.exe", "awg.exe", "xray.exe", "sing-box.exe", "wintun.dll"} {
		if e := os.Remove(filepath.Join(destination, "engines", name)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	config := mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal, BinaryPathName: `"` + filepath.Join(destination, "OneTunnel.Service.exe") + `"`, ServiceStartName: "LocalSystem", DisplayName: "OneTunnel Core", Description: "OneTunnel connections, DNS, routes and persistent traffic protection"}
	if existing {
		err = service.UpdateConfig(config)
	} else {
		service, err = manager.CreateService(control.ServiceName, filepath.Join(destination, "OneTunnel.Service.exe"), config)
		if err == nil {
			defer service.Close()
		}
	}
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCRPLO;;;" + owner + ")")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err = windows.SetSecurityInfo(service.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return err
	}
	if err = service.Start(); err != nil {
		return err
	}
	if err = waitServiceState(ctx, service, svc.Running); err != nil {
		return err
	}
	return nil
}

type shellExecuteInfo struct {
	Size, Mask                        uint32
	Window                            uintptr
	Verb, File, Parameters, Directory *uint16
	Show                              int32
	Instance                          uintptr
	IDList                            uintptr
	Class                             *uint16
	ClassKey                          uintptr
	HotKey                            uint32
	Icon                              uintptr
	Process                           windows.Handle
}

func ElevateInstall(directory string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	owner := user.User.Sid.String()
	if windows.GetCurrentProcessToken().IsElevated() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return InstallPublicService(ctx, directory, owner)
	}
	return elevatedHostCommand(executable, directory, "--install-service "+owner)
}

func elevatedHostCommand(executable, directory, arguments string) error {
	info := shellExecuteInfo{Mask: 0x40 | 0x100, Verb: windows.StringToUTF16Ptr("runas"), File: windows.StringToUTF16Ptr(executable), Parameters: windows.StringToUTF16Ptr(arguments), Directory: windows.StringToUTF16Ptr(directory)}
	info.Size = uint32(unsafe.Sizeof(info))
	result, _, callErr := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	if result == 0 {
		if errors.Is(callErr, syscall.Errno(1223)) {
			return errors.New("Установка отменена в окне UAC.")
		}
		return errors.New("Не удалось запустить установку службы.")
	}
	if info.Process == 0 {
		return errors.New("installation process unavailable")
	}
	defer windows.CloseHandle(info.Process)
	state, err := windows.WaitForSingleObject(info.Process, 150000)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		return errors.New("Установка ещё может выполняться. Проверь состояние службы перед повтором.")
	}
	var code uint32
	if windows.GetExitCodeProcess(info.Process, &code) != nil || code != 0 {
		return errors.New("Служба не установлена. Подключение должно быть отключено; прежняя установка сохранена для отката.")
	}
	return nil
}

func ElevateLegacyRecovery(directory string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return elevatedHostCommand(executable, directory, "--recover-legacy "+user.User.Sid.String())
}
