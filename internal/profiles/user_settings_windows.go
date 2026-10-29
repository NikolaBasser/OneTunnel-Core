package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"golang.org/x/sys/windows"
)

// UserPreferences contains portable preferences, never machine startup ownership.
type UserPreferences struct {
	UseSystemProxy bool
	AutoConnect    bool
	ProfileID      string
	FullDevice     bool
	AllowTrusted   bool
	AllowPublic    bool
	Transport      TransportInput `json:",omitzero"`
	Balance        BalanceInput   `json:",omitzero"`
}

type UserSettingsView struct {
	Preferences                                                          UserPreferences
	Token, NetworkCategory, Message                                      string
	CanSave, ProxyEnabled, AutoConnectInhibited, StartupRecorded         bool
	CanEnableProxy, CanDisableProxy, CanEnableStartup, CanDisableStartup bool
	StartupEnabled                                                       bool
}
type UserSettingsTick struct {
	View       UserSettingsView
	Connection *DesktopReply `json:",omitempty"`
}
type userProxyLease interface {
	Owns(string) (bool, error)
	Enable(string) (string, error)
	Disable(string) (bool, error)
	Reconcile() (bool, error)
}
type userStartup interface {
	ProposedCommand(string) (string, error)
	Status(string) (bool, error)
	Enable(string, string) (string, error)
	Disable(string) (bool, error)
}

// UserAutomation is owned exclusively by the serialized profile-host command loop.
type UserAutomation struct {
	NetworkCategory            func() platform.UserNetworkCategory
	ProxyFactory               func() (userProxyLease, error)
	Startup                    userStartup
	ReadStartupOwner           func() (string, error)
	WriteStartupOwner          func(string) error
	Transaction                func(func() error) error
	SessionIdentity            func() (string, error)
	ReadInhibitedSession       func() (string, error)
	WriteInhibitedSession      func(string) error
	proxy                      userProxyLease
	lease                      string
	proxyAddress               string
	initialized                bool
	initializationErr          error
	inhibitionErr              error
	notice                     string
	inhibited                  bool
	category                   platform.UserNetworkCategory
	categorySince, nextAttempt time.Time
	attempted                  bool
	attempts                   int
}

var errUserSettings = errors.New("user settings operation could not be confirmed")

func (a *Application) automation() *UserAutomation {
	if a.UserAutomation == nil {
		a.UserAutomation = &UserAutomation{}
	}
	u := a.UserAutomation
	if u.Transaction == nil {
		u.Transaction = platform.UserAutomationTransaction
	}
	if u.NetworkCategory == nil {
		u.NetworkCategory = platform.CurrentUserPhysicalNetworkCategory
	}
	if u.ProxyFactory == nil {
		u.ProxyFactory = func() (userProxyLease, error) { return platform.NewUserProxyAtRoot(a.Store.Root) }
	}
	if u.Startup == nil {
		u.Startup = platform.UserStartup{}
	}
	if u.ReadStartupOwner == nil {
		u.ReadStartupOwner = func() (string, error) { return readStartupOwner(a.Store.Root) }
	}
	if u.WriteStartupOwner == nil {
		u.WriteStartupOwner = func(value string) error { return writeStartupOwner(a.Store.Root, value) }
	}
	if u.SessionIdentity == nil {
		u.SessionIdentity = profileHostSessionIdentity
	}
	if u.ReadInhibitedSession == nil {
		u.ReadInhibitedSession = func() (string, error) {
			state, err := readUserMachineOwnership(a.Store.Root)
			return state.InhibitedSession, err
		}
	}
	if u.WriteInhibitedSession == nil {
		u.WriteInhibitedSession = func(session string) error {
			state, err := readUserMachineOwnership(a.Store.Root)
			if err != nil {
				return err
			}
			state.InhibitedSession = session
			return writeUserMachineOwnership(a.Store.Root, state)
		}
	}
	return u
}

func profileHostSessionIdentity() (string, error) {
	parent := os.Getppid()
	if parent <= 0 {
		return "", errUserSettings
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(parent))
	if err != nil {
		return "", errUserSettings
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return "", errUserSettings
	}
	var exitCode uint32
	if windows.GetExitCodeProcess(h, &exitCode) != nil || exitCode != 259 || os.Getppid() != parent {
		return "", errUserSettings
	}
	var ownCreated, ownExited, ownKernel, ownUser windows.Filetime
	if windows.GetProcessTimes(windows.CurrentProcess(), &ownCreated, &ownExited, &ownKernel, &ownUser) != nil ||
		uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) > uint64(ownCreated.HighDateTime)<<32|uint64(ownCreated.LowDateTime) {
		return "", errUserSettings
	}
	path := make([]uint16, 32768)
	length := uint32(len(path))
	self, err := os.Executable()
	if err != nil || windows.QueryFullProcessImageName(h, 0, &path[0], &length) != nil ||
		!strings.EqualFold(filepath.Clean(windows.UTF16ToString(path[:length])), filepath.Join(filepath.Dir(self), "OneTunnel.exe")) {
		return "", errUserSettings
	}
	return fmt.Sprintf("%d:%d:%d", parent, created.HighDateTime, created.LowDateTime), nil
}

func normalizedUserPreferences(input *UserPreferences, doc Document) (*UserPreferences, error) {
	if input == nil {
		return nil, nil
	}
	value := *input
	if _, err := value.Balance.snapshot(doc); err != nil {
		return nil, err
	}
	if value.Transport != (TransportInput{}) {
		options, err := value.Transport.Parse()
		if err != nil || protocol.ValidateTransportPreferences(&options) != nil {
			return nil, errors.New("Проверьте общие параметры фрагментации, шумов и MUX.")
		}
		if options.MuxMaxConnections == 0 && options.MuxMinStreams != 0 {
			return nil, errors.New("Минимум потоков MUX задаётся вместе с ограничением числа соединений.")
		}
	}
	value.ProfileID = strings.TrimSpace(value.ProfileID)
	if value.ProfileID != "" && !favoriteProfileIDPattern.MatchString(value.ProfileID) {
		return nil, errUserSettings
	}
	if value.AutoConnect {
		if !value.AllowTrusted && !value.AllowPublic {
			return nil, errUserSettings
		}
		found := false
		for _, p := range doc.Profiles {
			if p.ID == value.ProfileID {
				found = true
				if protocol.ValidateNetworkOptions(p.Network, p.Protocol, value.FullDevice) != nil {
					return nil, errUserSettings
				}
				break
			}
		}
		if !found {
			return nil, errUserSettings
		}
	}
	if value == (UserPreferences{}) {
		return nil, nil
	}
	return &value, nil
}

func preferencesValue(p *UserPreferences) UserPreferences {
	if p == nil {
		return UserPreferences{}
	}
	return *p
}

// Used by ordinary document writes after deletion, never to accept a new UI target.
func normalizeStoredUserPreferences(input *UserPreferences, doc Document) *UserPreferences {
	if input == nil {
		return nil
	}
	value := *input
	if _, err := normalizedUserPreferences(&value, doc); err != nil {
		value.AutoConnect = false
		value.Balance.Enabled = false
	}
	if value == (UserPreferences{}) {
		return nil
	}
	return &value
}

func disableRestoredUserAutomation(doc *Document) {
	if doc.UserSettings == nil {
		return
	}
	value := *doc.UserSettings
	value.AutoConnect = false
	value.UseSystemProxy = false
	doc.UserSettings = &value
}

func (a *Application) userSettingsView() (UserSettingsView, error) {
	if a == nil || a.Store == nil {
		return UserSettingsView{}, errUserSettings
	}
	doc, err := a.Store.Load()
	if err != nil {
		return UserSettingsView{}, errUserSettings
	}
	u := a.automation()
	category := platform.UserNetworkPublic
	if preferencesValue(doc.UserSettings).AutoConnect {
		category = u.NetworkCategory()
	}
	if category != platform.UserNetworkTrusted {
		category = platform.UserNetworkPublic
	}
	if err := a.refreshProxyOwnership(); err != nil {
		return UserSettingsView{}, err
	}
	owned, err := u.ReadStartupOwner()
	if err != nil {
		return UserSettingsView{}, errUserSettings
	}
	registered := false
	if owned != "" {
		registered, err = u.Startup.Status(owned)
		if err != nil {
			return UserSettingsView{}, errUserSettings
		}
	}
	prefs := preferencesValue(doc.UserSettings)
	s := a.desktopState.Response.State
	canProxy := prefs.UseSystemProxy && u.lease == "" && a.desktopState.Available && s.Active && !s.Reconnecting && !s.NeedsRecovery && !s.TrafficLocked && !s.FullDeviceMode && !s.WholeDevice && s.LocalPort > 0 && s.LocalPort <= 65535
	message := "Automatic actions are off by default. Unknown networks are public. Startup registration does not enable auto-connect."
	if u.initializationErr != nil {
		canProxy = false
		message = "Previous proxy ownership could not be reconciled. Explicitly restore it before enabling proxy changes."
	}
	if u.notice != "" {
		message += " " + u.notice
	}
	if u.inhibitionErr != nil {
		message += " Automatic connection is unavailable because its UI session could not be confirmed."
	}
	return UserSettingsView{Preferences: prefs, Token: fmtHex(a.Store.revision[:]), NetworkCategory: string(category), CanSave: a.refreshAllowed(), ProxyEnabled: u.lease != "", AutoConnectInhibited: u.inhibited, StartupRecorded: owned != "", StartupEnabled: registered, CanEnableProxy: canProxy, CanDisableProxy: u.lease != "" || u.initializationErr != nil, CanEnableStartup: owned == "", CanDisableStartup: owned != "", Message: message}, nil
}

func (a *Application) saveUserSettings(token string, input *UserPreferences) (Document, error) {
	if a == nil || a.Store == nil {
		return Document{}, errUserSettings
	}
	var result Document
	err := a.automation().Transaction(func() error {
		var err error
		result, err = a.saveUserSettingsLocked(token, input)
		return err
	})
	return result, err
}

func (a *Application) saveUserSettingsLocked(token string, input *UserPreferences) (Document, error) {
	if a == nil || a.Store == nil || input == nil || !a.refreshAllowed() {
		return Document{}, errUserSettings
	}
	doc, err := a.Store.Load()
	if err != nil || token == "" || token != fmtHex(a.Store.revision[:]) {
		return Document{}, errUserSettings
	}
	normalized, err := normalizedUserPreferences(input, doc)
	if err != nil {
		return Document{}, errUserSettings
	}
	old, next := preferencesValue(doc.UserSettings), preferencesValue(normalized)
	if old == next {
		return doc, nil
	}
	u := a.automation()
	if old.UseSystemProxy && !next.UseSystemProxy {
		if u.initializationErr != nil {
			return Document{}, errUserSettings
		}
		if err := a.releaseUserProxy(); err != nil {
			return Document{}, errUserSettings
		}
	}
	// Only a deliberate off->on change releases manual-disconnect inhibition.
	if !old.AutoConnect && next.AutoConnect {
		if session, err := u.SessionIdentity(); err != nil || session == "" {
			u.inhibited = true
			u.inhibitionErr = errUserSettings
			return Document{}, errUserSettings
		}
		if err := u.WriteInhibitedSession(""); err != nil {
			u.inhibited = true
			return Document{}, errUserSettings
		}
	}
	doc.UserSettings = normalized
	if err := a.Store.Save(doc); err != nil {
		return Document{}, errUserSettings
	}
	if !old.AutoConnect && next.AutoConnect {
		u.inhibitionErr = nil
		u.inhibited = false
		u.categorySince = time.Time{}
		u.nextAttempt = time.Time{}
		u.attempted = false
		u.attempts = 0
	}
	return doc, nil
}

func (a *Application) enableUserProxy(ctx context.Context, token string) (UserSettingsView, error) {
	if a == nil || a.Store == nil || a.desktopContext.Busy {
		return UserSettingsView{}, errUserSettings
	}
	doc, err := a.Store.Load()
	if err != nil || token == "" || token != fmtHex(a.Store.revision[:]) || !preferencesValue(doc.UserSettings).UseSystemProxy {
		return UserSettingsView{}, errUserSettings
	}
	state := a.desktopCall(ctx, "status", nil, false)
	s := state.Response.State
	if !state.Available || state.Response.Error != nil || !s.Active || s.Reconnecting || s.NeedsRecovery || s.TrafficLocked || s.FullDeviceMode || s.WholeDevice || s.LocalPort < 1 || s.LocalPort > 65535 {
		return UserSettingsView{}, errUserSettings
	}
	u := a.automation()
	if u.initializationErr != nil {
		return UserSettingsView{}, errUserSettings
	}
	err = u.Transaction(func() error {
		current, err := a.validateUserSettingsToken(token)
		if err != nil || !preferencesValue(current.UserSettings).UseSystemProxy {
			return errUserSettings
		}
		if !u.initialized {
			if err := a.initializeUserAutomation(); err != nil {
				return errUserSettings
			}
		}
		if u.lease != "" {
			return nil
		}
		if u.proxy == nil {
			u.proxy, err = u.ProxyFactory()
			if err != nil {
				return errUserSettings
			}
		}
		lease, err := u.proxy.Enable(net.JoinHostPort("127.0.0.1", strconv.Itoa(s.LocalPort)))
		if err != nil {
			return errUserSettings
		}
		u.lease = lease
		u.proxyAddress = net.JoinHostPort("127.0.0.1", strconv.Itoa(s.LocalPort))
		return nil
	})
	if err != nil {
		return UserSettingsView{}, errUserSettings
	}
	return a.userSettingsView()
}

func (a *Application) releaseUserProxy() error {
	if a == nil || a.UserAutomation == nil {
		return nil
	}
	u := a.UserAutomation
	if u.proxy == nil || u.lease == "" {
		return nil
	}
	conflict, err := u.proxy.Disable(u.lease)
	if err != nil {
		return errUserSettings
	}
	u.lease = ""
	u.proxyAddress = ""
	if conflict {
		u.notice = "External proxy changes were left unchanged; only OneTunnel-owned values were restored."
	}
	return nil
}

func (a *Application) disableUserProxy(token string) (UserSettingsView, error) {
	if _, err := a.validateUserSettingsToken(token); err != nil {
		return UserSettingsView{}, err
	}
	if err := a.releaseUserProxy(); err != nil {
		return UserSettingsView{}, err
	}
	u := a.automation()
	if u.initializationErr != nil {
		if u.proxy == nil {
			var err error
			u.proxy, err = u.ProxyFactory()
			if err != nil {
				return UserSettingsView{}, errUserSettings
			}
		}
		conflict, err := u.proxy.Reconcile()
		if err != nil {
			return UserSettingsView{}, errUserSettings
		}
		if conflict {
			u.notice = "External proxy changes were left unchanged; only OneTunnel-owned values were restored."
		}
		u.initializationErr = nil
		u.initialized = true
	}
	return a.userSettingsView()
}

func (a *Application) refreshProxyOwnership() error {
	u := a.UserAutomation
	if u == nil || u.proxy == nil || u.lease == "" {
		return nil
	}
	owned, err := u.proxy.Owns(u.lease)
	if err != nil {
		return errUserSettings
	}
	if !owned {
		u.lease = ""
		u.proxyAddress = ""
	}
	return nil
}

func (a *Application) validateUserSettingsToken(token string) (Document, error) {
	if a == nil || a.Store == nil {
		return Document{}, errUserSettings
	}
	doc, err := a.Store.Load()
	if err != nil || token == "" || token != fmtHex(a.Store.revision[:]) {
		return Document{}, errUserSettings
	}
	return doc, nil
}

// Called before an explicit stop/toggle-stop, never for internal retry cleanup.
func (a *Application) inhibitUserAutoConnect() error {
	u := a.automation()
	u.inhibited = true
	durableErr := u.Transaction(func() error {
		session, err := u.SessionIdentity()
		if err != nil || session == "" {
			u.inhibitionErr = errUserSettings
			return errUserSettings
		}
		if err := u.WriteInhibitedSession(session); err != nil {
			u.inhibitionErr = errUserSettings
			return errUserSettings
		}
		return nil
	})
	return errors.Join(durableErr, a.releaseUserProxy())
}

// Reconcile before accepting automation commands. It never enables settings.
func (a *Application) initializeUserAutomation() error {
	if a == nil || a.Store == nil {
		return errUserSettings
	}
	u := a.automation()
	if u.initialized {
		return nil
	}
	if err := u.Transaction(func() error {
		session, err := u.SessionIdentity()
		if err != nil || session == "" {
			return errUserSettings
		}
		inhibitedSession, err := u.ReadInhibitedSession()
		if err != nil {
			return errUserSettings
		}
		u.inhibited = inhibitedSession == session
		return nil
	}); err != nil {
		u.inhibited = true
		u.inhibitionErr = errUserSettings
	}
	proxy, err := u.ProxyFactory()
	if err != nil {
		u.initializationErr = errUserSettings
		return errUserSettings
	}
	u.proxy = proxy
	conflict, err := proxy.Reconcile()
	if err != nil {
		u.initializationErr = errUserSettings
		return errUserSettings
	}
	if conflict {
		u.notice = "External proxy changes were left unchanged; only OneTunnel-owned values were restored."
	}
	u.initialized = true
	u.initializationErr = nil
	return nil
}

func (a *Application) InitializeUserAutomation() error { return a.initializeUserAutomation() }

func (a *Application) tickUserSettings(ctx context.Context) (UserSettingsTick, error) {
	if a == nil || a.Store == nil {
		return UserSettingsTick{}, errUserSettings
	}
	doc, err := a.Store.Load()
	if err != nil {
		return UserSettingsTick{}, errUserSettings
	}
	u := a.automation()
	prefs := preferencesValue(doc.UserSettings)
	if err := a.refreshProxyOwnership(); err != nil {
		return UserSettingsTick{}, err
	}
	done := func(message string, reply *DesktopReply) (UserSettingsTick, error) {
		view, e := a.userSettingsView()
		if e != nil {
			return UserSettingsTick{}, e
		}
		view.Message = message
		if u.notice != "" {
			view.Message += " " + u.notice
		}
		return UserSettingsTick{View: view, Connection: reply}, nil
	}
	if u.initializationErr != nil {
		return done("Previous proxy ownership needs explicit restoration before automatic connection.", nil)
	}
	if u.lease != "" {
		status := a.desktopCall(ctx, "status", nil, false)
		s := status.Response.State
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(s.LocalPort))
		stableRetry := s.ProxyListenerStable && s.Reconnecting && address == u.proxyAddress
		if !status.Available || status.Response.Error != nil || ((!s.Active || s.Reconnecting || s.NeedsRecovery) && !stableRetry) || s.FullDeviceMode || s.WholeDevice || address != u.proxyAddress {
			if err := a.releaseUserProxy(); err != nil {
				return UserSettingsTick{}, errUserSettings
			}
		}
	}
	if !prefs.AutoConnect || u.inhibited || a.desktopContext.Busy || !a.desktopContext.StorageReady || a.backupPreview != nil || a.pendingPreview != nil {
		return done("Automatic connection is disabled, inhibited, or busy.", nil)
	}
	if _, err := normalizedUserPreferences(&prefs, doc); err != nil {
		return done("The selected automatic connection profile is unavailable.", nil)
	}
	category := u.NetworkCategory()
	if category != platform.UserNetworkTrusted {
		category = platform.UserNetworkPublic
	}
	now := a.now()
	if u.category != category || u.categorySince.IsZero() || now.Before(u.categorySince) {
		if u.category != category {
			u.attempts = 0
		}
		u.category = category
		u.categorySince = now
		return done("Waiting for a stable network category.", nil)
	}
	if now.Sub(u.categorySince) < 5*time.Second {
		return done("Waiting for a stable network category.", nil)
	}
	if category == platform.UserNetworkTrusted && !prefs.AllowTrusted || category == platform.UserNetworkPublic && !prefs.AllowPublic {
		return done("Automatic connection is not permitted on this network.", nil)
	}
	if u.attempted && now.Before(u.nextAttempt) {
		return done("Automatic connection is waiting before another attempt.", nil)
	}
	if u.attempts >= 3 {
		return done("Automatic connection attempts stopped. Re-enable the setting to retry.", nil)
	}
	// Authenticate state immediately before normal connection.start; never auto-recover.
	status := a.desktopCall(ctx, "status", nil, false)
	s := status.Response.State
	if status.Available && status.Response.Error == nil && s.Active && !s.Reconnecting && !s.NeedsRecovery && !s.TrafficLocked {
		return done("A connection is already active; automatic connection is not needed.", &status)
	}
	if !status.Available || status.Response.Error != nil || s.Active || s.Reconnecting || s.NeedsRecovery || s.TrafficLocked || !a.refreshAllowed() {
		return done("The service is not confirmed idle.", &status)
	}
	u.attempted = true
	u.attempts++
	u.nextAttempt = now.Add(30 * time.Second)
	value, err := a.desktop(ctx, Request{Version: 1, Command: "connection.start", ID: prefs.ProfileID, FullDevice: prefs.FullDevice, autoConnectPreferences: &prefs})
	if err != nil {
		return done("Automatic connection did not complete.", nil)
	}
	reply, ok := value.(DesktopReply)
	if !ok {
		return UserSettingsTick{}, errUserSettings
	}
	if reply.Available && reply.Response.Error == nil && reply.Response.State.Active {
		u.attempts = 0
	}
	return done("Automatic connection was requested through the normal Go controller.", &reply)
}

// Recheck after blocking preparation/status calls, before their next network effect.
func (a *Application) recheckAutoConnectNetwork(prefs UserPreferences) error {
	u := a.automation()
	category := u.NetworkCategory()
	if category != platform.UserNetworkTrusted {
		category = platform.UserNetworkPublic
	}
	now := a.now()
	if category != u.category || u.categorySince.IsZero() || now.Before(u.categorySince) {
		if category != u.category {
			u.attempts = 0
		}
		u.category = category
		u.categorySince = now
		return errUserSettings
	}
	if now.Sub(u.categorySince) < 5*time.Second ||
		category == platform.UserNetworkTrusted && !prefs.AllowTrusted ||
		category == platform.UserNetworkPublic && !prefs.AllowPublic {
		return errUserSettings
	}
	return nil
}

func (a *Application) enableUserStartup(executable, token string) (UserSettingsView, error) {
	if a == nil || a.Store == nil {
		return UserSettingsView{}, errUserSettings
	}
	if _, err := a.validateUserSettingsToken(token); err != nil {
		return UserSettingsView{}, err
	}
	u := a.automation()
	err := u.Transaction(func() error {
		if _, err := a.validateUserSettingsToken(token); err != nil {
			return err
		}
		owned, err := u.ReadStartupOwner()
		if err != nil {
			return errUserSettings
		}
		expected, err := u.Startup.ProposedCommand(executable)
		if err != nil {
			return errUserSettings
		}
		if owned != "" && owned != expected {
			return errUserSettings
		}
		// Persist intended ownership before the registry operation for crash recovery.
		if err := u.WriteStartupOwner(expected); err != nil {
			return errUserSettings
		}
		command, err := u.Startup.Enable(executable, owned)
		if err != nil {
			_ = u.WriteStartupOwner(owned)
			return errUserSettings
		}
		if command != expected {
			return errUserSettings
		}
		return nil
	})
	if err != nil {
		return UserSettingsView{}, errUserSettings
	}
	return a.userSettingsView()
}
func (a *Application) disableUserStartup(token string) (UserSettingsView, error) {
	if a == nil || a.Store == nil {
		return UserSettingsView{}, errUserSettings
	}
	if _, err := a.validateUserSettingsToken(token); err != nil {
		return UserSettingsView{}, err
	}
	u := a.automation()
	err := u.Transaction(func() error {
		if _, err := a.validateUserSettingsToken(token); err != nil {
			return err
		}
		owned, err := u.ReadStartupOwner()
		if err != nil || owned == "" {
			return errUserSettings
		}
		conflict, err := u.Startup.Disable(owned)
		if err != nil {
			return errUserSettings
		}
		if conflict {
			u.notice = "External startup changes were left unchanged; recorded ownership was retained for review."
			return nil
		}
		if err := u.WriteStartupOwner(""); err != nil {
			return errUserSettings
		}
		return nil
	})
	if err != nil {
		return UserSettingsView{}, errUserSettings
	}
	return a.userSettingsView()
}

type userMachineOwnership struct {
	Version          int
	StartupCommand   string
	InhibitedSession string `json:",omitempty"`
}

func readStartupOwner(root string) (string, error) {
	state, err := readUserMachineOwnership(root)
	return state.StartupCommand, err
}
func readUserMachineOwnership(root string) (userMachineOwnership, error) {
	path, err := backupPath(filepath.Join(root, "user-machine.bin"))
	if err != nil {
		return userMachineOwnership{}, errUserSettings
	}
	f, err := openBackupFile(path)
	if os.IsNotExist(err) {
		return userMachineOwnership{Version: 1}, nil
	}
	if err != nil {
		if _, e := os.Lstat(path); os.IsNotExist(e) {
			return userMachineOwnership{Version: 1}, nil
		}
		return userMachineOwnership{}, errUserSettings
	}
	defer f.Close()
	encrypted, err := readBounded(f, 65536)
	if err != nil {
		return userMachineOwnership{}, errUserSettings
	}
	defer clear(encrypted)
	plain, err := Protect(encrypted, false)
	if err != nil {
		return userMachineOwnership{}, errUserSettings
	}
	defer clear(plain)
	var value userMachineOwnership
	if json.Unmarshal(plain, &value) != nil || value.Version != 1 || len(value.StartupCommand) > 32767 || len(value.InhibitedSession) > 128 {
		return userMachineOwnership{}, errUserSettings
	}
	return value, nil
}
func writeStartupOwner(root, value string) error {
	state, err := readUserMachineOwnership(root)
	if err != nil {
		return err
	}
	state.StartupCommand = value
	return writeUserMachineOwnership(root, state)
}
func writeUserMachineOwnership(root string, value userMachineOwnership) error {
	path, err := backupPath(filepath.Join(root, "user-machine.bin"))
	if err != nil || len(value.StartupCommand) > 32767 || len(value.InhibitedSession) > 128 {
		return errUserSettings
	}
	value.Version = 1
	plain, err := json.Marshal(value)
	if err != nil {
		return errUserSettings
	}
	defer clear(plain)
	encrypted, err := Protect(plain, true)
	if err != nil {
		return errUserSettings
	}
	defer clear(encrypted)
	f, err := os.CreateTemp(root, "user-machine-*.new")
	if err != nil {
		return errUserSettings
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(encrypted); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errUserSettings
	}
	if err = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return errUserSettings
	}
	return nil
}
