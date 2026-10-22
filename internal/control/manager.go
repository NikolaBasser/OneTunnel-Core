package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
)

type Backend interface {
	Call(context.Context, Request) (BackendResult, error)
	Alive() bool
	Close()
}
type Factory func(onState func(State), onFailure func()) (Backend, error)

// Manager owns the public session identity, command order and failure policy.
// The temporary backend is a platform adapter, never a second public server.
type Manager struct {
	mu         sync.RWMutex
	state      State
	instance   string
	profileID  *string
	gate       chan struct{}
	factory    Factory
	backend    Backend
	generation uint64
	failed     bool
	closing    bool
}

func NewManager(factory Factory) (*Manager, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	m := &Manager{instance: hex.EncodeToString(token[:]), factory: factory, gate: make(chan struct{}, 1), state: State{Status: "Отключено"}}
	if err := m.restart(); err != nil {
		return nil, err
	}
	return m, nil
}
func (m *Manager) store(s State, generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation != m.generation || m.closing || m.failed {
		return
	}
	s.ProfileID = m.profileID
	m.state = s
}
func (m *Manager) fail(generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation != m.generation || m.closing {
		return
	}
	m.failed = true
	m.state.Active = false
	m.state.NeedsRecovery = true
	m.state.Status = "Адаптер остановился · требуется восстановление; состояние защиты сохранено"
}
func (m *Manager) restart() error {
	m.mu.Lock()
	m.generation++
	generation := m.generation
	m.failed = false
	m.mu.Unlock()
	if m.backend != nil {
		m.backend.Close()
	}
	backend, err := m.factory(func(s State) { m.store(s, generation) }, func() { m.fail(generation) })
	if err != nil {
		m.fail(generation)
		return err
	}
	m.backend = backend
	msg, err := backend.Call(context.Background(), Request{Version: Version, Command: "hello"})
	if err != nil {
		m.fail(generation)
		backend.Close()
		return err
	}
	m.store(msg.State, generation)
	return nil
}
func (m *Manager) snapshot() State { m.mu.RLock(); defer m.mu.RUnlock(); return m.state }
func (m *Manager) reply(result *string, code string) Response {
	var err *string
	if code != "" {
		err = &code
	}
	return Response{Version: Version, Instance: m.instance, State: m.snapshot(), Result: result, Error: err}
}
func (m *Manager) Dispatch(ctx context.Context, request Request) Response {
	if code := Validate(request); code != "" {
		return m.reply(nil, code)
	}
	if request.Command == "hello" || request.Command == "status" {
		return m.reply(nil, "")
	}
	select {
	case m.gate <- struct{}{}:
	case <-ctx.Done():
		return m.reply(nil, "operation_timeout")
	}
	defer func() { <-m.gate }()
	m.mu.RLock()
	failed := m.failed
	closing := m.closing
	m.mu.RUnlock()
	if closing {
		return m.reply(nil, "core_stopping")
	}
	if failed || m.backend == nil || !m.backend.Alive() {
		if request.Command != "recover" {
			return m.reply(nil, "backend_unavailable")
		}
		if err := m.restart(); err != nil {
			return m.reply(nil, "backend_unavailable")
		}
	}
	state := m.snapshot()
	if request.Command == "start" && (state.Active || state.NeedsRecovery) {
		return m.reply(nil, "recovery_required")
	}
	if request.Command == "start" {
		m.mu.Lock()
		id := request.Profile.ID
		m.profileID = &id
		m.mu.Unlock()
	}
	// Accepted operations are independent of a GUI/pipe cancellation. Their
	// adapter call has its own bounded deadline and never silently retries.
	message, err := m.backend.Call(context.Background(), request)
	if err != nil {
		m.fail(m.generation)
		return m.reply(nil, "backend_unavailable")
	}
	m.mu.Lock()
	if m.failed {
		m.mu.Unlock()
		return m.reply(nil, "backend_unavailable")
	}
	if message.Error == nil && (request.Command == "stop" || request.Command == "recover") || message.Error != nil && !message.State.Active {
		m.profileID = nil
	}
	message.State.ProfileID = m.profileID
	m.state = message.State
	m.mu.Unlock()
	code := ""
	if message.Error != nil {
		code = *message.Error
	}
	return m.reply(message.Result, code)
}
func (m *Manager) Close() {
	m.mu.Lock()
	m.closing = true
	m.mu.Unlock()
	m.gate <- struct{}{}
	defer func() { <-m.gate }()
	if m.backend != nil {
		m.backend.Close()
	}
}
