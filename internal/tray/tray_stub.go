//go:build !windows

package tray

type Callbacks struct {
	OnShowWindow  func()
	OnToggleBoost func()
	OnQuit        func()
}

type Manager struct{}

func NewManager(cb Callbacks, initialHotkey bool) *Manager  { return &Manager{} }
func (m *Manager) UpdateState(boosted bool, tooltip string) {}
func (m *Manager) SetHotkeyEnabled(enabled bool)            {}
func PlayTone(activating bool)                              {}
func (m *Manager) Close()                                   {}
