package main

import (
	"abiroute/internal/config"
	"abiroute/internal/engine"
	"abiroute/internal/tray"
	"abiroute/internal/updater"
	"context"
	"os"
	"sync/atomic"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx            context.Context
	store          *config.Store
	eng            *engine.Engine
	trayMgr        *tray.Manager
	forceQuit      atomic.Bool
	startMinimized bool
}

func NewApp(startMinimized bool) *App {
	store := config.LoadStore()
	app := &App{
		store:          store,
		startMinimized: startMinimized,
	}
	app.eng = engine.New(store, func(topic string, payload any) {
		if app.ctx != nil {
			wailsRuntime.EventsEmit(app.ctx, topic, payload)
		}
	})
	return app
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	st := a.store.Get()

	a.trayMgr = tray.NewManager(tray.Callbacks{
		OnShowWindow: func() {
			if a.ctx != nil {
				wailsRuntime.WindowShow(a.ctx)
				wailsRuntime.WindowUnminimise(a.ctx)
			}
		},
		OnToggleBoost: func() {
			if a.eng.IsBoosted() {
				a.eng.StopBoost()
				tray.PlayTone(false)
			} else {
				cur := a.store.Get()
				if err := a.eng.BoostOneClick(cur.ActiveGameID); err == nil {
					tray.PlayTone(true)
				}
			}
		},
		OnQuit: func() {
			a.QuitApp()
		},
	}, st.GlobalHotkey)

	a.eng.SetTrayHook(func(boosted bool, tooltip string, hotkey bool) {
		if a.trayMgr != nil {
			a.trayMgr.UpdateState(boosted, tooltip)
			a.trayMgr.SetHotkeyEnabled(hotkey)
		}
	})

	if a.startMinimized {
		wailsRuntime.WindowHide(ctx)
	}
}

func (a *App) beforeClose(ctx context.Context) bool {
	if a.forceQuit.Load() {
		return false
	}
	st := a.store.Get()
	if st.CloseToTray {
		wailsRuntime.WindowHide(ctx)
		return true
	}
	return false
}

func (a *App) shutdown(ctx context.Context) {
	if a.trayMgr != nil {
		a.trayMgr.Close()
	}
	if a.eng != nil {
		a.eng.Shutdown()
	}
}

func (a *App) GetState() engine.DashboardState {
	return a.eng.GetState()
}

func (a *App) SelectGame(gameID string) engine.DashboardState {
	return a.eng.SelectGame(gameID)
}

func (a *App) LaunchActiveGame() error {
	return a.eng.LaunchActiveGame()
}

func (a *App) AddCustomGame(name, exeNames, rawSubnets string) (engine.DashboardState, error) {
	return a.eng.AddCustomGame(name, exeNames, rawSubnets)
}

func (a *App) BoostOneClick(gameID string) error {
	return a.eng.BoostOneClick(gameID)
}

func (a *App) StopBoost() engine.DashboardState {
	return a.eng.StopBoost()
}

func (a *App) ScanEndpoints() error {
	return a.eng.ScanEndpoints()
}

func (a *App) CancelOperation() {
	a.eng.CancelOperation()
}

func (a *App) UpdateOptions(protocol, selectedEndpoint string, raidProtection, autoFailover, autoLearn bool, subnetPrefix int) engine.DashboardState {
	return a.eng.UpdateOptions(protocol, selectedEndpoint, raidProtection, autoFailover, autoLearn, subnetPrefix)
}

func (a *App) UpdateSystemPrefs(autoBoost, autoStop, closeToTray, startWithWin, globalHotkey bool, mtu int) engine.DashboardState {
	return a.eng.UpdateSystemPrefs(autoBoost, autoStop, closeToTray, startWithWin, globalHotkey, mtu)
}

func (a *App) GenerateWarpProfile() error {
	return a.eng.GenerateWarpProfile()
}

func (a *App) ApplyWarpPlus(licenseKey string) (engine.DashboardState, error) {
	return a.eng.ApplyWarpPlus(licenseKey)
}

func (a *App) AutoOptimizeMTU() (engine.DashboardState, error) {
	return a.eng.AutoOptimizeMTU()
}

func (a *App) AddProxyLinks(rawText string) (engine.DashboardState, error) {
	return a.eng.AddProxyLinks(rawText)
}

func (a *App) SyncSubscription(subURL string) (engine.DashboardState, error) {
	return a.eng.SyncSubscription(subURL)
}

func (a *App) SelectProxy(proxyID string) engine.DashboardState {
	return a.eng.SelectProxy(proxyID)
}

func (a *App) DeleteProxy(proxyID string) engine.DashboardState {
	return a.eng.DeleteProxy(proxyID)
}

func (a *App) SetHighPingFilter(enabled bool, thresholdMs int) engine.DashboardState {
	return a.eng.SetHighPingFilter(enabled, thresholdMs)
}

func (a *App) ToggleBlockServer(ip string) engine.DashboardState {
	return a.eng.ToggleBlockServer(ip)
}

func (a *App) ClearBlockedServers() engine.DashboardState {
	return a.eng.ClearBlockedServers()
}

func (a *App) SaveManualRoutes(manualLines, excludedLines string) engine.DashboardState {
	return a.eng.SaveManualRoutes(manualLines, excludedLines)
}

func (a *App) ResetLearnedRoutes() engine.DashboardState {
	return a.eng.ResetLearnedRoutes()
}

func (a *App) CheckUpdatesNow() updater.UpdateInfo {
	return a.eng.CheckUpdatesNow()
}

func (a *App) InstallUpdateNow() error {
	if err := a.eng.InstallUpdateNow(); err != nil {
		return err
	}
	a.QuitApp()
	return nil
}

func (a *App) ImportTunnelText(input, name string) error {
	return a.eng.ImportTunnelConfig(input, name)
}

func (a *App) ImportConfFile() error {
	if a.ctx == nil {
		return nil
	}
	filePath, err := wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Импорт конфига WireGuard / AmneziaWG (.conf)",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "Конфиг туннеля (*.conf)", Pattern: "*.conf"},
			{DisplayName: "Все файлы (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil || filePath == "" {
		return err
	}
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	return a.eng.ImportTunnelConfig(string(raw), "")
}

func (a *App) ExportConfFile() (string, error) {
	confText, err := a.eng.ExportTunnelConf()
	if err != nil {
		return "", err
	}
	if a.ctx == nil {
		return confText, nil
	}
	savePath, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		Title:           "Экспорт split-tunnel конфига для игры",
		DefaultFilename: "ABIRoute.conf",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "Конфиг AmneziaWG / WireGuard (*.conf)", Pattern: "*.conf"},
		},
	})
	if err != nil || savePath == "" {
		return "", err
	}
	if err := os.WriteFile(savePath, []byte(confText), 0o600); err != nil {
		return "", err
	}
	return savePath, nil
}

func (a *App) RunDiagnostics() engine.DiagReport {
	return a.eng.RunDiagnostics()
}

func (a *App) HideToTray() {
	if a.ctx != nil {
		wailsRuntime.WindowHide(a.ctx)
	}
}

func (a *App) QuitApp() {
	a.forceQuit.Store(true)
	if a.trayMgr != nil {
		a.trayMgr.Close()
	}
	if a.eng != nil {
		a.eng.Shutdown()
	}
	if a.ctx != nil {
		wailsRuntime.Quit(a.ctx)
	}
}
