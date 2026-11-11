package main

import (
	"abiroute/internal/config"
	"abiroute/internal/engine"
	"context"
	"os"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx   context.Context
	store *config.Store
	eng   *engine.Engine
}

func NewApp() *App {
	store := config.LoadStore()
	app := &App{store: store}
	app.eng = engine.New(store, func(topic string, payload any) {
		if app.ctx != nil {
			wailsRuntime.EventsEmit(app.ctx, topic, payload)
		}
	})
	return app
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(ctx context.Context) {
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

func (a *App) GenerateWarpProfile() error {
	return a.eng.GenerateWarpProfile()
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

func (a *App) WindowMinimize() {
	if a.ctx != nil {
		wailsRuntime.WindowMinimise(a.ctx)
	}
}

func (a *App) WindowToggleMax() {
	if a.ctx != nil {
		wailsRuntime.WindowToggleMaximise(a.ctx)
	}
}

func (a *App) QuitApp() {
	if a.eng != nil {
		a.eng.Shutdown()
	}
	if a.ctx != nil {
		wailsRuntime.Quit(a.ctx)
	}
}
