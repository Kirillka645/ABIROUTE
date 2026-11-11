package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	startMinimized := false
	for i, arg := range os.Args[1:] {
		if arg == "--selftest" {
			runSelfTest(os.Args[i+2:])
			return
		}
		if arg == "--minimized" {
			startMinimized = true
		}
	}

	if !acquireSingleInstance() {
		return
	}

	app := NewApp(startMinimized)
	err := wails.Run(&options.App{
		Title:            "ABI Route 5.0 — Smart Game Booster",
		Width:            1080,
		Height:           690,
		MinWidth:         740,
		MinHeight:        500,
		Frameless:        false,
		BackgroundColour: &options.RGBA{R: 13, G: 16, B: 21, A: 255},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:     app.startup,
		OnBeforeClose: app.beforeClose,
		OnShutdown:    app.shutdown,
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			Theme:                windows.Dark,
			CustomTheme: &windows.ThemeSettings{
				DarkModeTitleBar:   windows.RGB(10, 13, 17),
				DarkModeTitleText:  windows.RGB(243, 246, 250),
				DarkModeBorder:     windows.RGB(28, 35, 46),
				LightModeTitleBar:  windows.RGB(10, 13, 17),
				LightModeTitleText: windows.RGB(243, 246, 250),
				LightModeBorder:    windows.RGB(28, 35, 46),
			},
		},
		Bind: []any{
			app,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Wails error: %v\n", err)
		os.Exit(1)
	}
}

func runSelfTest(rest []string) {
	app := NewApp(false)
	defer app.eng.Shutdown()

	state := app.GetState()
	payload, err := json.MarshalIndent(map[string]any{
		"ok":           true,
		"version":      state.Version,
		"gamesLoaded":  len(state.Catalog),
		"activeGame":   state.ActiveGame.ID,
		"presetRoutes": len(state.ActiveGame.PresetRanges),
		"isAdmin":      state.IsAdmin,
	}, "", "  ")
	if err != nil {
		os.Exit(2)
	}
	if len(rest) > 0 && rest[0] != "" {
		_ = os.WriteFile(rest[0], payload, 0o644)
	} else {
		fmt.Println(string(payload))
	}
}
