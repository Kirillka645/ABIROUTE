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
	// Headless CI / self-verification flag: ABIRoute.exe --selftest [out.json]
	for i, arg := range os.Args[1:] {
		if arg == "--selftest" {
			runSelfTest(os.Args[i+2:])
			return
		}
	}

	if !acquireSingleInstance() {
		return
	}

	app := NewApp()
	err := wails.Run(&options.App{
		Title:            "ABI Route 4.0 — Smart Game Booster",
		Width:            1140,
		Height:           740,
		MinWidth:         1020,
		MinHeight:        680,
		Frameless:        true,
		BackgroundColour: &options.RGBA{R: 13, G: 16, B: 21, A: 255},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			Theme:                windows.Dark,
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
	app := NewApp()
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
