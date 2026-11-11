//go:build windows

package syswin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const runRegPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValName = "ABIRoute"

var steamAppIDs = map[string]string{
	"abi":         "2073620",
	"delta-force": "2507950",
	"pubg":        "578080",
	"cs2":         "730",
	"apex":        "1172470",
}

func SetAutoStart(enabled bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runRegPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if !enabled {
		_ = k.DeleteValue(runValName)
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf(`"%s" --minimized`, exe)
	return k.SetStringValue(runValName, cmd)
}

func LaunchGame(gameID string, customExePath string) error {
	if customExePath != "" {
		if _, err := os.Stat(customExePath); err == nil {
			cmd := exec.Command(customExePath)
			cmd.Dir = filepath.Dir(customExePath)
			return cmd.Start()
		}
	}

	// Check standalone Arena Breakout Infinite / Tarkov launchers first if present
	if gameID == "abi" {
		for _, p := range findABILauncherPaths() {
			if _, err := os.Stat(p); err == nil {
				cmd := exec.Command(p)
				cmd.Dir = filepath.Dir(p)
				return cmd.Start()
			}
		}
	}
	if gameID == "eft" {
		for _, drive := range []string{"C:", "D:", "E:"} {
			p := filepath.Join(drive, `\Battlestate Games\BsgLauncher\BsgLauncher.exe`)
			if _, err := os.Stat(p); err == nil {
				cmd := exec.Command(p)
				cmd.Dir = filepath.Dir(p)
				return cmd.Start()
			}
		}
	}

	if appID, ok := steamAppIDs[gameID]; ok {
		cmd := exec.Command("cmd", "/c", "start", "", "steam://rungameid/"+appID)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
		return cmd.Start()
	}
	return fmt.Errorf("путь запуска для этой игры не найден — запустите игру с ярлыка на рабочем столе")
}

func findABILauncherPaths() []string {
	var paths []string
	// Check Registry Uninstall entries for Arena Breakout Infinite
	for _, root := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
		for _, sub := range []string{
			`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Arena Breakout Infinite`,
			`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Arena Breakout Infinite`,
		} {
			if k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE); err == nil {
				if loc, _, err := k.GetStringValue("InstallLocation"); err == nil && loc != "" {
					paths = append(paths,
						filepath.Join(loc, "launcher", "arena_breakout_infinite_launcher.exe"),
						filepath.Join(loc, "ArenaBreakoutInfiniteLauncher.exe"),
					)
				}
				k.Close()
			}
		}
	}
	for _, drive := range []string{"C:", "D:", "E:"} {
		paths = append(paths,
			filepath.Join(drive, `\Arena Breakout Infinite\launcher\arena_breakout_infinite_launcher.exe`),
			filepath.Join(drive, `\Program Files\Arena Breakout Infinite\launcher\arena_breakout_infinite_launcher.exe`),
		)
	}
	return paths
}
