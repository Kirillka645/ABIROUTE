//go:build !windows

package syswin

func SetAutoStart(enabled bool) error                  { return nil }
func LaunchGame(gameID string, customExePath string) error { return nil }
