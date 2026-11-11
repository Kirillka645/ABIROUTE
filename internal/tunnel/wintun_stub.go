//go:build !windows

package tunnel

func EnsureWintunDLL() error { return nil }
