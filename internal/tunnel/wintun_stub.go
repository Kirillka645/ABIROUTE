//go:build !windows

package tunnel

import "os/exec"

func EnsureWintunDLL() error        { return nil }
func setSysProcHide(cmd *exec.Cmd) {}
