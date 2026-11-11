//go:build windows

package blocker

import (
	"abiroute/internal/netwin"
	"os/exec"
	"strings"
	"syscall"
)

func runFw(args ...string) error {
	cmd := exec.Command("netsh", append([]string{"advfirewall", "firewall"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	_, err := cmd.CombinedOutput()
	return err
}

// SyncFirewallBlocks updates the ABIRoute_HighPingFilter outbound Windows Firewall rule.
func SyncFirewallBlocks(blockedTargets []string) error {
	if !netwin.IsAdmin() {
		return nil
	}
	_ = runFw("delete", "rule", "name="+FirewallRuleName)
	clean := netwin.NormalizePrefixes(blockedTargets, "")
	if len(clean) == 0 {
		return nil
	}
	return runFw(
		"add", "rule",
		"name="+FirewallRuleName,
		"dir=out",
		"action=block",
		"remoteip="+strings.Join(clean, ","),
		"enable=yes",
	)
}

func ClearFirewallBlocks() {
	if netwin.IsAdmin() {
		_ = runFw("delete", "rule", "name="+FirewallRuleName)
	}
}
