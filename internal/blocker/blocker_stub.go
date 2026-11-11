//go:build !windows

package blocker

func SyncFirewallBlocks(blockedTargets []string) error { return nil }
func ClearFirewallBlocks()                             {}
