//go:build !windows

package probe

func DiscoverOptimalMTU(targetIP, srcLocalIP string) int { return 1360 }
