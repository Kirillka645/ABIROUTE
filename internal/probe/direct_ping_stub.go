//go:build !windows

package probe

import "time"

type PingStats struct {
	MedianMs int    `json:"medianMs"`
	JitterMs int    `json:"jitterMs"`
	LossPct  int    `json:"lossPct"`
	Method   string `json:"method"`
}

func DirectPingOne(targetIP string, tcpPort int, srcLocalIP string, timeout time.Duration) (float64, string, error) {
	return 25.0, "ICMP", nil
}

func MeasureDirect(targetIP string, tcpPort int, srcLocalIP string, count int) *PingStats {
	return &PingStats{MedianMs: 25, JitterMs: 1, LossPct: 0, Method: "ICMP"}
}
