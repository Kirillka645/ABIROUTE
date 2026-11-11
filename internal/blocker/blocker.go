package blocker

import (
	"net/netip"
	"strings"
)

const FirewallRuleName = "ABIRoute_HighPingFilter"

// ClassifyRegion estimates a game server's geographical region using known cloud/game IP blocks and RTT.
func ClassifyRegion(ipStr string, directPingMs int) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil || !addr.Is4() {
		return "Неизвестно"
	}
	b := addr.As4()

	// Known Asian Tencent Cloud / Singapore / Hong Kong / Tokyo blocks used by ABI & Delta Force
	if b[0] == 101 && (b[1] == 32 || b[1] == 33) {
		return "Азия"
	}
	if b[0] == 119 && b[1] == 28 {
		return "Азия"
	}
	if b[0] == 129 && b[1] == 226 {
		return "Азия"
	}
	if b[0] == 150 && b[1] == 109 {
		return "Азия"
	}
	if b[0] == 43 && (b[1] == 134 || b[1] == 153 || b[1] == 156 || b[1] == 163) {
		if directPingMs > 0 && directPingMs < 95 {
			return "Европа"
		}
		return "Азия"
	}

	// Known US / Americas blocks
	if (b[0] == 162 && b[1] == 62) || (b[0] == 184 && b[1] == 24) {
		return "США"
	}

	// Known CIS / Moscow blocks
	if (b[0] == 188 && b[1] == 43) || (b[0] == 92 && b[1] == 223) || (b[0] == 5 && b[1] == 188) {
		return "СНГ / Европа"
	}

	// Known European Frankfurt / Stockholm / Amsterdam blocks (Tencent EU, AWS EU, Valve EU)
	if (b[0] == 43 && (b[1] == 131 || b[1] == 157 || b[1] == 174)) ||
		(b[0] == 3 && b[1] == 64) ||
		(b[0] == 18 && (b[1] == 156 || b[1] == 194)) ||
		(b[0] == 52 && (b[1] == 28 || b[1] == 58)) ||
		(b[0] == 155 && b[1] == 133) ||
		(b[0] == 35 && (b[1] == 156 || b[1] == 228)) {
		return "Европа"
	}

	// Fallback by measured latency from RU/EU
	switch {
	case directPingMs > 0 && directPingMs <= 40:
		return "СНГ / Ближний"
	case directPingMs > 40 && directPingMs <= 105:
		return "Европа"
	case directPingMs > 105 && directPingMs <= 175:
		return "США / Восток"
	case directPingMs > 175:
		return "Азия / Океания"
	default:
		return "Глобальный"
	}
}
