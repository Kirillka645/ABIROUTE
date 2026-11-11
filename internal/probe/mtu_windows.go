//go:build windows

package probe

import (
	"net"
	"unsafe"
)

type ipOptionInformation32 struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

const ipFlagDF = 0x02

// DiscoverOptimalMTU probes the active physical path with Don't-Fragment ICMP packets
// and computes the ideal inner tunnel MTU (zero packet fragmentation in raids).
func DiscoverOptimalMTU(targetIP, srcLocalIP string) int {
	dst := net.ParseIP(targetIP).To4()
	if dst == nil {
		dst = net.IPv4(1, 1, 1, 1)
	}
	var src uint32
	if srcLocalIP != "" {
		if sip := net.ParseIP(srcLocalIP).To4(); sip != nil {
			src = ipv4Uint32LE(sip)
		}
	}

	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return 1280
	}
	defer procIcmpCloseHandle.Call(h)

	// Test IPv4 payload sizes (Total IP packet = payload + 28 bytes IP+ICMP header)
	candidates := []int{1472, 1464, 1452, 1432, 1412, 1392, 1372, 1352, 1320}
	bestOuterMTU := 1360

	for _, payloadLen := range candidates {
		payload := make([]byte, payloadLen)
		opts := ipOptionInformation32{
			Ttl:   64,
			Flags: ipFlagDF,
		}
		replyBuf := make([]byte, unsafe.Sizeof(icmpEchoReply32{})+uintptr(payloadLen)+64)
		ret, _, _ := procIcmpSendEcho2Ex.Call(
			h, 0, 0, 0,
			uintptr(src),
			uintptr(ipv4Uint32LE(dst)),
			uintptr(unsafe.Pointer(&payload[0])),
			uintptr(payloadLen),
			uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&replyBuf[0])),
			uintptr(len(replyBuf)),
			700,
		)
		if ret > 0 {
			rep := (*icmpEchoReply32)(unsafe.Pointer(&replyBuf[0]))
			if rep.Status == 0 {
				bestOuterMTU = payloadLen + 28
				break
			}
		}
	}

	// Subtract 80 bytes for WireGuard/AmneziaWG/QUIC outer headers + safety margin
	inner := bestOuterMTU - 80
	if inner < 1240 {
		inner = 1240
	}
	if inner > 1400 {
		inner = 1400
	}
	return inner
}
