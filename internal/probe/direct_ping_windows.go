//go:build windows

package probe

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sort"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlp              = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile    = modIphlp.NewProc("IcmpCreateFile")
	procIcmpCloseHandle   = modIphlp.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex   = modIphlp.NewProc("IcmpSendEcho2Ex")
)

type icmpEchoReply32 struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       [8]byte
}

func ipv4Uint32LE(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(v4)
}

type PingStats struct {
	MedianMs int    `json:"medianMs"`
	JitterMs int    `json:"jitterMs"`
	LossPct  int    `json:"lossPct"`
	Method   string `json:"method"`
}

// DirectPingOne sends a single Win32 ICMP Echo (bound to srcLocalIP if non-empty to bypass Wintun)
// and falls back to a bound TCP handshake if ICMP is filtered on the target host.
func DirectPingOne(targetIP string, tcpPort int, srcLocalIP string, timeout time.Duration) (float64, string, error) {
	dst := net.ParseIP(targetIP).To4()
	if dst == nil {
		return 0, "", fmt.Errorf("invalid IPv4: %s", targetIP)
	}
	var src uint32
	if srcLocalIP != "" {
		if sip := net.ParseIP(srcLocalIP).To4(); sip != nil {
			src = ipv4Uint32LE(sip)
		}
	}

	h, _, _ := procIcmpCreateFile.Call()
	if h != uintptr(windows.InvalidHandle) && h != 0 {
		defer procIcmpCloseHandle.Call(h)
		payload := []byte("ABIROUTE")
		replyBuf := make([]byte, unsafe.Sizeof(icmpEchoReply32{})+uintptr(len(payload))+32)
		msTimeout := uint32(timeout.Milliseconds())
		if msTimeout < 200 {
			msTimeout = 1000
		}
		t0 := time.Now()
		ret, _, _ := procIcmpSendEcho2Ex.Call(
			h,
			0,
			0,
			0,
			 uintptr(src),
			uintptr(ipv4Uint32LE(dst)),
			uintptr(unsafe.Pointer(&payload[0])),
			uintptr(len(payload)),
			0,
			uintptr(unsafe.Pointer(&replyBuf[0])),
			uintptr(len(replyBuf)),
			uintptr(msTimeout),
		)
		if ret > 0 {
			rep := (*icmpEchoReply32)(unsafe.Pointer(&replyBuf[0]))
			if rep.Status == 0 {
				rtt := float64(rep.RoundTripTime)
				if rtt < 0.5 {
					rtt = float64(time.Since(t0).Microseconds()) / 1000.0
				}
				return rtt, "ICMP", nil
			}
		}
	}

	// Fallback: bound TCP connect to game port or 443/80 (only for direct NIC path, never through Cloudflare WARP)
	ports := []int{443, 80}
	if tcpPort > 0 {
		ports = append([]int{tcpPort}, ports...)
	}
	for _, p := range ports {
		dialer := net.Dialer{Timeout: timeout}
		if srcLocalIP != "" {
			if sip := net.ParseIP(srcLocalIP).To4(); sip != nil {
				dialer.LocalAddr = &net.TCPAddr{IP: sip, Port: 0}
			}
		}
		t0 := time.Now()
		conn, err := dialer.Dial("tcp4", fmt.Sprintf("%s:%d", dst.String(), p))
		if err == nil {
			_ = conn.Close()
			return float64(time.Since(t0).Microseconds()) / 1000.0, fmt.Sprintf("TCP:%d", p), nil
		}
	}

	return 0, "", fmt.Errorf("no response")
}

// MeasureDirect measures median RTT, jitter, and packet loss directly through the physical NIC (bypassing Wintun).
func MeasureDirect(targetIP string, tcpPort int, srcLocalIP string, count int) *PingStats {
	if count < 1 {
		count = 3
	}
	var vals []float64
	method := "ICMP"
	for i := 0; i < count; i++ {
		ms, m, err := DirectPingOne(targetIP, tcpPort, srcLocalIP, 1200*time.Millisecond)
		if err == nil {
			vals = append(vals, ms)
			method = m
		}
		if i+1 < count {
			time.Sleep(60 * time.Millisecond)
		}
	}
	if len(vals) == 0 {
		return nil
	}
	sort.Float64s(vals)
	med := vals[len(vals)/2]
	var mean float64
	for _, v := range vals {
		mean += v
	}
	mean /= float64(len(vals))
	var variance float64
	for _, v := range vals {
		d := v - mean
		variance += d * d
	}
	jitter := 0.0
	if len(vals) > 1 {
		jitter = math.Sqrt(variance / float64(len(vals)))
	}
	return &PingStats{
		MedianMs: int(math.Round(med)),
		JitterMs: int(math.Round(jitter)),
		LossPct:  int(math.Round(float64(count-len(vals)) * 100.0 / float64(count))),
		Method:   method,
	}
}
