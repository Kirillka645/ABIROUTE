//go:build windows

package netwin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const createNoWindow = 0x08000000

var (
	modShell32             = windows.NewLazySystemDLL("shell32.dll")
	procIsUserAnAdmin      = modShell32.NewProc("IsUserAnAdmin")
	modIphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpForwardTable  = modIphlpapi.NewProc("GetIpForwardTable")
	procGetInterfaceInfo   = modIphlpapi.NewProc("GetAdaptersInfo")
)

type PhysicalNIC struct {
	IP          string `json:"ip"`
	Gateway     string `json:"gateway"`
	IfIndex     uint32 `json:"ifIndex"`
	AdapterName string `json:"adapterName"`
}

func IsAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

func runHidden(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// mibIpForwardRow matches Win32 MIB_IPFORWARDROW (IPv4 routing table entry).
type mibIpForwardRow struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

// ipAdapterInfo matches Win32 IP_ADAPTER_INFO layout for IPv4 adapter & gateway discovery.
type ipAddrString struct {
	Next      *ipAddrString
	IpAddress [16]byte
	IpMask    [16]byte
	Context   uint32
}

type ipAdapterInfo struct {
	Next                *ipAdapterInfo
	ComboIndex          uint32
	AdapterName         [260]byte
	Description         [132]byte
	AddressLength       uint32
	Address             [8]byte
	Index               uint32
	Type                uint32
	DhcpEnabled         uint32
	CurrentIpAddress    *ipAddrString
	IpAddressList       ipAddrString
	GatewayList         ipAddrString
	DhcpServer          ipAddrString
	HaveWins            int32
	PrimaryWinsServer   ipAddrString
	SecondaryWinsServer ipAddrString
	LeaseObtained       int64
	LeaseExpires        int64
}

func cStr(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx < 0 {
		return string(b)
	}
	return string(b[:idx])
}

func uint32LEToIPString(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

// DefaultPhysicalInterface finds the primary physical internet NIC, ignoring Wintun/ABIRoute adapters.
func DefaultPhysicalInterface() (*PhysicalNIC, error) {
	// 1. Inspect IPv4 default routes (0.0.0.0/0) with non-zero gateway
	var size uint32 = 16384
	buf := make([]byte, size)
	ret, _, _ := procGetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
	if ret == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		buf = make([]byte, size)
		ret, _, _ = procGetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
	}

	bestMetric := ^uint32(0)
	var bestIfIdx uint32
	var bestGw string

	if ret == 0 && len(buf) >= 4 {
		count := binary.LittleEndian.Uint32(buf[:4])
		rowSize := unsafe.Sizeof(mibIpForwardRow{})
		for i := uint32(0); i < count; i++ {
			off := uintptr(4) + uintptr(i)*rowSize
			if off+rowSize > uintptr(len(buf)) {
				break
			}
			row := *(*mibIpForwardRow)(unsafe.Pointer(&buf[off]))
			if row.ForwardDest == 0 && row.ForwardMask == 0 && row.ForwardNextHop != 0 {
				if row.ForwardMetric1 < bestMetric {
					bestMetric = row.ForwardMetric1
					bestIfIdx = row.ForwardIfIndex
					bestGw = uint32LEToIPString(row.ForwardNextHop)
				}
			}
		}
	}

	// 2. Match adapter IPv4 & description from GetAdaptersInfo
	var adSize uint32 = 32768
	adBuf := make([]byte, adSize)
	adRet, _, _ := procGetInterfaceInfo.Call(uintptr(unsafe.Pointer(&adBuf[0])), uintptr(unsafe.Pointer(&adSize)))
	if adRet == uintptr(windows.ERROR_BUFFER_OVERFLOW) {
		adBuf = make([]byte, adSize)
		adRet, _, _ = procGetInterfaceInfo.Call(uintptr(unsafe.Pointer(&adBuf[0])), uintptr(unsafe.Pointer(&adSize)))
	}
	if adRet == 0 && len(adBuf) > 0 {
		for cur := (*ipAdapterInfo)(unsafe.Pointer(&adBuf[0])); cur != nil; cur = cur.Next {
			desc := cStr(cur.Description[:])
			if strings.Contains(strings.ToLower(desc), "wintun") || strings.Contains(strings.ToLower(desc), "abiroute") {
				continue
			}
			ip := cStr(cur.IpAddressList.IpAddress[:])
			gw := cStr(cur.GatewayList.IpAddress[:])
			if cur.Index == bestIfIdx && ip != "" && ip != "0.0.0.0" {
				if gw == "" || gw == "0.0.0.0" {
					gw = bestGw
				}
				return &PhysicalNIC{
					IP:          ip,
					Gateway:     gw,
					IfIndex:     cur.Index,
					AdapterName: desc,
				}, nil
			}
		}
	}

	// Fallback: UDP connect socket selection
	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return &PhysicalNIC{
		IP:          localAddr.IP.String(),
		Gateway:     bestGw,
		IfIndex:     bestIfIdx,
		AdapterName: "Основной адаптер",
	}, nil
}

// ConfigureTunInterface assigns the /32 tunnel IPv4 address and MTU on the Wintun interface.
func ConfigureTunInterface(ifaceName, ipv4 string, mtu int) error {
	if ipv4 == "" {
		ipv4 = "172.16.0.2"
	}
	if mtu < 1200 {
		mtu = 1280
	}
	if _, err := runHidden("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", ifaceName), "source=static",
		fmt.Sprintf("addr=%s", ipv4), "mask=255.255.255.255", "store=active"); err != nil {
		// Retry without store=active for localized/older Windows builds
		if out, err2 := runHidden("netsh", "interface", "ipv4", "set", "address",
			fmt.Sprintf("name=%s", ifaceName), "static", ipv4, "255.255.255.255"); err2 != nil {
			return fmt.Errorf("не удалось назначить IP адаптеру %s: %s (%w)", ifaceName, strings.TrimSpace(out), err2)
		}
	}
	_, _ = runHidden("netsh", "interface", "ipv4", "set", "subinterface",
		ifaceName, fmt.Sprintf("mtu=%d", mtu), "store=active")
	return nil
}

// SyncRoutes ensures endpointIP/32 is pinned to the physical gateway and exact desiredPrefixes route via ifaceName.
func SyncRoutes(ifaceName, endpointIP string, phys *PhysicalNIC, desiredPrefixes []string, prevPrefixes []string) error {
	// 1. Pin tunnel server IP to physical NIC gateway so encrypted UDP/QUIC packets never enter Wintun
	if ep := net.ParseIP(strings.TrimSpace(endpointIP)); ep != nil && ep.To4() != nil && phys != nil && phys.Gateway != "" && phys.IfIndex != 0 {
		_, _ = runHidden("route", "delete", ep.To4().String(), "mask", "255.255.255.255")
		_, _ = runHidden("route", "add", ep.To4().String(), "mask", "255.255.255.255",
			phys.Gateway, "metric", "1", "if", fmt.Sprintf("%d", phys.IfIndex))
	}

	desiredSet := make(map[string]struct{}, len(desiredPrefixes))
	for _, p := range desiredPrefixes {
		desiredSet[p] = struct{}{}
	}
	prevSet := make(map[string]struct{}, len(prevPrefixes))
	for _, p := range prevPrefixes {
		prevSet[p] = struct{}{}
	}

	// Remove stale routes
	for oldP := range prevSet {
		if _, keep := desiredSet[oldP]; !keep {
			_, _ = runHidden("netsh", "interface", "ipv4", "delete", "route",
				fmt.Sprintf("prefix=%s", oldP), fmt.Sprintf("interface=%s", ifaceName), "store=active")
		}
	}

	// Add newly learned or preset routes
	for _, newP := range desiredPrefixes {
		if _, already := prevSet[newP]; already {
			continue
		}
		_, _ = runHidden("netsh", "interface", "ipv4", "add", "route",
			fmt.Sprintf("prefix=%s", newP), fmt.Sprintf("interface=%s", ifaceName),
			"nexthop=0.0.0.0", "metric=1", "store=active")
	}
	return nil
}

// CleanupRoutes removes pinned endpoint and Wintun routes when stopping the tunnel.
func CleanupRoutes(ifaceName, endpointIP string, prefixes []string) {
	if ep := net.ParseIP(strings.TrimSpace(endpointIP)); ep != nil && ep.To4() != nil {
		_, _ = runHidden("route", "delete", ep.To4().String(), "mask", "255.255.255.255")
	}
	for _, p := range prefixes {
		_, _ = runHidden("netsh", "interface", "ipv4", "delete", "route",
			fmt.Sprintf("prefix=%s", p), fmt.Sprintf("interface=%s", ifaceName), "store=active")
	}
}
