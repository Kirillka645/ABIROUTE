//go:build windows

package radar

import (
	"abiroute/internal/netwin"
	"encoding/binary"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afInet              = 2
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
)

var (
	modIphlpRadar            = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable  = modIphlpRadar.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable  = modIphlpRadar.NewProc("GetExtendedUdpTable")
)

type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type Tracker struct {
	mu           sync.RWMutex
	wantedNames  map[string]struct{}
	activePIDs   map[uint32]struct{}
	hits         map[string]*EndpointHit
	etw          *etwSession
	stopCh       chan struct{}
	running      bool
	excludeIP    string
	onNewServer  func(hit EndpointHit)
	onGameToggle func(running bool)
	lastGameOn   bool
}

func NewTracker(onNewServer func(hit EndpointHit), onGameToggle func(running bool)) *Tracker {
	return &Tracker{
		wantedNames:  map[string]struct{}{},
		activePIDs:   map[uint32]struct{}{},
		hits:         map[string]*EndpointHit{},
		onNewServer:  onNewServer,
		onGameToggle: onGameToggle,
	}
}

func (t *Tracker) SetTargetProcesses(names []string, excludeEndpointIP string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		clean := strings.ToLower(strings.TrimSpace(n))
		if clean != "" {
			m[clean] = struct{}{}
		}
	}
	t.wantedNames = m
	t.excludeIP = strings.TrimSpace(excludeEndpointIP)
}

func (t *Tracker) Start() {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return
	}
	t.running = true
	t.stopCh = make(chan struct{})
	t.mu.Unlock()

	// Refresh PID table immediately before ETW starts
	t.pollProcessesAndTables()

	if netwin.IsAdmin() {
		if sess, err := startETWSession(t.handleETWPacket); err == nil {
			t.mu.Lock()
			t.etw = sess
			t.mu.Unlock()
		}
	}

	go func(stop <-chan struct{}) {
		ticker := time.NewTicker(1500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				t.pollProcessesAndTables()
			}
		}
	}(t.stopCh)
}

func (t *Tracker) Stop() {
	t.mu.Lock()
	if !t.running {
		t.mu.Unlock()
		return
	}
	t.running = false
	close(t.stopCh)
	etw := t.etw
	t.etw = nil
	t.mu.Unlock()

	if etw != nil {
		etw.stop()
	}
}

func (t *Tracker) handleETWPacket(pid uint32, dstIP string, dstPort int, proto string) {
	t.mu.RLock()
	_, wanted := t.activePIDs[pid]
	exIP := t.excludeIP
	t.mu.RUnlock()
	if !wanted || dstIP == exIP {
		return
	}
	t.recordHit(dstIP, dstPort, proto, 1)
}

func (t *Tracker) recordHit(ip string, port int, proto string, minNewPackets int) {
	now := time.Now().Unix()
	var notify *EndpointHit

	t.mu.Lock()
	h, exists := t.hits[ip]
	if !exists {
		role := "Сервер рейда (UDP)"
		if proto == "TCP" {
			role = "Лобби / Матчмейкинг"
		}
		h = &EndpointHit{
			IP:       ip,
			Port:     port,
			Proto:    proto,
			Role:     role,
			Packets:  1,
			LastSeen: now,
		}
		t.hits[ip] = h
		if minNewPackets <= 1 {
			cp := *h
			notify = &cp
		}
	} else {
		prevPkts := h.Packets
		h.Packets++
		h.LastSeen = now
		if proto == "UDP" && h.Proto != "UDP" {
			h.Proto = "UDP"
			h.Role = "Сервер рейда (UDP)"
			h.Port = port
		}
		// Trigger UDP discovery once >= 3 packets confirm real raid/match traffic (filters stray DNS/STUN noise)
		if prevPkts == 2 && h.Packets == 3 {
			cp := *h
			notify = &cp
		}
	}
	t.mu.Unlock()

	if notify != nil && t.onNewServer != nil {
		t.onNewServer(*notify)
	}
}

func (t *Tracker) pollProcessesAndTables() {
	t.mu.RLock()
	wanted := make(map[string]struct{}, len(t.wantedNames))
	for k, v := range t.wantedNames {
		wanted[k] = v
	}
	exIP := t.excludeIP
	t.mu.RUnlock()

	if len(wanted) == 0 {
		return
	}

	pids := findProcessPIDs(wanted)
	gameOn := len(pids) > 0

	t.mu.Lock()
	t.activePIDs = pids
	changed := gameOn != t.lastGameOn
	t.lastGameOn = gameOn
	t.mu.Unlock()

	if changed && t.onGameToggle != nil {
		t.onGameToggle(gameOn)
	}
	if !gameOn {
		return
	}

	// Scan active IPv4 TCP connections belonging to game PIDs
	for _, ep := range scanTCPConnections(pids) {
		if ep.ip != exIP {
			t.recordHit(ep.ip, ep.port, "TCP", 1)
		}
	}
}

func findProcessPIDs(wantedLower map[string]struct{}) map[uint32]struct{} {
	out := map[uint32]struct{}{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return out
	}
	for {
		exeName := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		if _, ok := wantedLower[exeName]; ok {
			out[pe.ProcessID] = struct{}{}
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return out
}

type tcpRemote struct {
	ip   string
	port int
}

func scanTCPConnections(pids map[uint32]struct{}) []tcpRemote {
	var size uint32 = 32768
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet,
		tcpTableOwnerPidAll,
		0,
	)
	if ret == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		buf = make([]byte, size)
		ret, _, _ = procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			afInet,
			tcpTableOwnerPidAll,
			0,
		)
	}
	if ret != 0 || len(buf) < 4 {
		return nil
	}

	count := binary.LittleEndian.Uint32(buf[:4])
	rowSize := unsafe.Sizeof(mibTcpRowOwnerPid{})
	var out []tcpRemote
	for i := uint32(0); i < count; i++ {
		off := uintptr(4) + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := *(*mibTcpRowOwnerPid)(unsafe.Pointer(&buf[off]))
		if _, ok := pids[row.OwningPid]; !ok || row.RemoteAddr == 0 {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], row.RemoteAddr)
		addr := netip.AddrFrom4(b)
		if !netwin.IsPublicIPv4(addr) {
			continue
		}
		port := int(binary.BigEndian.Uint16([]byte{byte(row.RemotePort), byte(row.RemotePort >> 8)}))
		out = append(out, tcpRemote{ip: addr.String(), port: port})
	}
	return out
}

// ActiveUDPInPrefixes reports whether any game UDP server in the given subnets was active within `withinSec`.
func (t *Tracker) ActiveUDPInPrefixes(prefixes []string, withinSec int64) bool {
	if len(prefixes) == 0 {
		return false
	}
	cutoff := time.Now().Unix() - withinSec
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, h := range t.hits {
		if h.Proto == "UDP" && h.Packets >= 12 && h.LastSeen >= cutoff && netwin.InPrefixes(h.IP, prefixes) {
			return true
		}
	}
	return false
}

func (t *Tracker) Snapshot() Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pids := make([]uint32, 0, len(t.activePIDs))
	for p := range t.activePIDs {
		pids = append(pids, p)
	}
	hits := make([]EndpointHit, 0, len(t.hits))
	for _, h := range t.hits {
		hits = append(hits, *h)
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].LastSeen > hits[j].LastSeen })
	if len(hits) > 30 {
		hits = hits[:30]
	}
	return Snapshot{
		GameRunning: len(pids) > 0,
		ActivePIDs:  pids,
		ETWActive:   t.etw != nil,
		Hits:        hits,
	}
}
