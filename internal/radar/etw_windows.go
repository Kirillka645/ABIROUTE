//go:build windows

package radar

import (
	"abiroute/internal/netwin"
	"encoding/binary"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Microsoft-Windows-Kernel-Network GUID: {7DD42A49-5329-4832-8DFD-43D979153A88}
var guidKernelNetwork = windows.GUID{
	Data1: 0x7dd42a49,
	Data2: 0x5329,
	Data3: 0x4832,
	Data4: [8]byte{0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88},
}

// Unique session GUID for ABIRoute ETW trace
var guidABIRouteSession = windows.GUID{
	Data1: 0x91a8c4e1,
	Data2: 0x62b4,
	Data3: 0x4f09,
	Data4: [8]byte{0xa3, 0x19, 0x77, 0x5e, 0x20, 0x4b, 0x81, 0x04},
}

const (
	etwSessionName               = "ABIRouteKernelNetTrace"
	wnodeFlagTracedGuid          = 0x00020000
	eventTraceRealTimeMode       = 0x00000100
	processTraceModeRealTime     = 0x00000100
	processTraceModeEventRecord  = 0x10000000
	eventControlCodeEnable       = 1
	eventControlCodeDisable      = 0
	eventTraceControlStop        = 1
	traceLevelInformation        = 4
	keywordKernelNetworkIPv4     = 0x10 // KERNEL_NETWORK_KEYWORD_IPV4
)

var (
	modAdvapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW      = modAdvapi32.NewProc("StartTraceW")
	procControlTraceW    = modAdvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2   = modAdvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW       = modAdvapi32.NewProc("OpenTraceW")
	procProcessTrace     = modAdvapi32.NewProc("ProcessTrace")
	procCloseTrace       = modAdvapi32.NewProc("CloseTrace")

	globalETWCallbackOnce sync.Once
	globalETWCallbackPtr  uintptr
	globalETWConsumerMu   sync.RWMutex
	globalETWConsumer     func(pid uint32, dstIP string, dstPort int, proto string)
)

func getETWCallback() uintptr {
	globalETWCallbackOnce.Do(func() {
		globalETWCallbackPtr = syscall.NewCallback(func(recPtr uintptr) uintptr {
			if recPtr == 0 {
				return 0
			}
			// Verified x64 EVENT_RECORD offsets:
			// ProcessId = 12, ProviderId = 24, Id = 40, UserDataLength = 86, UserData = 96
			rec := unsafe.Slice((*byte)(unsafe.Pointer(recPtr)), 112)
			eventID := binary.LittleEndian.Uint16(rec[40:42])
			// Kernel-Network IPv4 outbound events:
			// 10 = TcpIpSendIPV4, 12 = TcpIpConnectIPV4, 42 = UdpIpSendIPV4, 43 = UdpIpRecvIPV4
			var proto string
			switch eventID {
			case 42, 43:
				proto = "UDP"
			case 10, 12:
				proto = "TCP"
			default:
				return 0
			}

			hdrPID := binary.LittleEndian.Uint32(rec[12:16])
			dataLen := binary.LittleEndian.Uint16(rec[86:88])
			userDataPtr := *(*uintptr)(unsafe.Pointer(&rec[96]))
			if userDataPtr == 0 || dataLen < 20 {
				return 0
			}

			// Microsoft-Windows-Kernel-Network IPv4 template:
			// [0:4] PID (uint32 LE), [4:8] size (uint32 LE), [8:12] daddr (IPv4), [12:16] saddr (IPv4), [16:18] dport (BE), [18:20] sport (BE)
			payload := unsafe.Slice((*byte)(unsafe.Pointer(userDataPtr)), dataLen)
			pid := binary.LittleEndian.Uint32(payload[0:4])
			if pid == 0 {
				pid = hdrPID
			}

			var dstBytes [4]byte
			copy(dstBytes[:], payload[8:12])
			dstAddr := netip.AddrFrom4(dstBytes)
			dport := int(binary.BigEndian.Uint16(payload[16:18]))

			// For inbound event 43 (UdpIpRecvIPV4), saddr is remote server if daddr is local
			if !netwin.IsPublicIPv4(dstAddr) {
				var srcBytes [4]byte
				copy(srcBytes[:], payload[12:16])
				srcAddr := netip.AddrFrom4(srcBytes)
				if netwin.IsPublicIPv4(srcAddr) {
					dstAddr = srcAddr
					dport = int(binary.BigEndian.Uint16(payload[18:20]))
				} else {
					return 0
				}
			}

			globalETWConsumerMu.RLock()
			fn := globalETWConsumer
			globalETWConsumerMu.RUnlock()
			if fn != nil {
				fn(pid, dstAddr.String(), dport, proto)
			}
			return 0
		})
	})
	return globalETWCallbackPtr
}

type etwSession struct {
	sessionHandle uintptr
	traceHandle   uintptr
	propsBuf      []byte
}

func makeTraceProperties() ([]byte, *uint16) {
	nameUTF16, _ := syscall.UTF16FromString(etwSessionName)
	nameBytes := len(nameUTF16) * 2
	// EVENT_TRACE_PROPERTIES on amd64 = 120 bytes
	totalSize := 120 + nameBytes + 16
	buf := make([]byte, totalSize)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalSize))                 // Wnode.BufferSize
	*(*windows.GUID)(unsafe.Pointer(&buf[24])) = guidABIRouteSession           // Wnode.Guid
	binary.LittleEndian.PutUint32(buf[40:44], 1)                               // Wnode.ClientContext = QPC
	binary.LittleEndian.PutUint32(buf[44:48], wnodeFlagTracedGuid)             // Wnode.Flags
	binary.LittleEndian.PutUint32(buf[64:68], eventTraceRealTimeMode)          // LogFileMode
	binary.LittleEndian.PutUint32(buf[116:120], 120)                           // LoggerNameOffset

	dstName := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[120])), len(nameUTF16))
	copy(dstName, nameUTF16)
	return buf, &nameUTF16[0]
}

func startETWSession(onPacket func(pid uint32, dstIP string, dstPort int, proto string)) (*etwSession, error) {
	// Stop any leftover session from a previous crash
	stopBuf, stopName := makeTraceProperties()
	_, _, _ = procControlTraceW.Call(0, uintptr(unsafe.Pointer(stopName)), uintptr(unsafe.Pointer(&stopBuf[0])), eventTraceControlStop)

	propsBuf, namePtr := makeTraceProperties()
	var sessHandle uintptr
	ret, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&sessHandle)),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&propsBuf[0])),
	)
	if ret != 0 {
		return nil, syscall.Errno(ret)
	}

	ret, _, _ = procEnableTraceEx2.Call(
		sessHandle,
		uintptr(unsafe.Pointer(&guidKernelNetwork)),
		eventControlCodeEnable,
		traceLevelInformation,
		keywordKernelNetworkIPv4,
		0,
		0,
		0,
	)
	if ret != 0 {
		_, _, _ = procControlTraceW.Call(sessHandle, 0, uintptr(unsafe.Pointer(&propsBuf[0])), eventTraceControlStop)
		return nil, syscall.Errno(ret)
	}

	globalETWConsumerMu.Lock()
	globalETWConsumer = onPacket
	globalETWConsumerMu.Unlock()

	// EVENT_TRACE_LOGFILEW on amd64 = 448 bytes:
	// LoggerName = offset 8, ProcessTraceMode = offset 28, EventRecordCallback = offset 424
	var logfile [448]byte
	nameUTF16, _ := syscall.UTF16PtrFromString(etwSessionName)
	*(*uintptr)(unsafe.Pointer(&logfile[8])) = uintptr(unsafe.Pointer(nameUTF16))
	binary.LittleEndian.PutUint32(logfile[28:32], processTraceModeRealTime|processTraceModeEventRecord)
	*(*uintptr)(unsafe.Pointer(&logfile[424])) = getETWCallback()

	traceHandle, _, openErr := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile[0])))
	if traceHandle == ^uintptr(0) || traceHandle == 0 {
		_, _, _ = procControlTraceW.Call(sessHandle, 0, uintptr(unsafe.Pointer(&propsBuf[0])), eventTraceControlStop)
		return nil, openErr
	}

	s := &etwSession{
		sessionHandle: sessHandle,
		traceHandle:   traceHandle,
		propsBuf:      propsBuf,
	}

	go func(th uintptr) {
		handleArr := [1]uintptr{th}
		_, _, _ = procProcessTrace.Call(uintptr(unsafe.Pointer(&handleArr[0])), 1, 0, 0)
	}(traceHandle)

	return s, nil
}

func (s *etwSession) stop() {
	if s == nil {
		return
	}
	globalETWConsumerMu.Lock()
	globalETWConsumer = nil
	globalETWConsumerMu.Unlock()

	if s.traceHandle != 0 && s.traceHandle != ^uintptr(0) {
		_, _, _ = procCloseTrace.Call(s.traceHandle)
		s.traceHandle = 0
	}
	if s.sessionHandle != 0 {
		_, _, _ = procEnableTraceEx2.Call(
			s.sessionHandle,
			uintptr(unsafe.Pointer(&guidKernelNetwork)),
			eventControlCodeDisable,
			0, 0, 0, 0, 0,
		)
		stopBuf, _ := makeTraceProperties()
		_, _, _ = procControlTraceW.Call(s.sessionHandle, 0, uintptr(unsafe.Pointer(&stopBuf[0])), eventTraceControlStop)
		s.sessionHandle = 0
	}
}
