//go:build windows

package tray

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmApp              = 0x8000
	wmTrayCallback     = wmApp + 1
	wmSyncHotkey       = wmApp + 2
	wmQuitLoop         = 0x0012 // WM_QUIT
	wmCommand          = 0x0111
	wmHotkey           = 0x0312
	wmLButtonUp        = 0x0202
	wmLButtonDblClk    = 0x0203
	wmRButtonUp        = 0x0205

	nimAdd             = 0x00000000
	nimModify          = 0x00000001
	nimDelete          = 0x00000002
	nifMessage         = 0x00000001
	nifIcon            = 0x00000002
	nifTip             = 0x00000004

	mfString           = 0x00000000
	mfSeparator        = 0x00000800
	tpmRightButton     = 0x0002
	tpmReturnCmd       = 0x0100
	tpmBottomAlign     = 0x0020

	modAltNoRepeat     = 0x4001 // MOD_ALT | MOD_NOREPEAT
	vkF9               = 0x78
	hotkeyID           = 9001

	cmdOpen            = 1001
	cmdToggleBoost     = 1002
	cmdQuit            = 1003
)

var (
	modUser32Tray          = windows.NewLazySystemDLL("user32.dll")
	modShell32Tray         = windows.NewLazySystemDLL("shell32.dll")
	modKernel32Tray        = windows.NewLazySystemDLL("kernel32.dll")

	procGetModuleHandleW   = modKernel32Tray.NewProc("GetModuleHandleW")
	procBeep               = modKernel32Tray.NewProc("Beep")
	procRegisterClassExW   = modUser32Tray.NewProc("RegisterClassExW")
	procCreateWindowExW    = modUser32Tray.NewProc("CreateWindowExW")
	procDefWindowProcW     = modUser32Tray.NewProc("DefWindowProcW")
	procDestroyWindow      = modUser32Tray.NewProc("DestroyWindow")
	procGetMessageW        = modUser32Tray.NewProc("GetMessageW")
	procTranslateMessage   = modUser32Tray.NewProc("TranslateMessage")
	procDispatchMessageW   = modUser32Tray.NewProc("DispatchMessageW")
	procPostMessageW       = modUser32Tray.NewProc("PostMessageW")
	procPostQuitMessage    = modUser32Tray.NewProc("PostQuitMessage")
	procLoadImageW         = modUser32Tray.NewProc("LoadImageW")
	procLoadIconW          = modUser32Tray.NewProc("LoadIconW")
	procCreatePopupMenu    = modUser32Tray.NewProc("CreatePopupMenu")
	procAppendMenuW        = modUser32Tray.NewProc("AppendMenuW")
	procSetMenuDefaultItem = modUser32Tray.NewProc("SetMenuDefaultItem")
	procDestroyMenu        = modUser32Tray.NewProc("DestroyMenu")
	procGetCursorPos       = modUser32Tray.NewProc("GetCursorPos")
	procSetForegroundWin   = modUser32Tray.NewProc("SetForegroundWindow")
	procTrackPopupMenu     = modUser32Tray.NewProc("TrackPopupMenu")
	procRegisterHotKey     = modUser32Tray.NewProc("RegisterHotKey")
	procUnregisterHotKey   = modUser32Tray.NewProc("UnregisterHotKey")
	procShellNotifyIconW   = modShell32Tray.NewProc("Shell_NotifyIconW")

	activeMgrMu sync.RWMutex
	activeMgr   *Manager
	wndProcOnce sync.Once
	wndProcPtr  uintptr
)

type Callbacks struct {
	OnShowWindow  func()
	OnToggleBoost func()
	OnQuit        func()
}

type Manager struct {
	mu            sync.RWMutex
	cb            Callbacks
	hwnd          uintptr
	hIcon         uintptr
	boosted       bool
	tooltip       string
	hotkeyEnabled bool
	readyCh       chan struct{}
}

func getWndProc() uintptr {
	wndProcOnce.Do(func() {
		wndProcPtr = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
			activeMgrMu.RLock()
			m := activeMgr
			activeMgrMu.RUnlock()
			if m != nil {
				switch uint32(msg) {
				case wmTrayCallback:
					ev := uint32(lParam & 0xFFFF)
					if ev == wmLButtonUp || ev == wmLButtonDblClk {
						if m.cb.OnShowWindow != nil {
							go m.cb.OnShowWindow()
						}
						return 0
					}
					if ev == wmRButtonUp {
						m.showContextMenu(hwnd)
						return 0
					}
				case wmHotkey:
					if wParam == hotkeyID && m.cb.OnToggleBoost != nil {
						go m.cb.OnToggleBoost()
						return 0
					}
				case wmSyncHotkey:
					m.applyHotkeyOnThread(hwnd)
					return 0
				}
			}
			r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
			return r
		})
	})
	return wndProcPtr
}

func NewManager(cb Callbacks, initialHotkey bool) *Manager {
	m := &Manager{
		cb:            cb,
		tooltip:       "ABI Route 5.0 — Готов к ускорению",
		hotkeyEnabled: initialHotkey,
		readyCh:       make(chan struct{}),
	}
	activeMgrMu.Lock()
	activeMgr = m
	activeMgrMu.Unlock()

	go m.loop()
	return m
}

func (m *Manager) loop() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInst, _, _ := procGetModuleHandleW.Call(0)
	clsName, _ := syscall.UTF16PtrFromString("ABIRouteTrayHiddenWnd")

	// WNDCLASSEXW on amd64: size=80, lpfnWndProc=8, hInstance=24, lpszClassName=64
	var wc [80]byte
	*(*uint32)(unsafe.Pointer(&wc[0])) = 80
	*(*uintptr)(unsafe.Pointer(&wc[8])) = getWndProc()
	*(*uintptr)(unsafe.Pointer(&wc[24])) = hInst
	*(*uintptr)(unsafe.Pointer(&wc[64])) = uintptr(unsafe.Pointer(clsName))
	_, _, _ = procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc[0])))

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(clsName)),
		uintptr(unsafe.Pointer(clsName)),
		0,
		0, 0, 0, 0,
		^uintptr(2), // HWND_MESSAGE = (HWND)-3
		0,
		hInst,
		0,
	)
	if hwnd == 0 {
		close(m.readyCh)
		return
	}

	// Load embedded resource ID 100 from winres/abiroute.rc (fallback to IDI_APPLICATION = 32512)
	hIcon, _, _ := procLoadImageW.Call(hInst, 100, 1, 0, 0, 0x00000040)
	if hIcon == 0 {
		hIcon, _, _ = procLoadIconW.Call(0, 32512)
	}

	m.mu.Lock()
	m.hwnd = hwnd
	m.hIcon = hIcon
	tip := m.tooltip
	m.mu.Unlock()

	nid := buildNID(hwnd, hIcon, tip)
	_, _, _ = procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid[0])))
	m.applyHotkeyOnThread(hwnd)
	close(m.readyCh)

	// MSG on amd64 = 48 bytes
	var msg [48]byte
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg[0])))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg[0])))
	}

	del := buildNID(hwnd, hIcon, "")
	_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&del[0])))
	_, _, _ = procUnregisterHotKey.Call(hwnd, hotkeyID)
	_, _, _ = procDestroyWindow.Call(hwnd)
}

func buildNID(hwnd, hIcon uintptr, tip string) [976]byte {
	// NOTIFYICONDATAW on amd64: size=976, hWnd=8, uID=16, uFlags=20, uCallbackMessage=24, hIcon=32, szTip=40
	var nid [976]byte
	*(*uint32)(unsafe.Pointer(&nid[0])) = 976
	*(*uintptr)(unsafe.Pointer(&nid[8])) = hwnd
	*(*uint32)(unsafe.Pointer(&nid[16])) = 1
	*(*uint32)(unsafe.Pointer(&nid[20])) = nifMessage | nifIcon | nifTip
	*(*uint32)(unsafe.Pointer(&nid[24])) = wmTrayCallback
	*(*uintptr)(unsafe.Pointer(&nid[32])) = hIcon

	if tip != "" {
		utf16Tip, _ := syscall.UTF16FromString(tip)
		if len(utf16Tip) > 127 {
			utf16Tip = utf16Tip[:127]
			utf16Tip[126] = 0
		}
		dst := unsafe.Slice((*uint16)(unsafe.Pointer(&nid[40])), 128)
		copy(dst, utf16Tip)
	}
	return nid
}

func (m *Manager) applyHotkeyOnThread(hwnd uintptr) {
	m.mu.RLock()
	en := m.hotkeyEnabled
	m.mu.RUnlock()
	_, _, _ = procUnregisterHotKey.Call(hwnd, hotkeyID)
	if en {
		_, _, _ = procRegisterHotKey.Call(hwnd, hotkeyID, modAltNoRepeat, vkF9)
	}
}

func (m *Manager) showContextMenu(hwnd uintptr) {
	m.mu.RLock()
	boosted := m.boosted
	tip := m.tooltip
	m.mu.RUnlock()

	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	lblOpen, _ := syscall.UTF16PtrFromString("Открыть ABI Route")
	toggleStr := "Ускорить в 1 клик (Alt+F9)"
	if boosted {
		toggleStr = "Остановить туннель (Alt+F9)"
	}
	lblToggle, _ := syscall.UTF16PtrFromString(toggleStr)
	lblTip, _ := syscall.UTF16PtrFromString(tip)
	lblQuit, _ := syscall.UTF16PtrFromString("Выключить и выйти")

	_, _, _ = procAppendMenuW.Call(hMenu, mfString, cmdOpen, uintptr(unsafe.Pointer(lblOpen)))
	_, _, _ = procSetMenuDefaultItem.Call(hMenu, cmdOpen, 0)
	_, _, _ = procAppendMenuW.Call(hMenu, mfString|0x00000001, 0, uintptr(unsafe.Pointer(lblTip))) // disabled info line
	_, _, _ = procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	_, _, _ = procAppendMenuW.Call(hMenu, mfString, cmdToggleBoost, uintptr(unsafe.Pointer(lblToggle)))
	_, _, _ = procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	_, _, _ = procAppendMenuW.Call(hMenu, mfString, cmdQuit, uintptr(unsafe.Pointer(lblQuit)))

	var pt struct{ X, Y int32 }
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForegroundWin.Call(hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(
		hMenu,
		tpmRightButton|tpmReturnCmd|tpmBottomAlign,
		uintptr(pt.X),
		uintptr(pt.Y),
		0,
		hwnd,
		0,
	)

	switch cmd {
	case cmdOpen:
		if m.cb.OnShowWindow != nil {
			go m.cb.OnShowWindow()
		}
	case cmdToggleBoost:
		if m.cb.OnToggleBoost != nil {
			go m.cb.OnToggleBoost()
		}
	case cmdQuit:
		if m.cb.OnQuit != nil {
			go m.cb.OnQuit()
		}
	}
}

func (m *Manager) UpdateState(boosted bool, tooltip string) {
	m.mu.Lock()
	m.boosted = boosted
	if tooltip != "" {
		m.tooltip = tooltip
	}
	hwnd := m.hwnd
	hIcon := m.hIcon
	tip := m.tooltip
	m.mu.Unlock()

	if hwnd != 0 {
		nid := buildNID(hwnd, hIcon, tip)
		_, _, _ = procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid[0])))
	}
}

func (m *Manager) SetHotkeyEnabled(enabled bool) {
	m.mu.Lock()
	m.hotkeyEnabled = enabled
	hwnd := m.hwnd
	m.mu.Unlock()
	if hwnd != 0 {
		_, _, _ = procPostMessageW.Call(hwnd, wmSyncHotkey, 0, 0)
	}
}

func PlayTone(activating bool) {
	if activating {
		_, _, _ = procBeep.Call(880, 85)
	} else {
		_, _, _ = procBeep.Call(440, 100)
	}
}

func (m *Manager) Close() {
	m.mu.RLock()
	hwnd := m.hwnd
	m.mu.RUnlock()
	if hwnd != 0 {
		_, _, _ = procPostMessageW.Call(hwnd, wmQuitLoop, 0, 0)
	}
}
