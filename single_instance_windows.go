//go:build windows

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	singleMutexHandle windows.Handle
	modUser32         = windows.NewLazySystemDLL("user32.dll")
	procFindWindowW   = modUser32.NewProc("FindWindowW")
	procShowWindow    = modUser32.NewProc("ShowWindow")
	procSetForeground = modUser32.NewProc("SetForegroundWindow")
)

func acquireSingleInstance() bool {
	name, err := syscall.UTF16PtrFromString(`Local\ABIRouteV4SingleInstance`)
	if err != nil {
		return true
	}
	h, err := windows.CreateMutex(nil, false, name)
	if err == windows.ERROR_ALREADY_EXISTS {
		title, _ := syscall.UTF16PtrFromString("ABI Route 4.0 — Smart Game Booster")
		hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(title)))
		if hwnd != 0 {
			procShowWindow.Call(hwnd, 9) // SW_RESTORE
			procSetForeground.Call(hwnd)
		}
		return false
	}
	singleMutexHandle = h
	return true
}
