//go:build windows

package tunnel

import (
	_ "embed"
	"os"
	"path/filepath"
	"sync"
)

//go:embed embed/wintun_amd64.dll
var embeddedWintunDLL []byte

var wintunOnce sync.Once

// EnsureWintunDLL extracts the WHQL-signed wintun.dll next to the executable (or System32 fallback)
// so golang.zx2c4.com/wintun finds it via LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32.
func EnsureWintunDLL() error {
	var outErr error
	wintunOnce.Do(func() {
		if len(embeddedWintunDLL) == 0 {
			return
		}
		exePath, err := os.Executable()
		if err == nil {
			appDll := filepath.Join(filepath.Dir(exePath), "wintun.dll")
			if st, err := os.Stat(appDll); err == nil && st.Size() > 100_000 {
				return
			}
			if err := os.WriteFile(appDll, embeddedWintunDLL, 0o644); err == nil {
				return
			}
		}
		sysRoot := os.Getenv("SystemRoot")
		if sysRoot == "" {
			sysRoot = `C:\Windows`
		}
		sysDll := filepath.Join(sysRoot, "System32", "wintun.dll")
		if st, err := os.Stat(sysDll); err == nil && st.Size() > 100_000 {
			return
		}
		outErr = os.WriteFile(sysDll, embeddedWintunDLL, 0o644)
	})
	return outErr
}
