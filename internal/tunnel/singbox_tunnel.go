package tunnel

import (
	"abiroute/internal/config"
	"abiroute/internal/netwin"
	"abiroute/internal/proxy"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type SingBoxConfig struct {
	RawURI   string
	MTU      int
	Routes   []string
	PhysNIC  *netwin.PhysicalNIC
	OnStatus func(msg string)
}

type SingBoxTunnel struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	ifaceName  string
	endpointIP string
	physNIC    *netwin.PhysicalNIC
	applied    []string
	confPath   string
	rxTotal    atomic.Uint64
	txTotal    atomic.Uint64
	startedTS  int64
}

func pickFreeLocalPort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func pidFilePath() string {
	return filepath.Join(config.DataDir(), "singbox.pid")
}

// CleanupStaleSingBox kills any orphaned sing-box child process from an earlier crash.
func CleanupStaleSingBox() {
	raw, err := os.ReadFile(pidFilePath())
	if err != nil {
		return
	}
	_ = os.Remove(pidFilePath())
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

func StartSingBox(ctx context.Context, cfg SingBoxConfig) (*SingBoxTunnel, error) {
	if err := EnsureWintunDLL(); err != nil {
		return nil, err
	}
	parsed, err := proxy.ParseURI(cfg.RawURI, "")
	if err != nil {
		return nil, err
	}

	sbExe, err := proxy.EnsureSingBoxBinary(ctx, cfg.OnStatus)
	if err != nil {
		return nil, err
	}
	// Ensure wintun.dll is also present right beside sing-box.exe
	exeSelf, _ := os.Executable()
	if srcWintun := filepath.Join(filepath.Dir(exeSelf), "wintun.dll"); srcWintun != "" {
		if raw, err := os.ReadFile(srcWintun); err == nil {
			_ = os.WriteFile(filepath.Join(filepath.Dir(sbExe), "wintun.dll"), raw, 0o644)
		}
	}

	ips, err := net.LookupIP(parsed.Node.Server)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("не удалось разрешить адрес сервера %s: %w", parsed.Node.Server, err)
	}
	var epIPv4 string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			epIPv4 = v4.String()
			break
		}
	}
	if epIPv4 == "" {
		epIPv4 = parsed.Node.Server
	}

	bindIP := ""
	if cfg.PhysNIC != nil {
		bindIP = cfg.PhysNIC.IP
	}
	clashPort := pickFreeLocalPort()

	confBytes, err := proxy.BuildSingBoxConfig(parsed, InterfaceName, cfg.MTU, bindIP, clashPort)
	if err != nil {
		return nil, err
	}

	confPath := filepath.Join(config.DataDir(), "singbox_run.json")
	if err := os.WriteFile(confPath, confBytes, 0o600); err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(runCtx, sbExe, "run", "-c", confPath)
	hideCmdWindow(cmd)
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("не удалось запустить sing-box: %w", err)
	}
	_ = os.WriteFile(pidFilePath(), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)

	// Wait ~1.2s for sing-box to bring up Wintun interface ABIRoute (or fail fast if config rejected)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	select {
	case waitErr := <-exited:
		cancel()
		_ = os.Remove(pidFilePath())
		msg := strings.TrimSpace(stderrBuf.String())
		if msg == "" && waitErr != nil {
			msg = waitErr.Error()
		}
		return nil, fmt.Errorf("ядро VLESS/Hysteria2 завершилось с ошибкой: %s", msg)
	case <-time.After(1400 * time.Millisecond):
	}

	cleanRoutes := netwin.NormalizePrefixes(cfg.Routes, epIPv4)
	if err := netwin.SyncRoutes(InterfaceName, epIPv4, cfg.PhysNIC, cleanRoutes, nil); err != nil {
		cancel()
		_ = cmd.Process.Kill()
		_ = os.Remove(pidFilePath())
		return nil, err
	}

	t := &SingBoxTunnel{
		cmd:        cmd,
		cancel:     cancel,
		ifaceName:  InterfaceName,
		endpointIP: epIPv4,
		physNIC:    cfg.PhysNIC,
		applied:    cleanRoutes,
		confPath:   confPath,
		startedTS:  time.Now().Unix(),
	}

	if clashPort > 0 {
		go t.streamTraffic(runCtx, clashPort)
	}
	return t, nil
}

func hideCmdWindow(cmd *exec.Cmd) {
	setSysProcHide(cmd)
}

func (t *SingBoxTunnel) streamTraffic(ctx context.Context, port int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/traffic", port), nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var sample struct {
			Up   uint64 `json:"up"`
			Down uint64 `json:"down"`
		}
		if json.Unmarshal(sc.Bytes(), &sample) == nil {
			t.txTotal.Add(sample.Up)
			t.rxTotal.Add(sample.Down)
		}
	}
}

func (t *SingBoxTunnel) UpdateRoutes(desiredPrefixes []string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	clean := netwin.NormalizePrefixes(desiredPrefixes, t.endpointIP)
	if err := netwin.SyncRoutes(t.ifaceName, t.endpointIP, t.physNIC, clean, t.applied); err != nil {
		return err
	}
	t.applied = clean
	return nil
}

func (t *SingBoxTunnel) AppliedRoutes() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make([]string, len(t.applied))
	copy(cp, t.applied)
	return cp
}

func (t *SingBoxTunnel) Stats() Stats {
	return Stats{
		RxBytes:          t.rxTotal.Load(),
		TxBytes:          t.txTotal.Load(),
		LastHandshakeSec: t.startedTS,
		Connected:        t.startedTS > 0,
	}
}

func (t *SingBoxTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Signal(syscall.SIGTERM)
		_ = t.cmd.Process.Kill()
	}
	_ = os.Remove(pidFilePath())
	netwin.CleanupRoutes(t.ifaceName, t.endpointIP, t.applied)
	return nil
}
