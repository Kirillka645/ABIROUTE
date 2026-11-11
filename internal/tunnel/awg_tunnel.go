package tunnel

import (
	"abiroute/internal/netwin"
	"abiroute/internal/obf"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type AWGConfig struct {
	PrivateKeyB64 string
	PeerPubKeyB64 string
	PresharedB64  string
	AddressV4     string
	Endpoint      string
	MTU           int
	Profile       obf.Profile
	CustomS       map[string]int
	CustomH       map[string]string
	CustomI       map[string]string
	Routes        []string
	PhysNIC       *netwin.PhysicalNIC
}

type AWGTunnel struct {
	mu         sync.Mutex
	tunDev     tun.Device
	dev        *device.Device
	ifaceName  string
	endpointIP string
	peerHex    string
	physNIC    *netwin.PhysicalNIC
	applied    []string
}

func b64KeyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid 32-byte base64 key")
	}
	return hex.EncodeToString(raw), nil
}

func StartAWG(cfg AWGConfig) (*AWGTunnel, error) {
	if err := EnsureWintunDLL(); err != nil {
		return nil, fmt.Errorf("не удалось подготовить драйвер Wintun: %w", err)
	}

	privHex, err := b64KeyToHex(cfg.PrivateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("некорректный PrivateKey: %w", err)
	}
	peerHex, err := b64KeyToHex(cfg.PeerPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("некорректный PublicKey сервера: %w", err)
	}
	var pskHex string
	if strings.TrimSpace(cfg.PresharedB64) != "" {
		pskHex, err = b64KeyToHex(cfg.PresharedB64)
		if err != nil {
			return nil, fmt.Errorf("некорректный PresharedKey: %w", err)
		}
	}

	epHost, epPort, err := net.SplitHostPort(strings.TrimSpace(cfg.Endpoint))
	if err != nil {
		return nil, fmt.Errorf("неверный Endpoint %q: %w", cfg.Endpoint, err)
	}
	resolvedIPs, err := net.LookupIP(epHost)
	if err != nil || len(resolvedIPs) == 0 {
		return nil, fmt.Errorf("не удалось разрешить адрес узла %s: %w", epHost, err)
	}
	var epIPv4 string
	for _, ip := range resolvedIPs {
		if v4 := ip.To4(); v4 != nil {
			epIPv4 = v4.String()
			break
		}
	}
	if epIPv4 == "" {
		return nil, fmt.Errorf("узел %s не имеет IPv4-адреса", epHost)
	}
	resolvedEndpoint := net.JoinHostPort(epIPv4, epPort)

	mtu := cfg.MTU
	if mtu < 1200 || mtu > 1420 {
		mtu = 1280
	}

	tunDev, err := tun.CreateTUN(InterfaceName, mtu)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать адаптер Wintun (нужны права администратора): %w", err)
	}
	ifaceName, err := tunDev.Name()
	if err != nil || ifaceName == "" {
		ifaceName = InterfaceName
	}

	logger := device.NewLogger(device.LogLevelError, "[ABIRoute] ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	cleanRoutes := netwin.NormalizePrefixes(cfg.Routes, epIPv4)
	uapi := buildAWGUAPI(privHex, peerHex, pskHex, resolvedEndpoint, cfg, cleanRoutes)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("ошибка настройки параметров AmneziaWG: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("не удалось поднять устройство AmneziaWG: %w", err)
	}

	if err := netwin.ConfigureTunInterface(ifaceName, cfg.AddressV4, mtu); err != nil {
		dev.Close()
		return nil, err
	}
	if err := netwin.SyncRoutes(ifaceName, epIPv4, cfg.PhysNIC, cleanRoutes, nil); err != nil {
		dev.Close()
		return nil, err
	}

	return &AWGTunnel{
		tunDev:     tunDev,
		dev:        dev,
		ifaceName:  ifaceName,
		endpointIP: epIPv4,
		peerHex:    peerHex,
		physNIC:    cfg.PhysNIC,
		applied:    cleanRoutes,
	}, nil
}

func buildAWGUAPI(privHex, peerHex, pskHex, endpoint string, cfg AWGConfig, routes []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)

	jc, jmin, jmax := cfg.Profile.Jc, cfg.Profile.Jmin, cfg.Profile.Jmax
	if jc > 0 {
		fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\n", jc, jmin, jmax)
	}

	s1, s2 := cfg.Profile.S1, cfg.Profile.S2
	if v, ok := cfg.CustomS["S1"]; ok {
		s1 = v
	}
	if v, ok := cfg.CustomS["S2"]; ok {
		s2 = v
	}
	fmt.Fprintf(&b, "s1=%d\ns2=%d\n", s1, s2)
	if v, ok := cfg.CustomS["S3"]; ok {
		fmt.Fprintf(&b, "s3=%d\n", v)
	}
	if v, ok := cfg.CustomS["S4"]; ok {
		fmt.Fprintf(&b, "s4=%d\n", v)
	}

	h1, h2, h3, h4 := cfg.Profile.H1, cfg.Profile.H2, cfg.Profile.H3, cfg.Profile.H4
	if h1 == "" {
		h1, h2, h3, h4 = "1", "2", "3", "4"
	}
	if v := cfg.CustomH["H1"]; v != "" {
		h1 = v
	}
	if v := cfg.CustomH["H2"]; v != "" {
		h2 = v
	}
	if v := cfg.CustomH["H3"]; v != "" {
		h3 = v
	}
	if v := cfg.CustomH["H4"]; v != "" {
		h4 = v
	}
	fmt.Fprintf(&b, "h1=%s\nh2=%s\nh3=%s\nh4=%s\n", h1, h2, h3, h4)

	iMap := map[string]string{}
	for k, v := range cfg.Profile.I {
		iMap[k] = v
	}
	for k, v := range cfg.CustomI {
		iMap[k] = v
	}
	for idx := 1; idx <= 5; idx++ {
		key := fmt.Sprintf("I%d", idx)
		if spec := strings.TrimSpace(iMap[key]); spec != "" {
			fmt.Fprintf(&b, "i%d=%s\n", idx, spec)
		}
	}

	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", peerHex)
	if pskHex != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	b.WriteString("persistent_keepalive_interval=25\n")
	b.WriteString("replace_allowed_ips=true\n")
	for _, r := range routes {
		fmt.Fprintf(&b, "allowed_ip=%s\n", r)
	}
	return b.String()
}

func (t *AWGTunnel) UpdateRoutes(desiredPrefixes []string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	clean := netwin.NormalizePrefixes(desiredPrefixes, t.endpointIP)

	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", t.peerHex)
	b.WriteString("replace_allowed_ips=true\n")
	for _, r := range clean {
		fmt.Fprintf(&b, "allowed_ip=%s\n", r)
	}
	if err := t.dev.IpcSet(b.String()); err != nil {
		return err
	}
	if err := netwin.SyncRoutes(t.ifaceName, t.endpointIP, t.physNIC, clean, t.applied); err != nil {
		return err
	}
	t.applied = clean
	return nil
}

func (t *AWGTunnel) AppliedRoutes() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make([]string, len(t.applied))
	copy(cp, t.applied)
	return cp
}

func (t *AWGTunnel) Stats() Stats {
	var st Stats
	if t.dev == nil {
		return st
	}
	text, err := t.dev.IpcGet()
	if err != nil {
		return st
	}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			st.TxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "last_handshake_time_sec":
			st.LastHandshakeSec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	st.Connected = st.LastHandshakeSec > 0
	return st
}

func (t *AWGTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	netwin.CleanupRoutes(t.ifaceName, t.endpointIP, t.applied)
	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
	}
	return nil
}
