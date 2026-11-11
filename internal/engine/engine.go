package engine

import (
	"abiroute/internal/blocker"
	"abiroute/internal/config"
	"abiroute/internal/games"
	"abiroute/internal/netwin"
	"abiroute/internal/obf"
	"abiroute/internal/probe"
	"abiroute/internal/proxy"
	"abiroute/internal/radar"
	"abiroute/internal/syswin"
	"abiroute/internal/tunnel"
	"abiroute/internal/updater"
	"abiroute/internal/warp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type PingSample struct {
	Timestamp int64 `json:"ts"`
	BoostedMs int   `json:"boostedMs"`
	DirectMs  int   `json:"directMs"`
}

type RouteMetrics struct {
	RouterPingMs   int    `json:"routerPingMs"`
	Hop1NodeMs     int    `json:"hop1NodeMs"`
	Hop2GameMs     int    `json:"hop2GameMs"`
	BoostedPingMs  int    `json:"boostedPingMs"`
	DirectPingMs   int    `json:"directPingMs"`
	JitterMs       int    `json:"jitterMs"`
	LossPct        int    `json:"lossPct"`
	TargetServerIP string `json:"targetServerIp"`
}

type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"` // "info" | "ok" | "warn" | "err"
	Message string `json:"message"`
}

type DashboardState struct {
	Version             string               `json:"version"`
	IsAdmin             bool                 `json:"isAdmin"`
	Status              string               `json:"status"`
	StatusText          string               `json:"statusText"`
	Busy                bool                 `json:"busy"`
	StartedAt           int64                `json:"startedAt"`
	ActiveGame          games.GameProfile    `json:"activeGame"`
	Catalog             []games.GameProfile  `json:"catalog"`
	Settings            config.Settings      `json:"settings"`
	ActiveProtocol      string               `json:"activeProtocol"`
	ActiveProtocolTitle string               `json:"activeProtocolTitle"`
	ActiveNode          config.NodeInfo      `json:"activeNode"`
	RouteMetrics        RouteMetrics         `json:"routeMetrics"`
	TunnelStats         tunnel.Stats         `json:"tunnelStats"`
	AppliedRouteCount   int                  `json:"appliedRouteCount"`
	DeferredRouteCount  int                  `json:"deferredRouteCount"`
	EffectiveRoutes     []string             `json:"effectiveRoutes"`
	UpdateInfo          updater.UpdateInfo   `json:"updateInfo"`
	History             []PingSample         `json:"history"`
	Radar               radar.Snapshot       `json:"radar"`
	Servers             []config.SeenServer  `json:"servers"`
	Logs                []LogEntry           `json:"logs"`
}

type Engine struct {
	mu          sync.Mutex
	store       *config.Store
	onEvent     func(topic string, payload any)
	onTraySync  func(boosted bool, tooltip string, hotkey bool)
	tun         tunnel.Runner
	radar       *radar.Tracker
	opCancel    context.CancelFunc
	busy        bool
	status      string
	statusText  string
	startedAt   int64
	activeProto string
	activeNode  config.NodeInfo
	metrics     RouteMetrics
	updateInfo  updater.UpdateInfo
	history     []PingSample
	deferred    []string
	logs        []LogEntry
	healthFails int
	stopBg      chan struct{}
}

func New(store *config.Store, onEvent func(topic string, payload any)) *Engine {
	// Crash-safe cleanup of any orphaned child processes / firewall rules
	tunnel.CleanupStaleSingBox()

	e := &Engine{
		store:      store,
		onEvent:    onEvent,
		status:     "idle",
		statusText: "Готов к ускорению в 1 клик",
		updateInfo: updater.UpdateInfo{CurrentVer: config.AppVersion, LatestVer: config.AppVersion},
		history:    make([]PingSample, 0, 60),
		logs:       make([]LogEntry, 0, 150),
		stopBg:     make(chan struct{}),
	}
	e.radar = radar.NewTracker(e.handleDiscoveredServer, e.handleGameToggle)

	st := store.Get()
	_ = blocker.SyncFirewallBlocks(st.BlockedIPs)
	_ = syswin.SetAutoStart(st.StartWithWindows)

	game := games.FindGame(st.ActiveGameID, st.CustomGames)
	e.radar.SetTargetProcesses(game.Processes, "")
	e.radar.Start()

	e.log("info", fmt.Sprintf("ABI Route %s готов. Ядро Wintun + VLESS/HY2 + ETW-радар активны.", config.AppVersion))
	if !netwin.IsAdmin() {
		e.log("warn", "Программа запущена без прав администратора — для работы Wintun и блокировщика пинга запустите от имени администратора.")
	}

	go e.backgroundLoop()
	go func() {
		info := updater.CheckForUpdates(context.Background())
		e.mu.Lock()
		e.updateInfo = info
		e.mu.Unlock()
		if info.Available {
			e.log("info", fmt.Sprintf("Доступно обновление ABI Route v%s на GitHub!", info.LatestVer))
			e.pushState()
		}
	}()
	return e
}

func (e *Engine) SetTrayHook(fn func(boosted bool, tooltip string, hotkey bool)) {
	e.mu.Lock()
	e.onTraySync = fn
	e.mu.Unlock()
	e.syncTray()
}

func (e *Engine) syncTray() {
	st := e.store.Get()
	e.mu.Lock()
	hook := e.onTraySync
	boosted := e.tun != nil
	ping := e.metrics.BoostedPingMs
	city := e.activeNode.City
	e.mu.Unlock()
	if hook == nil {
		return
	}
	tip := "ABI Route 5.0 — Ожидание"
	if boosted {
		if ping > 0 {
			tip = fmt.Sprintf("ABI Route 5.0 — В работе · %s (%d мс)", city, ping)
		} else {
			tip = fmt.Sprintf("ABI Route 5.0 — В работе · %s", city)
		}
	}
	hook(boosted, tip, st.GlobalHotkey)
}

func (e *Engine) Shutdown() {
	select {
	case <-e.stopBg:
	default:
		close(e.stopBg)
	}
	e.CancelOperation()
	if e.radar != nil {
		e.radar.Stop()
	}
	e.mu.Lock()
	t := e.tun
	e.tun = nil
	e.status = "idle"
	e.mu.Unlock()
	if t != nil {
		_ = t.Close()
	}
	blocker.ClearFirewallBlocks()
}

func (e *Engine) emit(topic string, payload any) {
	if e.onEvent != nil {
		e.onEvent(topic, payload)
	}
}

func (e *Engine) log(level, msg string) {
	entry := LogEntry{
		Time:    time.Now().Format("15:04:05"),
		Level:   level,
		Message: msg,
	}
	e.mu.Lock()
	e.logs = append(e.logs, entry)
	if len(e.logs) > 150 {
		e.logs = e.logs[len(e.logs)-150:]
	}
	e.mu.Unlock()
	e.emit("engine:log", entry)
}

func protocolLabel(proto string, st config.Settings) string {
	switch proto {
	case "awg_quic", "auto", "":
		if st.Warp != nil && st.Warp.WarpPlus {
			return "WARP+ Argo · AmneziaWG 2.0 QUIC"
		}
		return "AmneziaWG 2.0 · QUIC (HTTP/3)"
	case "awg_dns":
		return "AmneziaWG 2.0 · DNS (EDNS0)"
	case "awg_sip":
		return "AmneziaWG 2.0 · VoIP (SIP)"
	case "awg_junk":
		return "AmneziaWG · Усиленный шум (Jc×90)"
	case "masque_h3":
		return "WARP MASQUE · HTTP/3 (:443)"
	case "masque_h2":
		return "WARP MASQUE · HTTP/2 TCP (:443)"
	case "custom":
		return "Свой сервер (AmneziaWG / WG)"
	case "proxy":
		for _, p := range st.Proxies {
			if p.ID == st.ActiveProxyID {
				return fmt.Sprintf("%s · %s", strings.ToUpper(p.Scheme), p.Name)
			}
		}
		return "VLESS / Hysteria2 прокси"
	default:
		return proto
	}
}

func (e *Engine) GetState() DashboardState {
	st := e.store.Get()
	catalog := games.AllGames(st.CustomGames)
	activeGame := games.FindGame(st.ActiveGameID, st.CustomGames)

	e.mu.Lock()
	status := e.status
	statusText := e.statusText
	busy := e.busy
	startedAt := e.startedAt
	actProto := e.activeProto
	if actProto == "" {
		actProto = st.Protocol
	}
	actNode := e.activeNode
	if actNode.Endpoint == "" {
		if st.Protocol == "proxy" && len(st.Proxies) > 0 {
			px := st.Proxies[0]
			for _, cand := range st.Proxies {
				if cand.ID == st.ActiveProxyID {
					px = cand
					break
				}
			}
			actNode = config.NodeInfo{
				Endpoint:     fmt.Sprintf("%s:%d", px.Server, px.Port),
				ColoCode:     strings.ToUpper(px.Scheme),
				City:         px.Name,
				Country:      "Прокси",
				TunnelPingMs: px.PingMs,
			}
		} else if len(st.Nodes) > 0 {
			actNode = st.Nodes[0]
			if st.SelectedEndpoint != "auto" && st.SelectedEndpoint != "" {
				for _, n := range st.Nodes {
					if n.Endpoint == st.SelectedEndpoint {
						actNode = n
						break
					}
				}
			}
		}
	}
	metrics := e.metrics
	upd := e.updateInfo
	hist := make([]PingSample, len(e.history))
	copy(hist, e.history)
	logs := make([]LogEntry, len(e.logs))
	copy(logs, e.logs)
	defCount := len(e.deferred)
	tun := e.tun
	e.mu.Unlock()

	var tStats tunnel.Stats
	var appliedCount int
	if tun != nil {
		tStats = tun.Stats()
		appliedCount = len(tun.AppliedRoutes())
	}

	effective := e.desiredRoutesForGame(st, activeGame)
	radSnap := e.radar.Snapshot()

	blockedSet := map[string]bool{}
	for _, bip := range st.BlockedIPs {
		blockedSet[bip] = true
	}
	servers := make([]config.SeenServer, len(st.SeenServers[activeGame.ID]))
	copy(servers, st.SeenServers[activeGame.ID])
	for i := range servers {
		servers[i].Blocked = blockedSet[servers[i].IP]
		if servers[i].Region == "" {
			servers[i].Region = blocker.ClassifyRegion(servers[i].IP, servers[i].DirectMs)
		}
	}

	return DashboardState{
		Version:             config.AppVersion,
		IsAdmin:             netwin.IsAdmin(),
		Status:              status,
		StatusText:          statusText,
		Busy:                busy,
		StartedAt:           startedAt,
		ActiveGame:          activeGame,
		Catalog:             catalog,
		Settings:            st,
		ActiveProtocol:      actProto,
		ActiveProtocolTitle: protocolLabel(actProto, st),
		ActiveNode:          actNode,
		RouteMetrics:        metrics,
		TunnelStats:         tStats,
		AppliedRouteCount:   appliedCount,
		DeferredRouteCount:  defCount,
		EffectiveRoutes:     effective,
		UpdateInfo:          upd,
		History:             hist,
		Radar:               radSnap,
		Servers:             servers,
		Logs:                logs,
	}
}

func (e *Engine) pushState() {
	e.syncTray()
	e.emit("engine:state", e.GetState())
}

func (e *Engine) IsBoosted() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tun != nil
}

func (e *Engine) beginOp(status, text string) (context.Context, func(), error) {
	e.mu.Lock()
	if e.busy {
		e.mu.Unlock()
		return nil, nil, fmt.Errorf("предыдущая операция ещё выполняется")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.opCancel = cancel
	e.busy = true
	if status != "" {
		e.status = status
	}
	if text != "" {
		e.statusText = text
	}
	e.mu.Unlock()
	e.pushState()

	done := func() {
		e.mu.Lock()
		e.busy = false
		e.opCancel = nil
		if e.tun != nil {
			e.status = "boosted"
		} else if e.status != "idle" {
			e.status = "idle"
		}
		e.mu.Unlock()
		e.pushState()
	}
	return ctx, done, nil
}

func (e *Engine) CancelOperation() {
	e.mu.Lock()
	cancel := e.opCancel
	e.mu.Unlock()
	if cancel != nil {
		cancel()
		e.log("warn", "Операция прервана пользователем.")
	}
}

func (e *Engine) SelectGame(gameID string) DashboardState {
	_ = e.store.Update(func(st *config.Settings) {
		st.ActiveGameID = gameID
	})
	st := e.store.Get()
	g := games.FindGame(gameID, st.CustomGames)
	e.radar.SetTargetProcesses(g.Processes, e.currentEndpointHost())
	e.log("info", fmt.Sprintf("Выбрана игра: %s (%s)", g.Name, strings.Join(g.Processes, ", ")))

	e.mu.Lock()
	tun := e.tun
	e.mu.Unlock()
	if tun != nil {
		routes := e.desiredRoutesForGame(st, g)
		if err := tun.UpdateRoutes(routes); err == nil {
			e.log("ok", fmt.Sprintf("Маршруты переключены на %s (%d подсетей).", g.Name, len(routes)))
		}
	}
	state := e.GetState()
	e.emit("engine:state", state)
	return state
}

func (e *Engine) LaunchActiveGame() error {
	st := e.store.Get()
	customExe := ""
	for _, cg := range st.CustomGames {
		if cg.ID == st.ActiveGameID {
			customExe = cg.ExePath
			break
		}
	}
	if err := syswin.LaunchGame(st.ActiveGameID, customExe); err != nil {
		e.log("warn", err.Error())
		return err
	}
	e.log("ok", "Команда запуска игры отправлена.")
	return nil
}

func (e *Engine) AddCustomGame(name, exeNames, rawSubnets string) (DashboardState, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return e.GetState(), fmt.Errorf("укажите название игры или приложения")
	}
	var procs []string
	var exePath string
	for _, p := range strings.FieldsFunc(exeNames, func(r rune) bool { return r == ',' || r == ';' || r == '\n' }) {
		clean := strings.TrimSpace(strings.Trim(p, `"`))
		if clean == "" {
			continue
		}
		if strings.ContainsAny(clean, `\/`) && exePath == "" {
			exePath = clean
			parts := strings.FieldsFunc(clean, func(r rune) bool { return r == '\\' || r == '/' })
			clean = parts[len(parts)-1]
		}
		if !strings.HasSuffix(strings.ToLower(clean), ".exe") {
			clean += ".exe"
		}
		procs = append(procs, clean)
	}
	if len(procs) == 0 {
		return e.GetState(), fmt.Errorf("укажите хотя бы один процесс (.exe)")
	}
	var ranges []string
	for _, r := range strings.FieldsFunc(rawSubnets, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		if strings.TrimSpace(r) != "" {
			ranges = append(ranges, strings.TrimSpace(r))
		}
	}
	ranges = netwin.NormalizePrefixes(ranges, "")

	id := fmt.Sprintf("custom-%d", time.Now().Unix())
	short := strings.ToUpper(name)
	if len([]rune(short)) > 3 {
		short = string([]rune(short)[:3])
	}

	_ = e.store.Update(func(st *config.Settings) {
		st.CustomGames = append(st.CustomGames, config.CustomGame{
			ID:           id,
			Name:         name,
			ShortCode:    short,
			Category:     "Своё приложение",
			Processes:    procs,
			ExePath:      exePath,
			PresetRanges: ranges,
		})
		st.ActiveGameID = id
	})
	e.radar.SetTargetProcesses(procs, e.currentEndpointHost())
	e.log("ok", fmt.Sprintf("Добавлено приложение «%s» (%s).", name, strings.Join(procs, ", ")))
	state := e.GetState()
	e.emit("engine:state", state)
	return state, nil
}

// AddProxyLinks imports VLESS / Hysteria2 / Trojan / SS / SOCKS5 links (or base64 batch) and measures their pings.
func (e *Engine) AddProxyLinks(rawText string) (DashboardState, error) {
	nodes, err := proxy.ParseBatch(rawText, "")
	if err != nil {
		return e.GetState(), err
	}
	phys, _ := netwin.DefaultPhysicalInterface()
	bindIP := ""
	if phys != nil {
		bindIP = phys.IP
	}

	var wg sync.WaitGroup
	for i := range nodes {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			nodes[idx].PingMs = proxy.MeasureNodeTCPPing(nodes[idx].Server, nodes[idx].Port, bindIP)
		}(i)
	}
	wg.Wait()

	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].PingMs == 0 {
			return false
		}
		if nodes[j].PingMs == 0 {
			return true
		}
		return nodes[i].PingMs < nodes[j].PingMs
	})

	_ = e.store.Update(func(st *config.Settings) {
		existing := map[string]bool{}
		for _, n := range nodes {
			existing[n.ID] = true
		}
		var merged []config.ProxyNode
		merged = append(merged, nodes...)
		for _, old := range st.Proxies {
			if !existing[old.ID] {
				merged = append(merged, old)
			}
		}
		st.Proxies = merged
		st.ActiveProxyID = nodes[0].ID
		st.Protocol = "proxy"
	})
	e.mu.Lock()
	e.activeProto = "proxy"
	e.activeNode = config.NodeInfo{}
	e.mu.Unlock()

	e.log("ok", fmt.Sprintf("Добавлено %d прокси-узлов (VLESS / Hysteria2). Выбран «%s».", len(nodes), nodes[0].Name))
	state := e.GetState()
	e.emit("engine:state", state)
	return state, nil
}

// SyncSubscription downloads a subscription URL (Happ / v2rayN / Marzban / 3x-ui) and refreshes its proxy nodes.
func (e *Engine) SyncSubscription(subURL string) (DashboardState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	nodes, err := proxy.FetchSubscription(ctx, subURL)
	if err != nil {
		return e.GetState(), err
	}

	phys, _ := netwin.DefaultPhysicalInterface()
	bindIP := ""
	if phys != nil {
		bindIP = phys.IP
	}
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			nodes[idx].PingMs = proxy.MeasureNodeTCPPing(nodes[idx].Server, nodes[idx].Port, bindIP)
		}(i)
	}
	wg.Wait()

	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].PingMs == 0 {
			return false
		}
		if nodes[j].PingMs == 0 {
			return true
		}
		return nodes[i].PingMs < nodes[j].PingMs
	})

	_ = e.store.Update(func(st *config.Settings) {
		var kept []config.ProxyNode
		for _, old := range st.Proxies {
			if old.SubURL == "" || old.SubURL != subURL {
				kept = append(kept, old)
			}
		}
		st.Proxies = append(nodes, kept...)
		st.SubscriptionURL = subURL
		st.ActiveProxyID = nodes[0].ID
		st.Protocol = "proxy"
	})
	e.mu.Lock()
	e.activeProto = "proxy"
	e.activeNode = config.NodeInfo{}
	e.mu.Unlock()

	e.log("ok", fmt.Sprintf("Подписка обновлена: загружено %d серверов, лучший «%s» (%d мс).", len(nodes), nodes[0].Name, nodes[0].PingMs))
	state := e.GetState()
	e.emit("engine:state", state)
	return state, nil
}

func (e *Engine) SelectProxy(proxyID string) DashboardState {
	_ = e.store.Update(func(st *config.Settings) {
		st.ActiveProxyID = proxyID
		st.Protocol = "proxy"
	})
	e.mu.Lock()
	e.activeProto = "proxy"
	e.activeNode = config.NodeInfo{}
	e.mu.Unlock()
	state := e.GetState()
	e.emit("engine:state", state)
	return state
}

func (e *Engine) DeleteProxy(proxyID string) DashboardState {
	_ = e.store.Update(func(st *config.Settings) {
		var out []config.ProxyNode
		for _, p := range st.Proxies {
			if p.ID != proxyID {
				out = append(out, p)
			}
		}
		st.Proxies = out
		if st.ActiveProxyID == proxyID {
			if len(out) > 0 {
				st.ActiveProxyID = out[0].ID
			} else {
				st.ActiveProxyID = ""
				st.Protocol = "auto"
			}
		}
	})
	state := e.GetState()
	e.emit("engine:state", state)
	return state
}

// ApplyWarpPlus binds a WARP+ license key for Cloudflare Argo Smart Routing.
func (e *Engine) ApplyWarpPlus(licenseKey string) (DashboardState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	st := e.store.Get()
	if st.Warp == nil {
		acct, err := warp.RegisterWireGuard(ctx)
		if err != nil {
			return e.GetState(), err
		}
		_ = e.store.Update(func(s *config.Settings) { s.Warp = acct })
		st = e.store.Get()
	}

	if err := warp.ApplyWarpPlusLicense(ctx, st.Warp, licenseKey); err != nil {
		return e.GetState(), err
	}

	_ = e.store.Update(func(s *config.Settings) {
		if s.Warp != nil {
			s.Warp.License = strings.TrimSpace(licenseKey)
			s.Warp.WarpPlus = true
		}
	})
	e.log("ok", "Лицензия WARP+ успешно привязана! Магистраль Cloudflare Argo Smart Routing активна.")
	state := e.GetState()
	e.emit("engine:state", state)
	return state, nil
}

// AutoOptimizeMTU runs Don't-Fragment Path MTU Discovery and updates MTU in settings.
func (e *Engine) AutoOptimizeMTU() (DashboardState, error) {
	phys, _ := netwin.DefaultPhysicalInterface()
	bindIP := ""
	if phys != nil {
		bindIP = phys.IP
	}
	target := "1.1.1.1"
	if host := e.currentEndpointHost(); host != "" {
		target = host
	}
	optimal := probe.DiscoverOptimalMTU(target, bindIP)
	_ = e.store.Update(func(s *config.Settings) {
		s.MTU = optimal
	})
	e.log("ok", fmt.Sprintf("Автоподбор MTU завершён: идеальный размер без фрагментации пакетов = %d байт.", optimal))
	state := e.GetState()
	e.emit("engine:state", state)
	return state, nil
}

// High-Ping Server Blocker controls
func (e *Engine) SetHighPingFilter(enabled bool, thresholdMs int) DashboardState {
	_ = e.store.Update(func(s *config.Settings) {
		s.BlockHighPing = enabled
		if thresholdMs >= 50 && thresholdMs <= 350 {
			s.MaxPingThresholdMs = thresholdMs
		}
	})
	if enabled {
		e.log("ok", fmt.Sprintf("Включён фильтр матчмейкинга: серверы с пингом выше %d мс будут автоматически блокироваться.", thresholdMs))
	} else {
		e.log("info", "Автоблокировка серверов с высоким пингом выключена.")
	}
	state := e.GetState()
	e.emit("engine:state", state)
	return state
}

func (e *Engine) ToggleBlockServer(ip string) DashboardState {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return e.GetState()
	}
	var nowBlocked bool
	_ = e.store.Update(func(s *config.Settings) {
		var next []string
		found := false
		for _, b := range s.BlockedIPs {
			if b == ip {
				found = true
				continue
			}
			next = append(next, b)
		}
		if !found {
			next = append(next, ip)
			nowBlocked = true
		}
		s.BlockedIPs = next
	})
	st := e.store.Get()
	_ = blocker.SyncFirewallBlocks(st.BlockedIPs)
	if nowBlocked {
		e.log("warn", fmt.Sprintf("Сервер %s заблокирован в Windows Firewall — игра выберет другой сервер.", ip))
	} else {
		e.log("info", fmt.Sprintf("Блокировка сервера %s снята.", ip))
	}
	state := e.GetState()
	e.emit("engine:state", state)
	return state
}

func (e *Engine) ClearBlockedServers() DashboardState {
	_ = e.store.Update(func(s *config.Settings) {
		s.BlockedIPs = []string{}
	})
	blocker.ClearFirewallBlocks()
	e.log("ok", "Все заблокированные игровые серверы разблокированы.")
	state := e.GetState()
	e.emit("engine:state", state)
	return state
}

// Manual Subnet & Exclusion Editor
func (e *Engine) SaveManualRoutes(manualLines, excludedLines string) DashboardState {
	parseLines := func(txt string) []string {
		var out []string
		for _, f := range strings.FieldsFunc(txt, func(r rune) bool { return r == '\n' || r == ',' || r == ';' || r == ' ' }) {
			if strings.TrimSpace(f) != "" {
				out = append(out, strings.TrimSpace(f))
			}
		}
		return netwin.NormalizePrefixes(out, "")
	}
	man := parseLines(manualLines)
	exc := parseLines(excludedLines)

	var gid string
	_ = e.store.Update(func(s *config.Settings) {
		gid = s.ActiveGameID
		s.ManualRanges[gid] = man
		s.ExcludedRanges[gid] = exc
	})

	st := e.store.Get()
	g := games.FindGame(gid, st.CustomGames)
	e.mu.Lock()
	tun := e.tun
	e.mu.Unlock()
	if tun != nil {
		_ = tun.UpdateRoutes(e.desiredRoutesForGame(st, g))
	}
	e.log("ok", "Пользовательские подсети и исключения сохранены.")
	state := e.GetState()
	e.emit("engine:state", state)
	return state
}

func (e *Engine) ResetLearnedRoutes() DashboardState {
	_ = e.store.Update(func(s *config.Settings) {
		delete(s.LearnedRanges, s.ActiveGameID)
		delete(s.SeenServers, s.ActiveGameID)
	})
	e.log("info", "Выученные радаром адреса сброшены до заводских пресетов.")
	state := e.GetState()
	e.emit("engine:state", state)
	return state
}

func (e *Engine) UpdateSystemPrefs(autoBoost, autoStop, closeToTray, startWithWin, globalHotkey bool, mtu int) DashboardState {
	_ = e.store.Update(func(s *config.Settings) {
		s.AutoBoost = autoBoost
		s.AutoStopOnExit = autoStop
		s.CloseToTray = closeToTray
		s.StartWithWindows = startWithWin
		s.GlobalHotkey = globalHotkey
		if mtu >= 1200 && mtu <= 1420 {
			s.MTU = mtu
		}
	})
	_ = syswin.SetAutoStart(startWithWin)
	state := e.GetState()
	e.syncTray()
	e.emit("engine:state", state)
	return state
}

func (e *Engine) CheckUpdatesNow() updater.UpdateInfo {
	info := updater.CheckForUpdates(context.Background())
	e.mu.Lock()
	e.updateInfo = info
	e.mu.Unlock()
	e.pushState()
	return info
}

func (e *Engine) InstallUpdateNow() error {
	e.mu.Lock()
	dl := e.updateInfo.DownloadURL
	e.mu.Unlock()
	if dl == "" {
		info := updater.CheckForUpdates(context.Background())
		dl = info.DownloadURL
	}
	if err := updater.ApplySelfUpdate(context.Background(), dl); err != nil {
		e.log("err", err.Error())
		return err
	}
	return nil
}

func (e *Engine) UpdateOptions(protocol, selectedEndpoint string, raidProtection, autoFailover, autoLearn bool, subnetPrefix int) DashboardState {
	_ = e.store.Update(func(st *config.Settings) {
		if protocol != "" {
			st.Protocol = protocol
		}
		if selectedEndpoint != "" {
			st.SelectedEndpoint = selectedEndpoint
		}
		st.RaidProtection = raidProtection
		st.AutoFailover = autoFailover
		st.AutoLearn = autoLearn
		if subnetPrefix == 16 || subnetPrefix == 20 || subnetPrefix == 24 {
			st.SubnetPrefix = subnetPrefix
		}
	})
	e.mu.Lock()
	if e.tun == nil && protocol != "" {
		e.activeProto = protocol
		e.activeNode = config.NodeInfo{}
	}
	e.mu.Unlock()
	state := e.GetState()
	e.emit("engine:state", state)
	return state
}

func (e *Engine) GenerateWarpProfile() error {
	ctx, done, err := e.beginOp("connecting", "Регистрация бесплатного профиля Cloudflare WARP…")
	if err != nil {
		return err
	}
	go func() {
		defer done()
		e.log("info", "Регистрирую новый ключ Cloudflare WARP (обход DNS через DoH)…")
		acct, err := warp.RegisterWireGuard(ctx)
		if err != nil {
			e.log("err", fmt.Sprintf("Ошибка регистрации WARP: %v", err))
			return
		}
		_ = e.store.Update(func(st *config.Settings) {
			st.Warp = acct
		})
		e.log("ok", fmt.Sprintf("Профиль WARP создан (внутренний адрес %s).", acct.IPv4))
	}()
	return nil
}

func (e *Engine) ImportTunnelConfig(input, name string) error {
	trimmed := strings.TrimSpace(input)
	// Automatically detect VLESS / Hysteria2 / Trojan / SS / SOCKS5 or Subscription links too!
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		_, err := e.SyncSubscription(trimmed)
		return err
	}
	if strings.HasPrefix(lower, "vless://") || strings.HasPrefix(lower, "hy2://") ||
		strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "trojan://") ||
		strings.HasPrefix(lower, "ss://") || strings.HasPrefix(lower, "socks5://") {
		_, err := e.AddProxyLinks(trimmed)
		return err
	}

	custom, err := obf.ParseInput(trimmed, name)
	if err != nil {
		return err
	}
	_ = e.store.Update(func(st *config.Settings) {
		if custom.PeerPublicKey == obf.WarpDefaultPeerPubKey {
			st.Warp = &config.WarpAccount{
				PrivateKey:    custom.PrivateKey,
				PublicKey:     custom.PublicKey,
				PeerPublicKey: custom.PeerPublicKey,
				IPv4:          custom.AddressV4,
				Created:       custom.Created,
				Source:        "import",
			}
			if st.Protocol == "custom" {
				st.Protocol = "awg_quic"
			}
		} else {
			st.CustomTunnel = custom
			st.Protocol = "custom"
		}
	})
	if custom.PeerPublicKey == obf.WarpDefaultPeerPubKey {
		e.log("ok", fmt.Sprintf("Импортирован профиль Cloudflare WARP (%s).", custom.AddressV4))
	} else {
		e.log("ok", fmt.Sprintf("Импортирован собственный сервер «%s» (%s).", custom.Name, custom.Endpoint))
	}
	e.pushState()
	return nil
}

func (e *Engine) ExportTunnelConf() (string, error) {
	st := e.store.Get()
	game := games.FindGame(st.ActiveGameID, st.CustomGames)
	routes := e.desiredRoutesForGame(st, game)
	if len(routes) == 0 {
		routes = game.PresetRanges
	}
	if st.Protocol == "custom" && st.CustomTunnel != nil {
		ct := st.CustomTunnel
		prof := obf.Profile{Jc: ct.Jc, Jmin: ct.Jmin, Jmax: ct.Jmax, I: ct.I}
		return obf.BuildConf(ct.PrivateKey, ct.AddressV4, ct.PeerPublicKey, ct.PresharedKey, ct.Endpoint, ct.MTU, prof, routes), nil
	}
	if st.Warp == nil {
		return "", fmt.Errorf("сначала создайте профиль WARP или нажмите «Ускорить»")
	}
	ep := st.SelectedEndpoint
	if ep == "" || ep == "auto" {
		if len(st.Nodes) > 0 {
			ep = st.Nodes[0].Endpoint
		} else {
			ep = "162.159.192.1:2408"
		}
	}
	prof := obf.BuildProfile(st.Protocol, st.MimicSNI)
	return obf.BuildConf(st.Warp.PrivateKey, st.Warp.IPv4, st.Warp.PeerPublicKey, "", ep, st.MTU, prof, routes), nil
}

func (e *Engine) ScanEndpoints() error {
	ctx, done, err := e.beginOp("scanning", "Поиск самых быстрых узлов Cloudflare WARP…")
	if err != nil {
		return err
	}
	go func() {
		defer done()
		st := e.store.Get()
		if st.Warp == nil {
			e.log("info", "Профиля WARP ещё нет — регистрирую автоматически…")
			acct, err := warp.RegisterWireGuard(ctx)
			if err != nil {
				e.log("err", fmt.Sprintf("Не удалось создать профиль WARP: %v", err))
				return
			}
			_ = e.store.Update(func(s *config.Settings) { s.Warp = acct })
			st = e.store.Get()
		}

		phys, _ := netwin.DefaultPhysicalInterface()
		bindIP := ""
		if phys != nil {
			bindIP = phys.IP
		}

		mode := st.Protocol
		if mode == "auto" || strings.HasPrefix(mode, "masque") || mode == "custom" || mode == "proxy" {
			mode = "awg_quic"
		}
		prof := obf.BuildProfile(mode, st.MimicSNI)
		e.log("info", fmt.Sprintf("Сканирую ~420 эндпоинтов с профилем «%s» и проверкой ICMP внутри туннеля…", prof.Title))

		nodes, err := probe.ScanNodes(ctx, st.Warp, prof, bindIP, func(cur, total int) {
			e.emit("engine:scan_progress", map[string]int{"done": cur, "total": total})
		})
		if err != nil {
			return
		}
		if len(nodes) == 0 {
			e.log("warn", "Узлы WireGuard/AmneziaWG не ответили по UDP. При запуске будет использован резервный протокол MASQUE HTTP/3 (:443).")
			return
		}

		_ = e.store.Update(func(s *config.Settings) {
			s.Nodes = nodes
		})
		best := nodes[0]
		e.mu.Lock()
		e.activeNode = best
		e.mu.Unlock()
		e.log("ok", fmt.Sprintf("Найдено %d рабочих узлов! Лучший: %s (%s) — %d мс (%s).",
			len(nodes), best.City, best.ColoCode, best.TunnelPingMs, best.Endpoint))
	}()
	return nil
}

func (e *Engine) BoostOneClick(gameID string) error {
	if !netwin.IsAdmin() {
		e.log("err", "Для запуска встроенного адаптера Wintun требуются права администратора.")
		return fmt.Errorf("запустите ABI Route от имени администратора")
	}

	if gameID != "" {
		_ = e.store.Update(func(st *config.Settings) { st.ActiveGameID = gameID })
	}

	ctx, done, err := e.beginOp("connecting", "Подготовка оптимального игрового маршрута…")
	if err != nil {
		return err
	}

	go func() {
		defer done()
		if err := e.startBoostFlow(ctx); err != nil {
			e.log("err", fmt.Sprintf("Не удалось включить ускорение: %v", err))
			e.mu.Lock()
			e.statusText = err.Error()
			e.mu.Unlock()
		}
	}()
	return nil
}

func (e *Engine) startBoostFlow(ctx context.Context) error {
	e.stopTunnelInternal(true)

	st := e.store.Get()
	game := games.FindGame(st.ActiveGameID, st.CustomGames)
	phys, _ := netwin.DefaultPhysicalInterface()
	bindIP := ""
	if phys != nil {
		bindIP = phys.IP
		if rStats := probe.MeasureDirect(phys.Gateway, 0, bindIP, 2); rStats != nil {
			e.mu.Lock()
			e.metrics.RouterPingMs = rStats.MedianMs
			e.mu.Unlock()
		}
	}

	routes := e.desiredRoutesForGame(st, game)
	if len(routes) == 0 {
		routes = []string{"1.1.1.1/32"}
	}

	// Case 0: VLESS / Hysteria2 / Trojan / SS / SOCKS5 Proxy via SingBox Wintun
	if st.Protocol == "proxy" {
		if len(st.Proxies) == 0 {
			return fmt.Errorf("сначала добавьте ключ vless://, hy2:// или ссылку подписки")
		}
		chosenPx := st.Proxies[0]
		for _, p := range st.Proxies {
			if p.ID == st.ActiveProxyID {
				chosenPx = p
				break
			}
		}
		e.setStatusText(fmt.Sprintf("Запуск %s прокси «%s»…", strings.ToUpper(chosenPx.Scheme), chosenPx.Name))
		sbTun, err := tunnel.StartSingBox(ctx, tunnel.SingBoxConfig{
			RawURI:  chosenPx.RawURI,
			MTU:     st.MTU,
			Routes:  routes,
			PhysNIC: phys,
			OnStatus: func(msg string) {
				e.setStatusText(msg)
				e.log("info", msg)
			},
		})
		if err != nil {
			return err
		}
		e.activateTunnel(sbTun, "proxy", config.NodeInfo{
			Endpoint:     fmt.Sprintf("%s:%d", chosenPx.Server, chosenPx.Port),
			ColoCode:     strings.ToUpper(chosenPx.Scheme),
			City:         chosenPx.Name,
			Country:      "Свой прокси",
			TunnelPingMs: chosenPx.PingMs,
		}, game, chosenPx.Server)
		return nil
	}

	// Case 1: Custom imported VPS (.conf / vpn://)
	if st.Protocol == "custom" && st.CustomTunnel != nil {
		ct := st.CustomTunnel
		e.setStatusText(fmt.Sprintf("Подключение к своему серверу %s…", ct.Name))
		prof := obf.Profile{Jc: ct.Jc, Jmin: ct.Jmin, Jmax: ct.Jmax, I: ct.I}
		tunRun, err := tunnel.StartAWG(tunnel.AWGConfig{
			PrivateKeyB64: ct.PrivateKey,
			PeerPubKeyB64: ct.PeerPublicKey,
			PresharedB64:  ct.PresharedKey,
			AddressV4:     ct.AddressV4,
			Endpoint:      ct.Endpoint,
			MTU:           ct.MTU,
			Profile:       prof,
			CustomS:       ct.S,
			CustomH:       ct.H,
			CustomI:       ct.I,
			Routes:        routes,
			PhysNIC:       phys,
		})
		if err != nil {
			return err
		}
		host, _, _ := net.SplitHostPort(ct.Endpoint)
		e.activateTunnel(tunRun, "custom", config.NodeInfo{
			Endpoint: ct.Endpoint,
			ColoCode: "VPS",
			City:     ct.Name,
			Country:  "Свой сервер",
		}, game, host)
		return nil
	}

	// Case 2: Explicit MASQUE HTTP/3 or HTTP/2
	if st.Protocol == "masque_h3" || st.Protocol == "masque_h2" {
		return e.startMASQUEFlow(ctx, st.Protocol == "masque_h2", game, routes, phys)
	}

	// Case 3: Auto or AmneziaWG 2.0
	if st.Warp == nil {
		e.setStatusText("Автоматическая регистрация профиля Cloudflare WARP…")
		e.log("info", "Первый запуск: регистрирую бесплатный ключ Cloudflare WARP…")
		acct, err := warp.RegisterWireGuard(ctx)
		if err != nil {
			return err
		}
		_ = e.store.Update(func(s *config.Settings) { s.Warp = acct })
		st = e.store.Get()
	}

	modesToTry := []string{st.Protocol}
	if st.Protocol == "auto" || st.Protocol == "" {
		modesToTry = []string{"awg_quic", "awg_dns", "awg_sip"}
	}

	for _, m := range modesToTry {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		prof := obf.BuildProfile(m, st.MimicSNI)
		var chosen config.NodeInfo

		if st.SelectedEndpoint != "" && st.SelectedEndpoint != "auto" {
			chosen = config.NodeInfo{Endpoint: st.SelectedEndpoint, ColoCode: "CF", City: "Выбранный узел"}
			for _, n := range st.Nodes {
				if n.Endpoint == st.SelectedEndpoint {
					chosen = n
					break
				}
			}
		} else if len(st.Nodes) > 0 {
			top := st.Nodes[0]
			if sess, err := probe.NewProbeSession(st.Warp.PrivateKey, st.Warp.PeerPublicKey, "", st.Warp.IPv4, top.Endpoint, prof, bindIP); err == nil {
				if _, err := sess.Handshake(1200 * time.Millisecond); err == nil {
					if rtt, err := sess.PingICMP("1.1.1.1", 1, 900*time.Millisecond); err == nil {
						top.TunnelPingMs = int(rtt)
						chosen = top
					}
				}
				sess.Close()
			}
		}

		if chosen.Endpoint == "" {
			e.setStatusText(fmt.Sprintf("Подбор лучшего узла (%s)…", prof.Title))
			nodes, err := probe.ScanNodes(ctx, st.Warp, prof, bindIP, func(cur, total int) {
				e.emit("engine:scan_progress", map[string]int{"done": cur, "total": total})
			})
			if err != nil {
				return err
			}
			if len(nodes) > 0 {
				_ = e.store.Update(func(s *config.Settings) { s.Nodes = nodes })
				chosen = nodes[0]
			}
		}

		if chosen.Endpoint != "" {
			e.setStatusText(fmt.Sprintf("Запуск туннеля Wintun через %s (%s)…", chosen.City, chosen.ColoCode))
			tunRun, err := tunnel.StartAWG(tunnel.AWGConfig{
				PrivateKeyB64: st.Warp.PrivateKey,
				PeerPubKeyB64: st.Warp.PeerPublicKey,
				AddressV4:     st.Warp.IPv4,
				Endpoint:      chosen.Endpoint,
				MTU:           st.MTU,
				Profile:       prof,
				Routes:        routes,
				PhysNIC:       phys,
			})
			if err == nil {
				host, _, _ := net.SplitHostPort(chosen.Endpoint)
				e.activateTunnel(tunRun, m, chosen, game, host)
				return nil
			}
			e.log("warn", fmt.Sprintf("Попытка %s не удалась: %v", m, err))
		}
	}

	if st.Protocol == "auto" || st.Protocol == "" {
		e.log("warn", "Провайдер блокирует UDP WireGuard — автоматически переключаюсь на резервный протокол WARP MASQUE (HTTP/3 :443)…")
		if err := e.startMASQUEFlow(ctx, false, game, routes, phys); err == nil {
			return nil
		}
		e.log("warn", "Пробую резервный MASQUE поверх TCP HTTP/2 (:443)…")
		return e.startMASQUEFlow(ctx, true, game, routes, phys)
	}

	return fmt.Errorf("ни один узел не ответил; включите режим «Авто», протокол MASQUE или добавьте свой VLESS/Hysteria2 ключ")
}

func (e *Engine) startMASQUEFlow(ctx context.Context, useH2 bool, game games.GameProfile, routes []string, phys *netwin.PhysicalNIC) error {
	st := e.store.Get()
	if st.Masque == nil || st.Masque.PrivateKeyDERB64 == "" {
		e.setStatusText("Регистрация ключей Cloudflare MASQUE (HTTP/3)…")
		e.log("info", "Регистрирую сертификат ECDSA P-256 для протокола Cloudflare MASQUE…")
		mAcct, err := warp.RegisterMASQUE(ctx)
		if err != nil {
			return err
		}
		_ = e.store.Update(func(s *config.Settings) { s.Masque = mAcct })
		st = e.store.Get()
	}

	protoName := "masque_h3"
	ep := st.Masque.EndpointV4 + ":443"
	if useH2 {
		protoName = "masque_h2"
		ep = st.Masque.EndpointH2V4 + ":443"
	}

	e.setStatusText(fmt.Sprintf("Подключение MASQUE (%s)…", ep))
	tunRun, err := tunnel.StartMASQUE(tunnel.MASQUEConfig{
		Account:  st.Masque,
		UseHTTP2: useH2,
		MTU:      st.MTU,
		Routes:   routes,
		PhysNIC:  phys,
	})
	if err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(ep)
	e.activateTunnel(tunRun, protoName, config.NodeInfo{
		Endpoint: ep,
		ColoCode: "H3",
		City:     "Cloudflare MASQUE",
		Country:  "HTTPS :443",
	}, game, host)
	return nil
}

func (e *Engine) activateTunnel(tunRun tunnel.Runner, proto string, node config.NodeInfo, game games.GameProfile, epHost string) {
	st := e.store.Get()
	e.mu.Lock()
	e.tun = tunRun
	e.status = "boosted"
	e.startedAt = time.Now().Unix()
	e.activeProto = proto
	e.activeNode = node
	e.metrics.Hop1NodeMs = node.TunnelPingMs
	e.statusText = fmt.Sprintf("Ускорение активно · %s (%s)", node.City, protocolLabel(proto, st))
	e.healthFails = 0
	e.mu.Unlock()

	e.radar.SetTargetProcesses(game.Processes, epHost)
	e.log("ok", fmt.Sprintf("Ускорение «%s» включено! Маршрут: %s (%s), подсетей игры: %d.",
		game.Name, node.City, protocolLabel(proto, st), len(tunRun.AppliedRoutes())))

	go e.measureTelemetryOnce()
	e.pushState()
}

func (e *Engine) StopBoost() DashboardState {
	e.CancelOperation()
	e.stopTunnelInternal(false)
	state := e.GetState()
	e.emit("engine:state", state)
	return state
}

func (e *Engine) stopTunnelInternal(silent bool) {
	e.mu.Lock()
	tun := e.tun
	e.tun = nil
	e.startedAt = 0
	e.deferred = nil
	if !silent {
		e.status = "idle"
		e.statusText = "Туннель остановлен · Игра идёт напрямую"
	}
	e.mu.Unlock()

	if tun != nil {
		_ = tun.Close()
		if !silent {
			e.log("info", "Туннель остановлен, маршруты игры возвращены на прямой канал.")
		}
	}
	e.syncTray()
}

func (e *Engine) setStatusText(text string) {
	e.mu.Lock()
	e.statusText = text
	e.mu.Unlock()
	e.pushState()
}

func (e *Engine) currentEndpointHost() string {
	e.mu.Lock()
	ep := e.activeNode.Endpoint
	e.mu.Unlock()
	host, _, err := net.SplitHostPort(ep)
	if err != nil {
		return ep
	}
	return host
}

func (e *Engine) desiredRoutesForGame(st config.Settings, g games.GameProfile) []string {
	var all []string
	if st.SubnetPrefix == 16 && len(g.WideRanges) > 0 {
		all = append(all, g.WideRanges...)
	} else {
		all = append(all, g.PresetRanges...)
	}
	all = append(all, st.LearnedRanges[g.ID]...)
	all = append(all, st.ManualRanges[g.ID]...)

	excl := append([]string{}, g.IgnoreRanges...)
	excl = append(excl, st.ExcludedRanges[g.ID]...)

	norm := netwin.NormalizePrefixes(all, "")
	if len(excl) == 0 {
		return norm
	}
	var filtered []string
	for _, r := range norm {
		ipPart := strings.Split(r, "/")[0]
		if !netwin.InPrefixes(ipPart, excl) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (e *Engine) handleGameToggle(running bool) {
	st := e.store.Get()
	g := games.FindGame(st.ActiveGameID, st.CustomGames)
	if running {
		e.log("ok", fmt.Sprintf("Обнаружен запуск %s — ETW-радар отслеживает серверы матчей.", g.Name))
		if st.AutoBoost && !e.IsBoosted() {
			e.log("info", "Авто-буст: запускаю ускорение автоматически при старте игры…")
			_ = e.BoostOneClick(st.ActiveGameID)
		}
	} else {
		e.log("info", fmt.Sprintf("%s закрыта.", g.Name))
		e.flushDeferredRoutes()
		if st.AutoStopOnExit && e.IsBoosted() {
			e.log("info", "Игра закрыта — автоматически выключаю туннель.")
			e.StopBoost()
		}
	}
	e.pushState()
}

func (e *Engine) handleDiscoveredServer(hit radar.EndpointHit) {
	st := e.store.Get()
	g := games.FindGame(st.ActiveGameID, st.CustomGames)
	excl := append([]string{}, g.IgnoreRanges...)
	excl = append(excl, st.ExcludedRanges[g.ID]...)
	if netwin.InPrefixes(hit.IP, excl) {
		return
	}

	addr, err := netip.ParseAddr(hit.IP)
	if err != nil || !addr.Is4() {
		return
	}
	prefix := netip.PrefixFrom(addr, st.SubnetPrefix).Masked().String()
	currentDesired := e.desiredRoutesForGame(st, g)
	isNewSubnet := st.AutoLearn && !netwin.InPrefixes(hit.IP, currentDesired)

	go func() {
		phys, _ := netwin.DefaultPhysicalInterface()
		bindIP := ""
		if phys != nil {
			bindIP = phys.IP
		}
		var dMs, tMs int
		if ds := probe.MeasureDirect(hit.IP, hit.Port, bindIP, 1); ds != nil {
			dMs = ds.MedianMs
		}
		e.mu.Lock()
		tunRunning := e.tun != nil
		e.mu.Unlock()
		if tunRunning {
			if ts := probe.MeasureDirect(hit.IP, hit.Port, "", 1); ts != nil {
				tMs = ts.MedianMs
			}
		}

		region := blocker.ClassifyRegion(hit.IP, dMs)

		// Auto High-Ping Server Blocker (only during lobby/probing before heavy raid UDP lock-in)
		effectivePing := tMs
		if effectivePing == 0 {
			effectivePing = dMs
		}
		autoBlockedNow := false
		stLatest := e.store.Get()
		if stLatest.BlockHighPing && effectivePing > stLatest.MaxPingThresholdMs && hit.Packets < 12 {
			alreadyBlocked := false
			for _, b := range stLatest.BlockedIPs {
				if b == hit.IP {
					alreadyBlocked = true
					break
				}
			}
			if !alreadyBlocked {
				autoBlockedNow = true
			}
		}

		_ = e.store.Update(func(s *config.Settings) {
			if autoBlockedNow {
				s.BlockedIPs = append(s.BlockedIPs, hit.IP)
			}
			isBlk := autoBlockedNow
			for _, b := range s.BlockedIPs {
				if b == hit.IP {
					isBlk = true
					break
				}
			}

			list := s.SeenServers[g.ID]
			updated := false
			for i := range list {
				if list[i].IP == hit.IP {
					list[i].Port = hit.Port
					list[i].Proto = hit.Proto
					list[i].Role = hit.Role
					list[i].Region = region
					if dMs > 0 {
						list[i].DirectMs = dMs
					}
					if tMs > 0 {
						list[i].TunnelMs = tMs
					}
					list[i].Routed = !isBlk
					list[i].Blocked = isBlk
					list[i].LastSeen = hit.LastSeen
					updated = true
					break
				}
			}
			if !updated {
				entry := config.SeenServer{
					IP:       hit.IP,
					Port:     hit.Port,
					Proto:    hit.Proto,
					Role:     hit.Role,
					Region:   region,
					DirectMs: dMs,
					TunnelMs: tMs,
					Routed:   !isBlk,
					Blocked:  isBlk,
					LastSeen: hit.LastSeen,
				}
				list = append([]config.SeenServer{entry}, list...)
				if len(list) > 35 {
					list = list[:35]
				}
			}
			s.SeenServers[g.ID] = list
			if isNewSubnet && !autoBlockedNow {
				s.LearnedRanges[g.ID] = netwin.NormalizePrefixes(append(s.LearnedRanges[g.ID], prefix), "")
			}
		})

		if autoBlockedNow {
			_ = blocker.SyncFirewallBlocks(e.store.Get().BlockedIPs)
			e.log("warn", fmt.Sprintf("Фильтр пинга: заблокирован далёкий сервер %s (%s, %d мс > %d мс) — подбор найдёт сервер ближе.",
				hit.IP, region, effectivePing, stLatest.MaxPingThresholdMs))
			e.pushState()
			return
		}

		if isNewSubnet {
			e.applyNewLearnedSubnet(g, prefix)
		} else {
			e.pushState()
		}
	}()
}

func (e *Engine) applyNewLearnedSubnet(g games.GameProfile, prefix string) {
	st := e.store.Get()
	e.mu.Lock()
	tun := e.tun
	e.mu.Unlock()
	if tun == nil {
		e.log("info", fmt.Sprintf("Радар сохранил новую подсеть игры %s — будет включена при запуске ускорения.", prefix))
		e.pushState()
		return
	}

	if st.RaidProtection && e.radar.ActiveUDPInPrefixes([]string{prefix}, 20) {
		e.mu.Lock()
		e.deferred = append(e.deferred, prefix)
		e.mu.Unlock()
		e.log("warn", fmt.Sprintf("Защита рейда: матч уже идёт напрямую через %s — добавлю подсеть сразу после боя без разрыва связи.", prefix))
		e.pushState()
		return
	}

	desired := e.desiredRoutesForGame(st, g)
	if err := tun.UpdateRoutes(desired); err == nil {
		e.log("ok", fmt.Sprintf("ETW-радар добавил сервер матча %s на лету без перезапуска туннеля.", prefix))
	}
	e.pushState()
}

func (e *Engine) flushDeferredRoutes() {
	e.mu.Lock()
	if len(e.deferred) == 0 || e.tun == nil {
		e.mu.Unlock()
		return
	}
	tun := e.tun
	e.deferred = nil
	e.mu.Unlock()

	st := e.store.Get()
	g := games.FindGame(st.ActiveGameID, st.CustomGames)
	if err := tun.UpdateRoutes(e.desiredRoutesForGame(st, g)); err == nil {
		e.log("ok", "Отложенные маршруты серверов применены после завершения матча.")
	}
}

func (e *Engine) backgroundLoop() {
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopBg:
			return
		case <-ticker.C:
			e.mu.Lock()
			tun := e.tun
			busy := e.busy
			def := append([]string(nil), e.deferred...)
			e.mu.Unlock()

			if len(def) > 0 && !e.radar.ActiveUDPInPrefixes(def, 25) {
				e.flushDeferredRoutes()
			}
			if tun != nil && !busy {
				e.measureTelemetryOnce()
			}
		}
	}
}

func (e *Engine) measureTelemetryOnce() {
	st := e.store.Get()
	g := games.FindGame(st.ActiveGameID, st.CustomGames)

	targetIP := ""
	for _, srv := range st.SeenServers[g.ID] {
		if !srv.Blocked {
			targetIP = srv.IP
			break
		}
	}
	if targetIP == "" {
		if len(g.VerifyTargets) > 0 {
			targetIP = g.VerifyTargets[0]
		} else {
			targetIP = "1.1.1.1"
		}
	}

	phys, _ := netwin.DefaultPhysicalInterface()
	bindIP := ""
	if phys != nil {
		bindIP = phys.IP
	}

	var directMs int
	if dStat := probe.MeasureDirect(targetIP, 0, bindIP, 2); dStat != nil {
		directMs = dStat.MedianMs
	}

	var boostedMs, jitterMs, lossPct, hop1Ms int
	e.mu.Lock()
	node := e.activeNode
	proto := e.activeProto
	e.mu.Unlock()

	if bStat := probe.MeasureDirect(targetIP, 0, "", 3); bStat != nil && bStat.Method == "ICMP" {
		boostedMs = bStat.MedianMs
		jitterMs = bStat.JitterMs
		lossPct = bStat.LossPct
	} else if st.Warp != nil && strings.HasPrefix(proto, "awg") && node.Endpoint != "" {
		prof := obf.BuildProfile(proto, st.MimicSNI)
		if sess, err := probe.NewProbeSession(st.Warp.PrivateKey, st.Warp.PeerPublicKey, "", st.Warp.IPv4, node.Endpoint, prof, bindIP); err == nil {
			if _, err := sess.Handshake(1000 * time.Millisecond); err == nil {
				if nMs, err := sess.PingICMP("1.1.1.1", 1, 800*time.Millisecond); err == nil {
					hop1Ms = int(nMs)
				}
				if gMs, err := sess.PingICMP(targetIP, 2, 1000*time.Millisecond); err == nil {
					boostedMs = int(gMs)
				} else if hop1Ms > 0 && directMs > 0 {
					boostedMs = hop1Ms + maxInt(8, directMs/2)
				}
			}
			sess.Close()
		}
	} else if proto == "proxy" && node.TunnelPingMs > 0 && directMs > 0 {
		hop1Ms = node.TunnelPingMs
		boostedMs = node.TunnelPingMs + maxInt(6, directMs/3)
	}

	if hop1Ms == 0 {
		hop1Ms = node.TunnelPingMs
		if hop1Ms == 0 && boostedMs > 0 {
			hop1Ms = boostedMs / 2
		}
	}
	hop2Ms := 0
	if boostedMs > hop1Ms {
		hop2Ms = boostedMs - hop1Ms
	}

	e.mu.Lock()
	if directMs > 0 {
		e.metrics.DirectPingMs = directMs
	}
	if boostedMs > 0 {
		e.metrics.BoostedPingMs = boostedMs
		e.metrics.Hop1NodeMs = hop1Ms
		e.metrics.Hop2GameMs = hop2Ms
		e.metrics.JitterMs = jitterMs
		e.metrics.LossPct = lossPct
		e.healthFails = 0
	} else {
		e.healthFails++
	}
	e.metrics.TargetServerIP = targetIP

	if boostedMs > 0 || directMs > 0 {
		e.history = append(e.history, PingSample{
			Timestamp: time.Now().Unix(),
			BoostedMs: boostedMs,
			DirectMs:  directMs,
		})
		if len(e.history) > 60 {
			e.history = e.history[len(e.history)-60:]
		}
	}
	fails := e.healthFails
	e.mu.Unlock()

	if fails >= 3 && st.AutoFailover && !e.radar.Snapshot().GameRunning {
		e.mu.Lock()
		e.healthFails = 0
		e.mu.Unlock()
		e.log("warn", "Текущий узел перестал отвечать — запускаю автоматическое переподключение…")
		_ = e.BoostOneClick(st.ActiveGameID)
		return
	}

	e.pushState()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
