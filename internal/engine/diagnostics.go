package engine

import (
	"abiroute/internal/config"
	"abiroute/internal/games"
	"abiroute/internal/netwin"
	"abiroute/internal/obf"
	"abiroute/internal/probe"
	"abiroute/internal/tunnel"
	"abiroute/internal/warp"
	"context"
	"fmt"
	"time"
)

type DiagStep struct {
	Step   int    `json:"step"`
	Title  string `json:"title"`
	Status string `json:"status"` // "ok" | "warn" | "fail"
	Detail string `json:"detail"`
}

type DiagReport struct {
	OverallOK      bool       `json:"overallOk"`
	Summary        string     `json:"summary"`
	Recommendation string     `json:"recommendation"`
	Steps          []DiagStep `json:"steps"`
}

// RunDiagnostics runs the 5-step GearUP-style network & DPI self-check.
func (e *Engine) RunDiagnostics() DiagReport {
	st := e.store.Get()
	game := games.FindGame(st.ActiveGameID, st.CustomGames)
	steps := make([]DiagStep, 0, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()

	// Step 1: Local Router & NIC
	phys, err := netwin.DefaultPhysicalInterface()
	bindIP := ""
	if err != nil || phys == nil {
		steps = append(steps, DiagStep{
			Step:   1,
			Title:  "Локальная сеть и роутер",
			Status: "fail",
			Detail: "Не обнаружено активное подключение к интернету",
		})
		return DiagReport{
			OverallOK:      false,
			Summary:        "Нет подключения к локальной сети или интернету.",
			Recommendation: "Проверьте кабель Ethernet или подключение Wi-Fi к роутеру.",
			Steps:          steps,
		}
	}
	bindIP = phys.IP
	gwDetail := fmt.Sprintf("%s (%s)", phys.AdapterName, phys.IP)
	gwStatus := "ok"
	if phys.Gateway != "" {
		if gwPing := probe.MeasureDirect(phys.Gateway, 0, bindIP, 3); gwPing != nil {
			gwDetail = fmt.Sprintf("Шлюз %s · %d мс · потери %d%%", phys.Gateway, gwPing.MedianMs, gwPing.LossPct)
			if gwPing.MedianMs > 15 || gwPing.LossPct > 0 {
				gwStatus = "warn"
			}
		}
	}
	steps = append(steps, DiagStep{
		Step:   1,
		Title:  "Локальная сеть и роутер",
		Status: gwStatus,
		Detail: gwDetail,
	})

	// Step 2: WARP Profile & DPI Obfuscation
	if st.Warp == nil && st.CustomTunnel == nil {
		acct, err := warp.RegisterWireGuard(ctx)
		if err != nil {
			steps = append(steps, DiagStep{
				Step:   2,
				Title:  "Профиль и доступ к API",
				Status: "fail",
				Detail: err.Error(),
			})
			return DiagReport{
				OverallOK:      false,
				Summary:        "Провайдер блокирует регистрацию WARP даже через DoH.",
				Recommendation: "Импортируйте готовый файл .conf или ключ vpn:// на вкладке «Узлы и обход DPI».",
				Steps:          steps,
			}
		}
		_ = e.store.Update(func(s *config.Settings) { s.Warp = acct })
		st = e.store.Get()
	}
	steps = append(steps, DiagStep{
		Step:   2,
		Title:  "Профиль и обход DPI",
		Status: "ok",
		Detail: fmt.Sprintf("Ключ активен · режим %s", protocolLabel(st.Protocol, st)),
	})

	// Step 3: Cloudflare Edge Node Reachability (AWG QUIC vs MASQUE :443)
	nodeOK := false
	nodeDetail := ""
	if st.Warp != nil {
		ep := "162.159.195.4:878"
		if len(st.Nodes) > 0 {
			ep = st.Nodes[0].Endpoint
		}
		prof := obf.BuildProfile("awg_quic", st.MimicSNI)
		if sess, err := probe.NewProbeSession(st.Warp.PrivateKey, st.Warp.PeerPublicKey, "", st.Warp.IPv4, ep, prof, bindIP); err == nil {
			if _, err := sess.Handshake(1400 * time.Millisecond); err == nil {
				if ms, err := sess.PingICMP("1.1.1.1", 1, 1000*time.Millisecond); err == nil {
					colo := sess.QueryColo(700 * time.Millisecond)
					code, city, _ := warp.LookupColo(colo)
					nodeOK = true
					nodeDetail = fmt.Sprintf("%s (%s) · %.0f мс по QUIC I1", city, code, ms)
				}
			}
			sess.Close()
		}
	}
	if !nodeOK && st.Masque != nil {
		if ms, err := tunnel.ProbeMASQUE(ctx, st.Masque, false, bindIP); err == nil {
			nodeOK = true
			nodeDetail = fmt.Sprintf("MASQUE HTTP/3 (:443) · %d мс", ms)
		}
	}
	if nodeOK {
		steps = append(steps, DiagStep{
			Step:   3,
			Title:  "Узел Cloudflare",
			Status: "ok",
			Detail: nodeDetail,
		})
	} else {
		steps = append(steps, DiagStep{
			Step:   3,
			Title:  "Узел Cloudflare",
			Status: "warn",
			Detail: "Требуется сканирование узлов или переключение на MASQUE :443",
		})
	}

	// Step 4: Wintun & Admin Readiness
	if netwin.IsAdmin() {
		_ = tunnel.EnsureWintunDLL()
		steps = append(steps, DiagStep{
			Step:   4,
			Title:  "Драйвер Wintun и права",
			Status: "ok",
			Detail: "Права администратора есть · WHQL wintun.dll готов",
		})
	} else {
		steps = append(steps, DiagStep{
			Step:   4,
			Title:  "Драйвер Wintun и права",
			Status: "fail",
			Detail: "Нет прав администратора для создания сетевого адаптера",
		})
	}

	// Step 5: Game Server Reachability
	target := "1.1.1.1"
	if len(game.VerifyTargets) > 0 {
		target = game.VerifyTargets[0]
	}
	if gp := probe.MeasureDirect(target, 443, bindIP, 2); gp != nil {
		steps = append(steps, DiagStep{
			Step:   5,
			Title:  "Серверы " + game.ShortCode,
			Status: "ok",
			Detail: fmt.Sprintf("%s отвечает (%d мс напрямую)", target, gp.MedianMs),
		})
	} else {
		steps = append(steps, DiagStep{
			Step:   5,
			Title:  "Серверы " + game.ShortCode,
			Status: "warn",
			Detail: fmt.Sprintf("Прямой доступ к %s ограничен — требуется туннель", target),
		})
	}

	overall := netwin.IsAdmin() && nodeOK
	rec := "Все проверки пройдены — нажмите «Ускорить в 1 клик»."
	if !netwin.IsAdmin() {
		rec = "Перезапустите ABI Route от имени администратора."
	} else if !nodeOK {
		rec = "Нажмите «Ускорить в 1 клик» в режиме «Авто» — программа сама переберёт узлы и MASQUE :443."
	}

	e.log("info", "Самодиагностика завершена: "+rec)
	return DiagReport{
		OverallOK:      overall,
		Summary:        fmt.Sprintf("Проверено 5 этапов для %s", game.Name),
		Recommendation: rec,
		Steps:          steps,
	}
}
