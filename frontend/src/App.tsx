import React, { useEffect, useMemo, useState } from 'react'
import { Bridge, formatBytes, formatDuration } from './lib/bridge'
import type { DashboardState, DiagReport } from './types'
import {
  ActivityIcon,
  BoltIcon,
  GlobeIcon,
  GridIcon,
  PlayIcon,
  RefreshIcon,
  SearchIcon,
  ShieldIcon,
  SlidersIcon,
} from './components/Icons'
import { RouteMap } from './components/RouteMap'
import { PingChart } from './components/PingChart'
import { AddGameModal, ImportModal, RouteEditorModal } from './components/Modals'

type TabKey = 'library' | 'boost' | 'nodes' | 'diag' | 'settings'
type NodePaneMode = 'warp' | 'proxy'

const PROTOCOLS = [
  {
    id: 'auto',
    title: 'Автоподбор WARP + MASQUE',
    badge: 'Умный',
    desc: 'Пробует AmneziaWG 2.0 QUIC → DNS → SIP и сам переходит на MASQUE HTTP/3 (:443), если провайдер блокирует UDP.',
  },
  {
    id: 'proxy',
    title: 'Свой VLESS / Hysteria2 / Подписка',
    badge: 'Свой VPS',
    desc: 'Точечный split-tunnel только для серверов игры через ваши ссылки vless:// (Reality/TLS), hy2://, trojan://, ss://.',
  },
  {
    id: 'awg_quic',
    title: 'AmneziaWG 2.0 · Маскировка QUIC',
    badge: 'Мин. пинг',
    desc: 'Отправляет настоящий TLS 1.3 ClientHello (HTTP/3 >=1200 байт) перед рукопожатием.',
  },
  {
    id: 'masque_h3',
    title: 'WARP MASQUE · HTTP/3 (:443)',
    badge: 'Анти-ТСПУ',
    desc: 'Официальный протокол Connect-IP поверх QUIC на порт 443 при полной блокировке WireGuard.',
  },
  {
    id: 'masque_h2',
    title: 'WARP MASQUE · HTTP/2 TCP (:443)',
    badge: 'Резерв TCP',
    desc: 'Туннель поверх обычного HTTPS/2 соединения TCP :443.',
  },
  {
    id: 'awg_dns',
    title: 'AmneziaWG 2.0 · Маскировка DNS',
    badge: 'Альтернатива',
    desc: 'Имитация стандартного DNS-запроса EDNS0 с обфускацией заголовков.',
  },
]

export const App: React.FC = () => {
  const [state, setState] = useState<DashboardState | null>(null)
  const [tab, setTab] = useState<TabKey>('library')
  const [nodePane, setNodePane] = useState<NodePaneMode>('warp')
  const [search, setSearch] = useState('')
  const [scanProg, setScanProg] = useState<{ done: number; total: number } | null>(null)
  const [diag, setDiag] = useState<DiagReport | null>(null)
  const [diagRunning, setDiagRunning] = useState(false)
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000))

  const [warpPlusInput, setWarpPlusInput] = useState('')
  const [subInput, setSubInput] = useState('')
  const [actionMsg, setActionMsg] = useState('')
  const [mtuTesting, setMtuTesting] = useState(false)

  const [addModal, setAddModal] = useState(false)
  const [importModal, setImportModal] = useState(false)
  const [routeModal, setRouteModal] = useState(false)

  useEffect(() => {
    Bridge.getState().then((st) => {
      setState(st)
      if (st.settings.subscriptionUrl) setSubInput(st.settings.subscriptionUrl)
      if (st.settings.protocol === 'proxy') setNodePane('proxy')
    })
    const offState = Bridge.onEvent('engine:state', (next: DashboardState) => {
      setState(next)
      if (!next.busy) setScanProg(null)
    })
    const offLog = Bridge.onEvent('engine:log', () => {
      Bridge.getState().then(setState)
    })
    const offProg = Bridge.onEvent('engine:scan_progress', (p: { done: number; total: number }) => {
      setScanProg(p)
    })
    const timer = setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 1000)
    return () => {
      offState()
      offLog()
      offProg()
      clearInterval(timer)
    }
  }, [])

  const filteredGames = useMemo(() => {
    if (!state) return []
    const q = search.trim().toLowerCase()
    return state.catalog.filter((g) => {
      if (!q) return true
      return (
        g.name.toLowerCase().includes(q) ||
        g.shortCode.toLowerCase().includes(q) ||
        g.processes.some((p) => p.toLowerCase().includes(q))
      )
    })
  }, [state, search])

  if (!state) {
    return (
      <div className="w-full h-full flex items-center justify-center bg-[#0d1015] text-[#a1acbd] text-sm">
        Загрузка ядра ABI Route 5.0…
      </div>
    )
  }

  const isBoosted = state.status === 'boosted'
  const activeGame = state.activeGame
  const otherGames = filteredGames.filter((g) => g.id !== activeGame.id)
  const pingDelta =
    state.routeMetrics.directPingMs > 0 && state.routeMetrics.boostedPingMs > 0
      ? state.routeMetrics.directPingMs - state.routeMetrics.boostedPingMs
      : 0

  const flashMsg = (msg: string) => {
    setActionMsg(msg)
    setTimeout(() => setActionMsg(''), 4000)
  }

  const handleBoostGame = async (gameId: string) => {
    setTab('boost')
    await Bridge.boostOneClick(gameId)
  }

  const handleRunDiag = async () => {
    setTab('diag')
    setDiagRunning(true)
    try {
      const rep = await Bridge.runDiagnostics()
      setDiag(rep)
    } finally {
      setDiagRunning(false)
    }
  }

  const handleWarpPlus = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!warpPlusInput.trim()) return
    try {
      const next = await Bridge.applyWarpPlus(warpPlusInput)
      setState(next)
      setWarpPlusInput('')
      flashMsg('Ключ WARP+ активирован!')
    } catch (ex: any) {
      flashMsg(typeof ex === 'string' ? ex : ex?.message || 'Ошибка привязки WARP+')
    }
  }

  const handleSyncSub = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!subInput.trim()) return
    try {
      const next = await Bridge.syncSubscription(subInput)
      setState(next)
      flashMsg(`Подписка обновлена: ${next.settings.proxies.length} серверов`)
    } catch (ex: any) {
      flashMsg(typeof ex === 'string' ? ex : ex?.message || 'Ошибка загрузки подписки')
    }
  }

  const handleAutoMTU = async () => {
    setMtuTesting(true)
    try {
      const next = await Bridge.autoOptimizeMTU()
      setState(next)
      flashMsg(`Оптимальный MTU установлен: ${next.settings.mtu}`)
    } finally {
      setMtuTesting(false)
    }
  }

  const saveSysPref = async (patch: Partial<typeof state.settings>) => {
    const s = { ...state.settings, ...patch }
    const next = await Bridge.updateSystemPrefs(
      s.autoBoost,
      s.autoStopOnExit,
      s.closeToTray,
      s.startWithWindows,
      s.globalHotkey,
      s.mtu
    )
    setState(next)
  }

  return (
    <div className="flex w-full h-full min-w-0 min-h-0 bg-[#0d1015] text-[#f3f6fa]">
      {/* Responsive Left Sidebar: collapses to 68px icon rail below 920px so nothing ever clips */}
      <aside className="w-[68px] min-[920px]:w-[224px] shrink-0 flex flex-col justify-between p-2.5 min-[920px]:p-4 bg-[#0a0d11] border-r border-white/[0.07] transition-[width] duration-150">
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-center min-[920px]:justify-start gap-3 px-1 pt-1 pb-4">
            <div className="w-9 h-9 rounded-xl bg-[#22d37b]/12 border border-[#22d37b]/35 flex items-center justify-center text-[#22d37b] shrink-0">
              <BoltIcon className="w-5 h-5" />
            </div>
            <div className="hidden min-[920px]:block min-w-0">
              <div className="text-[16px] font-bold tracking-tight leading-none truncate">ABI Route</div>
              <div className="text-[11px] text-[#a1acbd] mt-1 truncate">Game Booster · v{state.version}</div>
            </div>
          </div>

          <nav className="flex flex-col gap-1">
            {(
              [
                ['library', 'Мои игры', GridIcon],
                ['boost', 'Ускорение', ActivityIcon],
                ['nodes', 'Узлы и прокси', GlobeIcon],
                ['diag', 'Радар и фильтр', ShieldIcon],
                ['settings', 'Настройки', SlidersIcon],
              ] as const
            ).map(([key, label, Icon]) => {
              const active = tab === key
              return (
                <button
                  key={key}
                  onClick={() => setTab(key)}
                  title={label}
                  className={`flex items-center justify-center min-[920px]:justify-start gap-2.5 px-2.5 min-[920px]:px-3 py-2.5 rounded-xl text-sm transition cursor-pointer relative ${
                    active
                      ? 'bg-[#22d37b]/12 text-[#22d37b] font-semibold shadow-[inset_0_0_0_1px_rgba(34,211,123,0.35)]'
                      : 'text-[#a1acbd] hover:bg-[#131820] hover:text-[#f3f6fa] font-medium'
                  }`}
                >
                  <Icon className="w-4.5 h-4.5 shrink-0" />
                  <span className="hidden min-[920px]:inline truncate">{label}</span>
                  {key === 'boost' && isBoosted && (
                    <span className="w-2 h-2 rounded-full bg-[#22d37b] animate-pulse min-[920px]:ml-auto max-[919px]:absolute max-[919px]:top-2 max-[919px]:right-2" />
                  )}
                </button>
              )
            })}
          </nav>
        </div>

        {/* Bottom Status Card (expands on wide, dot indicator on narrow) */}
        <div className="p-2.5 min-[920px]:p-3 rounded-xl bg-[#131820] border border-white/[0.07] flex flex-col gap-2 text-xs">
          <div className="flex items-center justify-center min-[920px]:justify-start gap-2 font-semibold">
            <span
              className={`w-2.5 h-2.5 rounded-full shrink-0 ${
                isBoosted ? 'bg-[#22d37b]' : state.busy ? 'bg-amber-400 animate-pulse' : 'bg-[#7b8798]'
              }`}
            />
            <span className="hidden min-[920px]:inline truncate">
              {isBoosted ? 'В работе' : state.busy ? 'Подключение…' : 'Wintun готов'}
            </span>
          </div>
          <div className="hidden min-[920px]:flex items-center justify-between text-[11px] text-[#a1acbd]">
            <span>{activeGame.shortCode}</span>
            <span className={state.radar.gameRunning ? 'text-[#22d37b] font-semibold' : 'text-[#7b8798]'}>
              {state.radar.gameRunning ? 'Игра запущена' : 'Ожидание'}
            </span>
          </div>
          <div className="hidden min-[920px]:flex items-center justify-between text-[11px] text-[#a1acbd]">
            <span>Трафик</span>
            <span className="font-mono-num truncate">
              ↓{formatBytes(state.tunnelStats.rxBytes)} ↑{formatBytes(state.tunnelStats.txBytes)}
            </span>
          </div>
        </div>
      </aside>

      {/* Main Scrollable & Responsive Workspace */}
      <main className="flex flex-col flex-1 min-w-0 min-h-0">
        {/* Clean Header Bar */}
        <header className="min-h-[52px] px-4 sm:px-6 py-2 border-b border-white/[0.07] flex items-center justify-between gap-3 flex-wrap shrink-0 bg-[#0d1015]">
          <div className="flex items-center gap-2.5 min-w-0 flex-1">
            {tab === 'library' ? (
              <label className="flex items-center gap-2 bg-[#131820] border border-white/[0.08] rounded-xl px-3 py-1.5 w-full max-w-[290px] text-[#a1acbd] focus-within:border-[#22d37b]/50">
                <SearchIcon className="w-4 h-4 shrink-0" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Поиск игры или процесса (.exe)…"
                  className="bg-transparent border-none outline-none text-xs text-[#f3f6fa] placeholder-[#7b8798] w-full min-w-0"
                />
              </label>
            ) : (
              <div className="flex items-center gap-2.5 min-w-0">
                <button
                  onClick={() => setTab('library')}
                  className="px-2.5 py-1 rounded-lg bg-[#131820] hover:bg-[#19202b] border border-white/[0.08] text-xs text-[#a1acbd] hover:text-[#f3f6fa] shrink-0 cursor-pointer"
                >
                  ← Игры
                </button>
                <span className="text-sm font-bold truncate">{activeGame.name}</span>
                <span className="hidden sm:inline-block px-2 py-0.5 rounded-md bg-[#131820] border border-white/[0.07] text-[11px] font-mono-num text-[#a1acbd] shrink-0">
                  {state.appliedRouteCount || state.effectiveRoutes.length} подсетей
                </span>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2 flex-wrap shrink-0">
            {actionMsg && (
              <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[#22d37b]/15 border border-[#22d37b]/35 text-[#22d37b]">
                {actionMsg}
              </span>
            )}
            {state.updateInfo.available && (
              <button
                onClick={() => Bridge.installUpdateNow()}
                className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-[#22d37b] text-[#061b10] cursor-pointer"
              >
                Обновить до v{state.updateInfo.latestVer}
              </button>
            )}
            {!state.isAdmin && (
              <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-amber-500/15 border border-amber-500/35 text-amber-300">
                Нужен запуск от Админа
              </span>
            )}
            {state.settings.globalHotkey && (
              <span className="hidden md:inline-flex px-2.5 py-1 rounded-full text-[11px] font-mono-num bg-[#131820] border border-white/[0.08] text-[#a1acbd]">
                Alt+F9 вкл/выкл
              </span>
            )}
            {isBoosted && (
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-[#22d37b]/12 border border-[#22d37b]/35 text-[#22d37b] font-mono-num">
                {formatDuration(state.startedAt, nowSec)}
              </span>
            )}
            <button
              onClick={() => Bridge.hideToTray()}
              title="Спрятать окно в системный трей у часов"
              className="px-2.5 py-1 rounded-lg text-xs font-medium bg-[#131820] hover:bg-[#19202b] border border-white/[0.08] text-[#a1acbd] hover:text-[#f3f6fa] cursor-pointer"
            >
              В трей
            </button>
          </div>
        </header>

        {/* Progress Bar */}
        {state.busy && (
          <div className="h-1 w-full bg-[#19202b] overflow-hidden shrink-0">
            <div
              className="h-full bg-[#22d37b] transition-all duration-200"
              style={{
                width: scanProg && scanProg.total > 0 ? `${Math.round((scanProg.done / scanProg.total) * 100)}%` : '45%',
              }}
            />
          </div>
        )}

        {/* Scrollable Content Container — prevents any vertical clipping at smaller heights */}
        <div className="p-4 sm:p-6 flex-1 overflow-y-auto overflow-x-hidden flex flex-col gap-4 min-w-0">
          {/* TAB 1: GAME LIBRARY */}
          {tab === 'library' && (
            <>
              <section
                className="grid grid-cols-1 min-[880px]:grid-cols-[1.3fr_1fr] gap-4 p-4 sm:p-5 rounded-2xl border border-[#22d37b]/35 items-center min-w-0"
                style={{
                  background:
                    'radial-gradient(120% 140% at 0% 0%, rgba(34,211,123,0.14) 0%, rgba(19,24,32,0.97) 58%), #131820',
                }}
              >
                <div className="flex flex-col gap-2.5 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#22d37b]/14 border border-[#22d37b]/35 text-[#22d37b]">
                      Выбранная игра · ETW-радар
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono-num bg-[#0d1015]/80 border border-white/[0.08] text-[#a1acbd]">
                      {activeGame.processes[0]}
                    </span>
                    {state.settings.warp?.warpPlus && (
                      <span className="px-2 py-0.5 rounded-full text-[11px] font-bold bg-[#22d37b] text-[#061b10]">
                        WARP+
                      </span>
                    )}
                  </div>
                  <h1 className="text-xl sm:text-[25px] font-bold tracking-tight leading-tight">{activeGame.name}</h1>
                  <p className="text-xs sm:text-[13px] text-[#a1acbd] leading-relaxed">{activeGame.description}</p>
                  <div className="flex items-center gap-2 flex-wrap pt-1">
                    {isBoosted ? (
                      <button
                        onClick={() => setTab('boost')}
                        className="px-5 py-2.5 rounded-xl text-sm font-bold bg-[#22d37b] hover:bg-[#3ae08e] text-[#061b10] flex items-center gap-2 cursor-pointer active:scale-[0.98]"
                      >
                        <ActivityIcon className="w-4 h-4" />
                        Телеметрия ({state.routeMetrics.boostedPingMs || '…'} мс)
                      </button>
                    ) : (
                      <button
                        onClick={() => handleBoostGame(activeGame.id)}
                        disabled={state.busy}
                        className="px-5 py-2.5 rounded-xl text-sm font-bold bg-[#22d37b] hover:bg-[#3ae08e] disabled:opacity-50 text-[#061b10] flex items-center gap-2 cursor-pointer active:scale-[0.98]"
                      >
                        <BoltIcon className="w-4 h-4" />
                        {state.busy ? 'Подключение…' : 'Ускорить в 1 клик'}
                      </button>
                    )}
                    <button
                      onClick={() =>
                        Bridge.launchActiveGame().catch((e: any) =>
                          flashMsg(typeof e === 'string' ? e : e?.message || 'Запустите игру с ярлыка')
                        )
                      }
                      className="px-3.5 py-2.5 rounded-xl text-xs sm:text-sm font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] flex items-center gap-1.5 cursor-pointer"
                    >
                      <PlayIcon className="w-3.5 h-3.5 text-[#22d37b]" />
                      Запустить игру
                    </button>
                    <button
                      onClick={() => setTab('nodes')}
                      className="px-3.5 py-2.5 rounded-xl text-xs sm:text-sm font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] cursor-pointer"
                    >
                      Узел / VLESS
                    </button>
                  </div>
                </div>

                <div className="bg-[#0a0d11]/75 border border-white/[0.08] rounded-xl p-3 flex flex-col gap-2 min-w-0">
                  <div className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-[#131820] border border-white/[0.06] text-xs">
                    <span className="text-[#a1acbd] shrink-0">Узел</span>
                    <button onClick={() => setTab('nodes')} className="font-semibold truncate cursor-pointer">
                      {state.activeNode.city || 'Автовыбор (Лучший)'}{' '}
                      {state.activeNode.tunnelPingMs > 0 && (
                        <span className="text-[#22d37b] font-mono-num">{state.activeNode.tunnelPingMs} мс</span>
                      )}
                    </button>
                  </div>
                  <div className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-[#131820] border border-white/[0.06] text-xs">
                    <span className="text-[#a1acbd] shrink-0">Движок</span>
                    <button onClick={() => setTab('nodes')} className="font-semibold truncate cursor-pointer">
                      {state.activeProtocolTitle}
                    </button>
                  </div>
                  <div className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-[#131820] border border-white/[0.06] text-xs">
                    <span className="text-[#a1acbd] shrink-0">Фильтр пинга</span>
                    <button
                      onClick={() => setTab('diag')}
                      className={`font-semibold cursor-pointer ${
                        state.settings.blockHighPing ? 'text-[#22d37b]' : 'text-[#a1acbd]'
                      }`}
                    >
                      {state.settings.blockHighPing ? `Блок > ${state.settings.maxPingThresholdMs} мс` : 'Выключен'}
                    </button>
                  </div>
                  <div className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-[#131820] border border-white/[0.06] text-xs">
                    <span className="text-[#a1acbd] shrink-0">Авто-буст / MTU</span>
                    <button onClick={() => setTab('settings')} className="font-semibold text-[#a1acbd] cursor-pointer">
                      {state.settings.autoBoost ? 'Авто ВКЛ' : 'Вручную'} · MTU {state.settings.mtu}
                    </button>
                  </div>
                </div>
              </section>

              <div className="flex items-baseline justify-between gap-2 flex-wrap pt-1">
                <h2 className="text-base font-bold tracking-tight">Каталог игр и приложений</h2>
                <span className="text-xs text-[#a1acbd]">Любая игра ускоряется точечно без VPN на весь ПК</span>
              </div>

              <section className="grid grid-cols-1 sm:grid-cols-2 min-[1020px]:grid-cols-4 gap-3">
                {otherGames.map((g) => (
                  <article
                    key={g.id}
                    className="bg-[#131820] hover:bg-[#19202b] border border-white/[0.08] hover:border-white/[0.15] rounded-2xl p-3.5 flex flex-col justify-between gap-3 transition min-w-0"
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2">
                        <div className="w-9 h-9 rounded-xl bg-[#19202b] border border-white/[0.12] flex items-center justify-center text-xs font-bold tracking-tight shrink-0">
                          {g.shortCode}
                        </div>
                        <span className="px-2 py-0.5 rounded-full text-[10.5px] bg-[#0d1015] border border-white/[0.07] text-[#a1acbd]">
                          {g.custom ? 'Свой .exe' : 'Пресет + ETW'}
                        </span>
                      </div>
                      <div className="font-bold text-sm mt-2.5 truncate">{g.name}</div>
                      <div className="text-[11.5px] text-[#a1acbd] truncate mt-0.5">{g.regionHint}</div>
                    </div>

                    <div className="flex items-center justify-between pt-2.5 border-t border-white/[0.07]">
                      <button
                        onClick={() => Bridge.selectGame(g.id).then(setState)}
                        className="text-xs text-[#a1acbd] hover:text-[#f3f6fa] font-medium cursor-pointer"
                      >
                        Выбрать
                      </button>
                      <button
                        onClick={() => handleBoostGame(g.id)}
                        className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#22d37b] hover:text-[#061b10] border border-white/[0.12] transition cursor-pointer"
                      >
                        Ускорить
                      </button>
                    </div>
                  </article>
                ))}

                <article
                  onClick={() => setAddModal(true)}
                  className="bg-[#131820]/70 hover:bg-[#19202b] border border-dashed border-white/[0.16] hover:border-[#22d37b]/50 rounded-2xl p-3.5 flex flex-col justify-between gap-3 transition cursor-pointer min-w-0"
                >
                  <div>
                    <div className="flex items-start justify-between">
                      <div className="w-9 h-9 rounded-xl bg-[#22d37b]/12 border border-[#22d37b]/35 text-[#22d37b] flex items-center justify-center text-lg font-bold">
                        +
                      </div>
                      <span className="px-2 py-0.5 rounded-full text-[10.5px] bg-[#0d1015] border border-white/[0.07] text-[#a1acbd]">
                        Любой .exe
                      </span>
                    </div>
                    <div className="font-bold text-sm mt-2.5">Добавить свою игру</div>
                    <div className="text-[11.5px] text-[#a1acbd] mt-0.5">Игра, лаунчер или Discord</div>
                  </div>
                  <div className="flex items-center justify-between pt-2.5 border-t border-white/[0.07]">
                    <span className="text-[11.5px] text-[#22d37b] font-semibold">ETW-автопоиск</span>
                    <span className="text-xs font-semibold">Настроить →</span>
                  </div>
                </article>
              </section>

              <section className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                <div className="flex items-center justify-between gap-3 p-3.5 rounded-xl bg-[#131820] border border-white/[0.07] min-w-0">
                  <div className="min-w-0">
                    <div className="text-[13px] font-semibold truncate">Свой VLESS / Hysteria2 / подписка / vpn://</div>
                    <div className="text-[11.5px] text-[#a1acbd] truncate">
                      Вставьте ключ vless://, hy2://, ссылку подписки или файл .conf
                    </div>
                  </div>
                  <button
                    onClick={() => setImportModal(true)}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] shrink-0 cursor-pointer"
                  >
                    Импорт
                  </button>
                </div>

                <div className="flex items-center justify-between gap-3 p-3.5 rounded-xl bg-[#131820] border border-white/[0.07] min-w-0">
                  <div className="min-w-0">
                    <div className="text-[13px] font-semibold truncate">Блокировка далёких серверов и диагностика</div>
                    <div className="text-[11.5px] text-[#a1acbd] truncate">
                      Отсечь серверы Азии/США с высоким пингом и проверить сеть
                    </div>
                  </div>
                  <button
                    onClick={handleRunDiag}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] shrink-0 cursor-pointer"
                  >
                    Открыть
                  </button>
                </div>
              </section>
            </>
          )}

          {/* TAB 2: BOOST COCKPIT */}
          {tab === 'boost' && (
            <>
              <div className="flex items-center justify-between gap-3 flex-wrap bg-[#131820] border border-white/[0.08] rounded-2xl px-4 sm:px-5 py-3.5">
                <div className="min-w-0">
                  <div className="text-sm font-bold text-[#f3f6fa] break-words">{state.statusText}</div>
                  <div className="text-xs text-[#a1acbd] mt-0.5 truncate">
                    Процессы: {activeGame.processes.join(', ')}
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap shrink-0">
                  <button
                    onClick={() =>
                      Bridge.launchActiveGame().catch((e: any) =>
                        flashMsg(typeof e === 'string' ? e : e?.message || 'Запустите игру с ярлыка')
                      )
                    }
                    className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] flex items-center gap-1.5 cursor-pointer"
                  >
                    <PlayIcon className="w-3.5 h-3.5 text-[#22d37b]" />
                    Запустить игру
                  </button>
                  {state.busy && (
                    <button
                      onClick={() => Bridge.cancelOperation()}
                      className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-amber-500/15 border border-amber-500/35 text-amber-300 cursor-pointer"
                    >
                      Прервать
                    </button>
                  )}
                  {isBoosted ? (
                    <button
                      onClick={() => Bridge.stopBoost().then(setState)}
                      className="px-5 py-2 rounded-xl text-sm font-semibold bg-red-500/14 hover:bg-red-500/24 border border-red-500/35 text-red-300 cursor-pointer"
                    >
                      Остановить
                    </button>
                  ) : (
                    <button
                      onClick={() => Bridge.boostOneClick(activeGame.id)}
                      disabled={state.busy}
                      className="px-5 py-2 rounded-xl text-sm font-bold bg-[#22d37b] hover:bg-[#3ae08e] disabled:opacity-50 text-[#061b10] flex items-center gap-2 cursor-pointer"
                    >
                      <BoltIcon className="w-4 h-4" />
                      Ускорить сейчас
                    </button>
                  )}
                </div>
              </div>

              <section className="grid grid-cols-1 min-[900px]:grid-cols-[252px_1fr] gap-4 min-w-0">
                <div
                  className="rounded-2xl p-5 border border-[#22d37b]/35 flex flex-col justify-between min-w-0"
                  style={{
                    background:
                      'radial-gradient(110% 110% at 50% 0%, rgba(34,211,123,0.14) 0%, rgba(19,24,32,0.98) 68%), #131820',
                  }}
                >
                  <div>
                    <div className="text-xs font-semibold text-[#a1acbd]">Честный пинг до сервера игры</div>
                    <div className="mt-2 flex items-baseline gap-1.5">
                      <span className="text-[48px] font-bold leading-none tracking-tight text-[#22d37b] font-mono-num">
                        {state.routeMetrics.boostedPingMs > 0
                          ? state.routeMetrics.boostedPingMs
                          : state.routeMetrics.directPingMs > 0
                          ? state.routeMetrics.directPingMs
                          : '—'}
                      </span>
                      <span className="text-lg font-semibold text-[#a1acbd]">мс</span>
                    </div>
                    <div className="mt-2.5 inline-flex items-center px-2.5 py-1 rounded-lg bg-[#22d37b]/12 text-[#22d37b] text-xs font-semibold">
                      {pingDelta > 2
                        ? `На ${pingDelta} мс быстрее прямого (${state.routeMetrics.directPingMs} мс)`
                        : isBoosted
                        ? 'Защищённый маршрут активен'
                        : 'Туннель сейчас выключен'}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 pt-3.5 mt-3.5 border-t border-white/[0.08]">
                    <div>
                      <div className="text-[11px] text-[#a1acbd]">Потери пакетов</div>
                      <div className="text-base font-bold font-mono-num text-[#22d37b] mt-0.5">
                        {state.routeMetrics.lossPct}%
                      </div>
                    </div>
                    <div>
                      <div className="text-[11px] text-[#a1acbd]">Джиттер</div>
                      <div className="text-base font-bold font-mono-num mt-0.5">±{state.routeMetrics.jitterMs} мс</div>
                    </div>
                  </div>
                </div>

                <RouteMap
                  boosted={isBoosted}
                  node={state.activeNode}
                  metrics={state.routeMetrics}
                  gameShort={activeGame.shortCode}
                  onChangeNode={() => setTab('nodes')}
                />
              </section>

              <section className="grid grid-cols-1 min-[940px]:grid-cols-[1.35fr_1fr] gap-4 min-w-0">
                <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-4 sm:p-5 flex flex-col justify-between gap-3 min-w-0">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div>
                      <div className="text-sm font-bold">Стабильность соединения</div>
                      <div className="text-[11.5px] text-[#a1acbd]">
                        Зелёная линия — через туннель · Серая пунктирная — напрямую мимо туннеля
                      </div>
                    </div>
                    {state.deferredRouteCount > 0 && (
                      <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-amber-500/15 text-amber-300">
                        Ждут конца боя: {state.deferredRouteCount}
                      </span>
                    )}
                  </div>

                  <PingChart samples={state.history} boosted={isBoosted} />

                  <div className="flex items-center justify-between gap-3 text-xs text-[#a1acbd]">
                    <span className="truncate">
                      {state.logs.length > 0
                        ? `${state.logs[state.logs.length - 1].time} · ${state.logs[state.logs.length - 1].message}`
                        : 'Готов к работе'}
                    </span>
                    <button
                      onClick={() => setTab('diag')}
                      className="text-[#22d37b] font-semibold whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Все серверы →
                    </button>
                  </div>
                </div>

                <div className="flex flex-col justify-between gap-2.5 min-w-0">
                  <div className="p-3.5 rounded-xl bg-[#131820] border border-white/[0.08] flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-[13px] font-semibold truncate">Движок и протокол</div>
                      <div className="text-[11.5px] text-[#a1acbd] truncate">{state.activeProtocolTitle}</div>
                    </div>
                    <button
                      onClick={() => setTab('nodes')}
                      className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-[#22d37b]/12 border border-[#22d37b]/35 text-[#22d37b] shrink-0 cursor-pointer"
                    >
                      Изменить
                    </button>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#131820] border border-white/[0.08] flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-[13px] font-semibold">Защита активного рейда</div>
                      <div className="text-[11.5px] text-[#a1acbd]">Не рвать UDP-поток во время боя</div>
                    </div>
                    <button
                      onClick={() =>
                        Bridge.updateOptions(
                          state.settings.protocol,
                          state.settings.selectedEndpoint,
                          !state.settings.raidProtection,
                          state.settings.autoFailover,
                          state.settings.autoLearn,
                          state.settings.subnetPrefix
                        ).then(setState)
                      }
                      className={`px-3 py-1 rounded-lg text-xs font-semibold border shrink-0 cursor-pointer ${
                        state.settings.raidProtection
                          ? 'bg-[#22d37b]/14 border-[#22d37b]/35 text-[#22d37b]'
                          : 'bg-[#19202b] border-white/[0.1] text-[#a1acbd]'
                      }`}
                    >
                      {state.settings.raidProtection ? 'Активна' : 'Выкл'}
                    </button>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#131820] border border-white/[0.08] flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-[13px] font-semibold">Блокировка высокого пинга</div>
                      <div className="text-[11.5px] text-[#a1acbd]">
                        Отсекать серверы {`> ${state.settings.maxPingThresholdMs} мс`} (блок: {state.settings.blockedIps.length})
                      </div>
                    </div>
                    <button
                      onClick={() =>
                        Bridge.setHighPingFilter(!state.settings.blockHighPing, state.settings.maxPingThresholdMs).then(setState)
                      }
                      className={`px-3 py-1 rounded-lg text-xs font-semibold border shrink-0 cursor-pointer ${
                        state.settings.blockHighPing
                          ? 'bg-[#22d37b]/14 border-[#22d37b]/35 text-[#22d37b]'
                          : 'bg-[#19202b] border-white/[0.1] text-[#a1acbd]'
                      }`}
                    >
                      {state.settings.blockHighPing ? 'Активна' : 'Выкл'}
                    </button>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#131820] border border-white/[0.08] flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-[13px] font-semibold">Размер пакета (MTU {state.settings.mtu})</div>
                      <div className="text-[11.5px] text-[#a1acbd]">Убирает микрофризы от фрагментации</div>
                    </div>
                    <button
                      onClick={handleAutoMTU}
                      disabled={mtuTesting}
                      className="px-3 py-1 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] shrink-0 cursor-pointer"
                    >
                      {mtuTesting ? 'Тест…' : 'Авто-MTU'}
                    </button>
                  </div>
                </div>
              </section>
            </>
          )}

          {/* TAB 3: NODES, VLESS/HY2 & ANTI-DPI */}
          {tab === 'nodes' && (
            <section className="grid grid-cols-1 min-[940px]:grid-cols-[1.25fr_1fr] gap-4 min-w-0">
              <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-4 sm:p-5 flex flex-col gap-3 min-w-0">
                {/* Switcher: Cloudflare WARP vs VLESS / Hysteria2 */}
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-1.5 bg-[#0d1015] p-1 rounded-xl border border-white/[0.07]">
                    <button
                      onClick={() => setNodePane('warp')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ${
                        nodePane === 'warp' ? 'bg-[#22d37b] text-[#061b10] font-bold' : 'text-[#a1acbd]'
                      }`}
                    >
                      Узлы Cloudflare WARP
                    </button>
                    <button
                      onClick={() => setNodePane('proxy')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ${
                        nodePane === 'proxy' ? 'bg-[#22d37b] text-[#061b10] font-bold' : 'text-[#a1acbd]'
                      }`}
                    >
                      Свои VLESS / Hysteria2 ({state.settings.proxies.length})
                    </button>
                  </div>

                  {nodePane === 'warp' ? (
                    <button
                      onClick={() => Bridge.scanEndpoints()}
                      disabled={state.busy}
                      className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] disabled:opacity-50 border border-white/[0.12] flex items-center gap-1.5 cursor-pointer"
                    >
                      <RefreshIcon className={`w-3.5 h-3.5 ${state.busy ? 'animate-spin' : ''}`} />
                      {scanProg ? `${scanProg.done}/${scanProg.total}` : 'Сканировать (420)'}
                    </button>
                  ) : (
                    <button
                      onClick={() => setImportModal(true)}
                      className="px-3 py-1.5 rounded-xl text-xs font-bold bg-[#22d37b] hover:bg-[#3ae08e] text-[#061b10] cursor-pointer"
                    >
                      + Добавить ключ
                    </button>
                  )}
                </div>

                {nodePane === 'warp' ? (
                  <>
                    {/* WARP+ Argo License Bar */}
                    <form onSubmit={handleWarpPlus} className="flex items-center gap-2">
                      <input
                        value={warpPlusInput}
                        onChange={(e) => setWarpPlusInput(e.target.value)}
                        placeholder={
                          state.settings.warp?.warpPlus
                            ? 'WARP+ активен (Argo Smart Routing) — ввести другой ключ'
                            : 'Ключ WARP+ из приложения 1.1.1.1 (Argo Smart Routing)…'
                        }
                        className="flex-1 min-w-0 px-3 py-1.5 rounded-xl bg-[#0d1015] border border-white/[0.09] text-xs text-[#f3f6fa] font-mono-num outline-none focus:border-[#22d37b]"
                      />
                      <button
                        type="submit"
                        disabled={!warpPlusInput.trim()}
                        className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] disabled:opacity-40 border border-white/[0.12] shrink-0 cursor-pointer"
                      >
                        Привязать WARP+
                      </button>
                    </form>

                    <div className="flex flex-col gap-2 max-h-[340px] overflow-y-auto pr-1">
                      <div
                        onClick={() =>
                          Bridge.updateOptions(
                            state.settings.protocol === 'proxy' ? 'auto' : state.settings.protocol,
                            'auto',
                            state.settings.raidProtection,
                            state.settings.autoFailover,
                            state.settings.autoLearn,
                            state.settings.subnetPrefix
                          ).then(setState)
                        }
                        className={`flex items-center justify-between gap-3 px-3.5 py-2.5 rounded-xl border cursor-pointer transition ${
                          state.settings.selectedEndpoint === 'auto' && state.settings.protocol !== 'proxy'
                            ? 'bg-[#22d37b]/12 border-[#22d37b]/40'
                            : 'bg-[#0d1015] border-white/[0.07] hover:border-white/[0.16]'
                        }`}
                      >
                        <div className="min-w-0">
                          <div className="text-sm font-semibold">Автоматический выбор (Лучший)</div>
                          <div className="text-[11.5px] text-[#a1acbd] truncate">
                            Самый быстрый рабочий узел по пингу, джиттеру и потерям
                          </div>
                        </div>
                        <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#22d37b]/15 text-[#22d37b] shrink-0">
                          {state.settings.nodes[0] ? `${state.settings.nodes[0].tunnelPingMs} мс` : 'Авто'}
                        </span>
                      </div>

                      {state.settings.nodes.map((n, idx) => {
                        const sel = state.settings.selectedEndpoint === n.endpoint && state.settings.protocol !== 'proxy'
                        return (
                          <div
                            key={n.endpoint}
                            onClick={() =>
                              Bridge.updateOptions(
                                state.settings.protocol === 'proxy' ? 'awg_quic' : state.settings.protocol,
                                n.endpoint,
                                state.settings.raidProtection,
                                state.settings.autoFailover,
                                state.settings.autoLearn,
                                state.settings.subnetPrefix
                              ).then(setState)
                            }
                            className={`flex items-center justify-between gap-3 px-3.5 py-2.5 rounded-xl border cursor-pointer transition ${
                              sel
                                ? 'bg-[#22d37b]/12 border-[#22d37b]/40'
                                : 'bg-[#0d1015] border-white/[0.07] hover:border-white/[0.16]'
                            }`}
                          >
                            <div className="min-w-0">
                              <div className="text-sm font-semibold truncate">
                                {n.city} · {n.country} ({n.coloCode})
                              </div>
                              <div className="text-[11.5px] text-[#a1acbd] font-mono-num truncate">
                                {n.endpoint} · ±{n.jitterMs} мс · потери {n.lossPct}%
                              </div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <span className="text-xs font-bold text-[#22d37b] font-mono-num">{n.tunnelPingMs} мс</span>
                              <span className="px-2 py-0.5 rounded-full text-[10.5px] bg-[#19202b] text-[#a1acbd]">
                                {sel ? 'Выбран' : `#${idx + 1}`}
                              </span>
                            </div>
                          </div>
                        )
                      })}
                    </div>

                    <div className="flex items-center justify-between gap-2 flex-wrap pt-2 border-t border-white/[0.07] mt-auto">
                      <button
                        onClick={() => Bridge.generateWarpProfile()}
                        disabled={state.busy}
                        className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.1] cursor-pointer"
                      >
                        Новый ключ WARP
                      </button>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setImportModal(true)}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.1] cursor-pointer"
                        >
                          Импорт .conf / vpn://
                        </button>
                        <button
                          onClick={() => Bridge.exportConfFile()}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.1] cursor-pointer"
                        >
                          Экспорт .conf
                        </button>
                      </div>
                    </div>
                  </>
                ) : (
                  <>
                    {/* Subscription URL Sync */}
                    <form onSubmit={handleSyncSub} className="flex items-center gap-2">
                      <input
                        value={subInput}
                        onChange={(e) => setSubInput(e.target.value)}
                        placeholder="Ссылка на подписку https://... (Happ / v2rayN / Marzban / 3x-ui)"
                        className="flex-1 min-w-0 px-3 py-1.5 rounded-xl bg-[#0d1015] border border-white/[0.09] text-xs text-[#f3f6fa] font-mono-num outline-none focus:border-[#22d37b]"
                      />
                      <button
                        type="submit"
                        disabled={!subInput.trim()}
                        className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] disabled:opacity-40 border border-white/[0.12] shrink-0 cursor-pointer"
                      >
                        Обновить подписку
                      </button>
                    </form>

                    <div className="flex flex-col gap-2 max-h-[360px] overflow-y-auto pr-1">
                      {state.settings.proxies.map((px) => {
                        const sel = state.settings.protocol === 'proxy' && state.settings.activeProxyId === px.id
                        return (
                          <div
                            key={px.id}
                            onClick={() => Bridge.selectProxy(px.id).then(setState)}
                            className={`flex items-center justify-between gap-3 px-3.5 py-2.5 rounded-xl border cursor-pointer transition ${
                              sel
                                ? 'bg-[#22d37b]/12 border-[#22d37b]/40'
                                : 'bg-[#0d1015] border-white/[0.07] hover:border-white/[0.16]'
                            }`}
                          >
                            <div className="min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-[#19202b] text-[#22d37b] uppercase">
                                  {px.scheme}
                                </span>
                                <span className="text-sm font-semibold truncate">{px.name}</span>
                              </div>
                              <div className="text-[11.5px] text-[#a1acbd] font-mono-num truncate mt-0.5">
                                {px.server}:{px.port}
                              </div>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              <span className="text-xs font-bold text-[#22d37b] font-mono-num">
                                {px.pingMs > 0 ? `${px.pingMs} мс` : 'ОК'}
                              </span>
                              <button
                                type="button"
                                onClick={(ev) => {
                                  ev.stopPropagation()
                                  Bridge.deleteProxy(px.id).then(setState)
                                }}
                                className="px-2 py-0.5 rounded-md text-xs text-[#a1acbd] hover:text-red-400 hover:bg-red-500/10 cursor-pointer"
                              >
                                ✕
                              </button>
                            </div>
                          </div>
                        )
                      })}

                      {state.settings.proxies.length === 0 && (
                        <div className="p-6 rounded-xl bg-[#0d1015]/60 border border-white/[0.06] text-center text-xs text-[#a1acbd]">
                          Вставьте ссылку подписки выше или нажмите «+ Добавить ключ», чтобы подключить свой VLESS (Reality/TLS), Hysteria2, Trojan или Shadowsocks сервер. Ядро sing-box скачается автоматически при первом запуске.
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>

              {/* Right: Protocol Engine Selector */}
              <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-4 sm:p-5 flex flex-col justify-between gap-3 min-w-0">
                <div className="flex flex-col gap-2">
                  <div>
                    <h2 className="text-base font-bold">Движок туннеля и обход DPI</h2>
                    <p className="text-xs text-[#a1acbd]">Выберите протокол под вашего провайдера</p>
                  </div>

                  {PROTOCOLS.map((p) => {
                    const sel = state.settings.protocol === p.id
                    return (
                      <div
                        key={p.id}
                        onClick={() => {
                          if (p.id === 'proxy') setNodePane('proxy')
                          Bridge.updateOptions(
                            p.id,
                            state.settings.selectedEndpoint,
                            state.settings.raidProtection,
                            state.settings.autoFailover,
                            state.settings.autoLearn,
                            state.settings.subnetPrefix
                          ).then(setState)
                        }}
                        className={`p-3 rounded-xl border cursor-pointer transition ${
                          sel
                            ? 'bg-[#22d37b]/12 border-[#22d37b]/40'
                            : 'bg-[#0d1015] border-white/[0.07] hover:border-white/[0.16]'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[13px] font-bold">{p.title}</span>
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10.5px] font-semibold shrink-0 ${
                              sel ? 'bg-[#22d37b] text-[#061b10]' : 'bg-[#19202b] text-[#a1acbd]'
                            }`}
                          >
                            {sel ? 'Выбран' : p.badge}
                          </span>
                        </div>
                        <p className="text-[11px] text-[#a1acbd] mt-1 leading-relaxed">{p.desc}</p>
                      </div>
                    )
                  })}

                  {state.settings.customTunnel && (
                    <div
                      onClick={() =>
                        Bridge.updateOptions(
                          'custom',
                          state.settings.selectedEndpoint,
                          state.settings.raidProtection,
                          state.settings.autoFailover,
                          state.settings.autoLearn,
                          state.settings.subnetPrefix
                        ).then(setState)
                      }
                      className={`p-3 rounded-xl border cursor-pointer transition ${
                        state.settings.protocol === 'custom'
                          ? 'bg-[#22d37b]/12 border-[#22d37b]/40'
                          : 'bg-[#0d1015] border-white/[0.07]'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[13px] font-bold">{state.settings.customTunnel.name}</span>
                        <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-[#22d37b]/15 text-[#22d37b]">
                          .conf / vpn://
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                <button
                  onClick={() => handleBoostGame(activeGame.id)}
                  disabled={state.busy}
                  className="w-full py-2.5 rounded-xl text-sm font-bold bg-[#22d37b] hover:bg-[#3ae08e] disabled:opacity-50 text-[#061b10] cursor-pointer active:scale-[0.99]"
                >
                  {isBoosted ? 'Перезапустить с этими настройками' : 'Применить и ускорить'}
                </button>
              </div>
            </section>
          )}

          {/* TAB 4: RADAR, HIGH-PING SERVER BLOCKER & DIAGNOSTICS */}
          {tab === 'diag' && (
            <>
              {/* High-Ping Matchmaking Server Blocker */}
              <section className="bg-[#131820] border border-white/[0.08] rounded-2xl p-4 flex items-center justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <div className="text-sm font-bold flex items-center gap-2">
                    <span>Блокировщик серверов с высоким пингом (Гео-фильтр матчей)</span>
                    {state.settings.blockedIps.length > 0 && (
                      <span className="px-2 py-0.5 rounded-full text-[11px] bg-red-500/15 text-red-300 font-mono-num">
                        Заблокировано: {state.settings.blockedIps.length}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-[#a1acbd] mt-0.5">
                    Отсекает далёкие серверы Азии и США на этапе поиска матча, чтобы игра подключала к ближайшему региону.
                  </p>
                </div>

                <div className="flex items-center gap-2 flex-wrap shrink-0">
                  <span className="text-xs text-[#a1acbd]">Порог:</span>
                  {[90, 110, 130, 160].map((ms) => (
                    <button
                      key={ms}
                      onClick={() => Bridge.setHighPingFilter(state.settings.blockHighPing, ms).then(setState)}
                      className={`px-2.5 py-1 rounded-lg text-xs font-mono-num border cursor-pointer ${
                        state.settings.maxPingThresholdMs === ms
                          ? 'bg-[#22d37b]/15 border-[#22d37b]/40 text-[#22d37b] font-bold'
                          : 'bg-[#0d1015] border-white/[0.08] text-[#a1acbd]'
                      }`}
                    >
                      &gt;{ms} мс
                    </button>
                  ))}
                  <button
                    onClick={() =>
                      Bridge.setHighPingFilter(!state.settings.blockHighPing, state.settings.maxPingThresholdMs).then(setState)
                    }
                    className={`px-3.5 py-1.5 rounded-xl text-xs font-bold cursor-pointer ${
                      state.settings.blockHighPing
                        ? 'bg-[#22d37b] text-[#061b10]'
                        : 'bg-[#19202b] border border-white/[0.12] text-[#f3f6fa]'
                    }`}
                  >
                    {state.settings.blockHighPing ? 'Авто-блок ВКЛ' : 'Включить авто-блок'}
                  </button>
                  {state.settings.blockedIps.length > 0 && (
                    <button
                      onClick={() => Bridge.clearBlockedServers().then(setState)}
                      className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-red-500/15 border border-red-500/35 text-red-300 cursor-pointer"
                    >
                      Сбросить блок
                    </button>
                  )}
                </div>
              </section>

              {/* 5-Step Self-Diagnosis */}
              <section className="bg-[#131820] border border-white/[0.08] rounded-2xl p-4 flex flex-col gap-3">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div className="min-w-0">
                    <h2 className="text-sm font-bold">Самодиагностика трафика (5 этапов)</h2>
                    <p className="text-xs text-[#a1acbd]">
                      {diag ? diag.recommendation : 'Проверка локального роутера, обхода DPI, узла и доступности серверов игры'}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => setRouteModal(true)}
                      className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] cursor-pointer"
                    >
                      Редактор подсетей
                    </button>
                    <button
                      onClick={handleRunDiag}
                      disabled={diagRunning}
                      className="px-4 py-2 rounded-xl text-xs font-bold bg-[#22d37b] hover:bg-[#3ae08e] disabled:opacity-50 text-[#061b10] cursor-pointer"
                    >
                      {diagRunning ? 'Проверка…' : 'Проверить всё'}
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 min-[980px]:grid-cols-5 gap-2.5">
                  {(diag?.steps && diag.steps.length > 0
                    ? diag.steps
                    : [
                        { step: 1, title: 'Локальная сеть', status: 'ok', detail: 'Готово к тесту' },
                        { step: 2, title: 'Обход DPI', status: 'ok', detail: state.activeProtocolTitle },
                        { step: 3, title: 'Узел маршрута', status: 'ok', detail: state.activeNode.city || 'Автовыбор' },
                        { step: 4, title: 'Драйвер Wintun', status: state.isAdmin ? 'ok' : 'warn', detail: state.isAdmin ? 'Админ права ОК' : 'Нужен Админ' },
                        { step: 5, title: `Серверы ${activeGame.shortCode}`, status: 'ok', detail: `${state.effectiveRoutes.length} подсетей` },
                      ]
                  ).map((s) => {
                    const borderCol =
                      s.status === 'ok'
                        ? 'border-[#22d37b]/35'
                        : s.status === 'warn'
                        ? 'border-amber-500/40'
                        : 'border-red-500/45'
                    const badgeCol =
                      s.status === 'ok' ? 'text-[#22d37b]' : s.status === 'warn' ? 'text-amber-300' : 'text-red-400'
                    return (
                      <div key={s.step} className={`p-3 rounded-xl bg-[#0d1015] border ${borderCol} flex flex-col gap-1 min-w-0`}>
                        <div className={`flex items-center justify-between text-[11px] font-bold ${badgeCol}`}>
                          <span>Шаг {s.step}</span>
                          <span>{s.status === 'ok' ? 'ОК' : s.status === 'warn' ? 'ВНИМ' : 'СБОЙ'}</span>
                        </div>
                        <div className="text-xs font-semibold truncate">{s.title}</div>
                        <div className="text-[11px] text-[#a1acbd] truncate">{s.detail}</div>
                      </div>
                    )
                  })}
                </div>
              </section>

              {/* Radar Table + Event Log */}
              <section className="grid grid-cols-1 min-[1040px]:grid-cols-[1.45fr_1fr] gap-4 min-w-0">
                <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-4 flex flex-col gap-3 min-w-0">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div>
                      <h3 className="text-sm font-bold">
                        ETW-радар серверов {state.radar.etwActive ? '· Ядро активно' : '· Сокеты'}
                      </h3>
                      <p className="text-[11.5px] text-[#a1acbd]">
                        Нажмите «Блок» напротив далёкого сервера, чтобы запретить игре подключаться к нему
                      </p>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="text-[11px] text-[#a1acbd]">Охват:</span>
                      {[24, 20, 16].map((pfx) => (
                        <button
                          key={pfx}
                          onClick={() =>
                            Bridge.updateOptions(
                              state.settings.protocol,
                              state.settings.selectedEndpoint,
                              state.settings.raidProtection,
                              state.settings.autoFailover,
                              state.settings.autoLearn,
                              pfx
                            ).then(setState)
                          }
                          className={`px-2 py-0.5 rounded-md text-[11px] font-mono-num border cursor-pointer ${
                            state.settings.subnetPrefix === pfx
                              ? 'bg-[#22d37b]/15 border-[#22d37b]/40 text-[#22d37b] font-bold'
                              : 'bg-[#0d1015] border-white/[0.08] text-[#a1acbd]'
                          }`}
                        >
                          /{pfx}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="overflow-x-auto max-h-[280px] overflow-y-auto">
                    <table className="w-full text-xs border-collapse min-w-[460px]">
                      <thead>
                        <tr className="text-[#a1acbd] border-b border-white/[0.08]">
                          <th className="text-left py-2 px-2 font-semibold">Сервер</th>
                          <th className="text-left py-2 px-2 font-semibold">Регион / Роль</th>
                          <th className="text-right py-2 px-2 font-semibold">Пинг</th>
                          <th className="text-right py-2 px-2 font-semibold">Действие</th>
                        </tr>
                      </thead>
                      <tbody>
                        {state.servers.map((srv) => (
                          <tr key={srv.ip} className="border-b border-white/[0.05]">
                            <td className="py-2 px-2 font-mono-num">
                              {srv.ip}
                              {srv.port ? `:${srv.port}` : ''}
                            </td>
                            <td className="py-2 px-2 text-[#a1acbd]">
                              <span className="text-[#f3f6fa] font-medium">{srv.region}</span> · {srv.role}
                            </td>
                            <td className="py-2 px-2 text-right font-mono-num font-semibold">
                              {srv.blocked ? (
                                <span className="text-red-400">Заблокирован</span>
                              ) : srv.directMs > 0 && srv.tunnelMs > 0 ? (
                                <span className="text-[#22d37b]">{srv.directMs} → {srv.tunnelMs} мс</span>
                              ) : srv.tunnelMs > 0 ? (
                                <span className="text-[#22d37b]">{srv.tunnelMs} мс</span>
                              ) : srv.directMs > 0 ? (
                                <span>{srv.directMs} мс</span>
                              ) : (
                                <span className="text-[#a1acbd]">в маршруте</span>
                              )}
                            </td>
                            <td className="py-2 px-2 text-right">
                              <button
                                onClick={() => Bridge.toggleBlockServer(srv.ip).then(setState)}
                                className={`px-2.5 py-0.5 rounded-lg text-[11px] font-semibold border cursor-pointer ${
                                  srv.blocked
                                    ? 'bg-[#22d37b]/15 border-[#22d37b]/40 text-[#22d37b]'
                                    : 'bg-red-500/12 border-red-500/30 text-red-300 hover:bg-red-500/20'
                                }`}
                              >
                                {srv.blocked ? 'Разблок' : 'Блок'}
                              </button>
                            </td>
                          </tr>
                        ))}
                        {state.servers.length === 0 && (
                          <tr>
                            <td colSpan={4} className="py-8 text-center text-[#a1acbd]">
                              Загружено {state.effectiveRoutes.length} подсетей {activeGame.shortCode}. Запустите игру — серверы лобби и матчей появятся здесь в реальном времени.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-4 flex flex-col gap-2.5 min-w-0 max-h-[360px]">
                  <div className="text-sm font-bold">Журнал событий</div>
                  <div className="flex flex-col gap-1.5 overflow-y-auto flex-1 pr-1">
                    {[...state.logs].reverse().map((l, idx) => (
                      <div
                        key={idx}
                        className="px-3 py-2 rounded-xl bg-[#0d1015] border border-white/[0.06] text-[11.5px] leading-relaxed text-[#a1acbd]"
                      >
                        <span
                          className={`font-mono-num font-semibold mr-1.5 ${
                            l.level === 'ok'
                              ? 'text-[#22d37b]'
                              : l.level === 'warn'
                              ? 'text-amber-400'
                              : l.level === 'err'
                              ? 'text-red-400'
                              : 'text-[#f3f6fa]'
                          }`}
                        >
                          {l.time}
                        </span>
                        {l.message}
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            </>
          )}

          {/* TAB 5: SYSTEM SETTINGS, AUTO-BOOST, TRAY, HOTKEY & UPDATER */}
          {tab === 'settings' && (
            <section className="grid grid-cols-1 min-[900px]:grid-cols-2 gap-4 min-w-0">
              <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-5 flex flex-col gap-3">
                <div>
                  <h2 className="text-base font-bold">Автоматизация и фоновый режим</h2>
                  <p className="text-xs text-[#a1acbd]">Настройте поведение ABI Route во время запуска Windows и игр</p>
                </div>

                {[
                  {
                    key: 'autoBoost' as const,
                    title: 'Авто-ускорение при запуске игры',
                    sub: 'Включать туннель автоматически, как только радар видит старт выбранной игры',
                  },
                  {
                    key: 'autoStopOnExit' as const,
                    title: 'Выключать туннель после закрытия игры',
                    sub: 'Автоматически освобождать адаптер Wintun при выходе из игры',
                  },
                  {
                    key: 'closeToTray' as const,
                    title: 'Сворачивать в системный трей при закрытии окна (✕)',
                    sub: 'Иконка остаётся у часов Windows с быстрым меню по правому клику',
                  },
                  {
                    key: 'startWithWindows' as const,
                    title: 'Запускать вместе с Windows (свёрнуто в трей)',
                    sub: 'В паре с «Авто-ускорением» позволяет вообще не открывать программу вручную',
                  },
                  {
                    key: 'globalHotkey' as const,
                    title: 'Глобальная клавиша Alt + F9 в игре',
                    sub: 'Включение и выключение ускорения прямо из полноэкранной игры со звуковым сигналом',
                  },
                ].map((item) => {
                  const val = state.settings[item.key]
                  return (
                    <div
                      key={item.key}
                      className="p-3.5 rounded-xl bg-[#0d1015] border border-white/[0.07] flex items-center justify-between gap-3"
                    >
                      <div className="min-w-0">
                        <div className="text-[13px] font-semibold">{item.title}</div>
                        <div className="text-[11.5px] text-[#a1acbd] mt-0.5">{item.sub}</div>
                      </div>
                      <button
                        onClick={() => saveSysPref({ [item.key]: !val })}
                        className={`px-3.5 py-1.5 rounded-xl text-xs font-bold shrink-0 cursor-pointer ${
                          val
                            ? 'bg-[#22d37b] text-[#061b10]'
                            : 'bg-[#19202b] border border-white/[0.12] text-[#a1acbd]'
                        }`}
                      >
                        {val ? 'ВКЛ' : 'ВЫКЛ'}
                      </button>
                    </div>
                  )
                })}
              </div>

              <div className="flex flex-col gap-4">
                <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-5 flex flex-col gap-3">
                  <div>
                    <h2 className="text-base font-bold">Тонкая настройка MTU (защита от микрофризов)</h2>
                    <p className="text-xs text-[#a1acbd]">
                      Оптимальный размер пакета предотвращает фрагментацию на оборудовании провайдера
                    </p>
                  </div>

                  <div className="flex items-center justify-between gap-3 p-3.5 rounded-xl bg-[#0d1015] border border-white/[0.07]">
                    <div>
                      <div className="text-sm font-bold font-mono-num">Текущий MTU: {state.settings.mtu} байт</div>
                      <div className="text-[11.5px] text-[#a1acbd]">Проверка флагом DF (Don&apos;t Fragment)</div>
                    </div>
                    <button
                      onClick={handleAutoMTU}
                      disabled={mtuTesting}
                      className="px-4 py-2 rounded-xl text-xs font-bold bg-[#22d37b] hover:bg-[#3ae08e] text-[#061b10] cursor-pointer"
                    >
                      {mtuTesting ? 'Измеряю…' : 'Подобрать автоматически'}
                    </button>
                  </div>
                </div>

                <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-5 flex flex-col gap-3">
                  <div>
                    <h2 className="text-base font-bold">Обновления и управление процессом</h2>
                    <p className="text-xs text-[#a1acbd]">Текущая версия: ABI Route v{state.version}</p>
                  </div>

                  <div className="flex items-center justify-between gap-3 p-3.5 rounded-xl bg-[#0d1015] border border-white/[0.07]">
                    <div>
                      <div className="text-xs font-semibold">
                        {state.updateInfo.available
                          ? `Доступна новая версия v${state.updateInfo.latestVer}!`
                          : 'Установлена актуальная версия'}
                      </div>
                      <div className="text-[11px] text-[#a1acbd]">Репозиторий Kirillka645/ABIROUTE</div>
                    </div>
                    {state.updateInfo.available ? (
                      <button
                        onClick={() => Bridge.installUpdateNow()}
                        className="px-4 py-2 rounded-xl text-xs font-bold bg-[#22d37b] text-[#061b10] cursor-pointer"
                      >
                        Обновить в 1 клик
                      </button>
                    ) : (
                      <button
                        onClick={() =>
                          Bridge.checkUpdatesNow().then((u) =>
                            flashMsg(u.available ? `Найдена версия v${u.latestVer}` : 'У вас последняя версия')
                          )
                        }
                        className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] cursor-pointer"
                      >
                        Проверить обновления
                      </button>
                    )}
                  </div>

                  <button
                    onClick={() => Bridge.quit()}
                    className="w-full py-2.5 rounded-xl text-xs font-semibold bg-red-500/12 hover:bg-red-500/22 border border-red-500/30 text-red-300 cursor-pointer"
                  >
                    Выключить туннель и полностью закрыть ABI Route
                  </button>
                </div>
              </div>
            </section>
          )}
        </div>
      </main>

      <AddGameModal open={addModal} onClose={() => setAddModal(false)} onAdded={setState} />
      <ImportModal open={importModal} onClose={() => setImportModal(false)} onUpdated={setState} />
      <RouteEditorModal
        open={routeModal}
        gameName={activeGame.name}
        initialManual={state.settings.manualRanges[activeGame.id] || []}
        initialExcluded={state.settings.excludedRanges[activeGame.id] || []}
        onClose={() => setRouteModal(false)}
        onSaved={setState}
      />
    </div>
  )
}
