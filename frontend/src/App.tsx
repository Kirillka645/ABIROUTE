import React, { useEffect, useMemo, useState } from 'react'
import { Bridge, formatBytes, formatDuration } from './lib/bridge'
import type { DashboardState, DiagReport } from './types'
import { ActivityIcon, BoltIcon, GlobeIcon, GridIcon, RefreshIcon, SearchIcon, ShieldIcon } from './components/Icons'
import { RouteMap } from './components/RouteMap'
import { PingChart } from './components/PingChart'
import { AddGameModal, CloseModal, ImportModal } from './components/Modals'

type TabKey = 'library' | 'boost' | 'nodes' | 'diag'

const PROTOCOLS = [
  {
    id: 'auto',
    title: 'Автоподбор (Рекомендуется)',
    badge: 'Умный режим',
    desc: 'Проверяет AmneziaWG 2.0 QUIC → DNS → SIP и автоматически переключается на MASQUE HTTP/3 (:443), если провайдер режет UDP.',
  },
  {
    id: 'awg_quic',
    title: 'AmneziaWG 2.0 · Маскировка QUIC',
    badge: 'Мин. пинг',
    desc: 'Отправляет настоящий TLS 1.3 ClientHello (HTTP/3 >=1200 байт) + серию шумовых пакетов перед открытием игрового туннеля.',
  },
  {
    id: 'masque_h3',
    title: 'WARP MASQUE · HTTP/3 (:443)',
    badge: 'Анти-ТСПУ',
    desc: 'Официальный протокол Cloudflare Connect-IP поверх QUIC на порт 443. Работает там, где WireGuard заблокирован полностью.',
  },
  {
    id: 'masque_h2',
    title: 'WARP MASQUE · HTTP/2 TCP (:443)',
    badge: 'Резерв TCP',
    desc: 'Туннель поверх обычного HTTPS/2 соединения TCP :443 для сетей с жёсткой фильтрацией любого UDP-трафика.',
  },
  {
    id: 'awg_dns',
    title: 'AmneziaWG 2.0 · Маскировка DNS / SIP',
    badge: 'Альтернатива',
    desc: 'Имитация стандартного DNS-запроса EDNS0 с обфускацией заголовков пакетов.',
  },
]

export const App: React.FC = () => {
  const [state, setState] = useState<DashboardState | null>(null)
  const [tab, setTab] = useState<TabKey>('library')
  const [search, setSearch] = useState('')
  const [scanProg, setScanProg] = useState<{ done: number; total: number } | null>(null)
  const [diag, setDiag] = useState<DiagReport | null>(null)
  const [diagRunning, setDiagRunning] = useState(false)
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000))

  const [addModal, setAddModal] = useState(false)
  const [importModal, setImportModal] = useState(false)
  const [closeModal, setCloseModal] = useState(false)

  useEffect(() => {
    Bridge.getState().then(setState)
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
        Загрузка ядра ABI Route 4.0…
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

  const handleCloseClick = () => {
    if (isBoosted || state.busy) {
      setCloseModal(true)
    } else {
      Bridge.quit()
    }
  }

  return (
    <div className="grid grid-cols-[236px_1fr] w-full h-full bg-[#0d1015] text-[#f3f6fa] border border-white/[0.08]">
      {/* Left Sidebar */}
      <aside className="flex flex-col justify-between p-4 bg-[#0a0d11] border-r border-white/[0.07]">
        <div>
          <div className="flex items-center gap-3 px-2 pt-1 pb-5 wails-drag">
            <div className="w-9 h-9 rounded-xl bg-[#22d37b]/12 border border-[#22d37b]/35 flex items-center justify-center text-[#22d37b] shrink-0">
              <BoltIcon className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[17px] font-bold tracking-tight leading-none">ABI Route</div>
              <div className="text-[11px] text-[#a1acbd] mt-1">Smart Game Booster · {state.version}</div>
            </div>
          </div>

          <nav className="flex flex-col gap-1">
            {(
              [
                ['library', 'Мои игры', GridIcon],
                ['boost', 'Ускорение', ActivityIcon],
                ['nodes', 'Узлы и обход DPI', GlobeIcon],
                ['diag', 'Диагностика и радар', ShieldIcon],
              ] as const
            ).map(([key, label, Icon]) => {
              const active = tab === key
              return (
                <button
                  key={key}
                  onClick={() => setTab(key)}
                  className={`flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-sm transition cursor-pointer text-left ${
                    active
                      ? 'bg-[#22d37b]/12 text-[#22d37b] font-semibold shadow-[inset_0_0_0_1px_rgba(34,211,123,0.35)]'
                      : 'text-[#a1acbd] hover:bg-[#131820] hover:text-[#f3f6fa] font-medium'
                  }`}
                >
                  <Icon className="w-4.5 h-4.5 shrink-0" />
                  <span>{label}</span>
                  {key === 'boost' && isBoosted && (
                    <span className="ml-auto w-2 h-2 rounded-full bg-[#22d37b] animate-pulse" />
                  )}
                </button>
              )
            })}
          </nav>
        </div>

        {/* Bottom Kernel Card */}
        <div className="p-3 rounded-xl bg-[#131820] border border-white/[0.07] flex flex-col gap-2 text-xs">
          <div className="flex items-center gap-2 font-semibold">
            <span
              className={`w-2 h-2 rounded-full shrink-0 ${
                isBoosted ? 'bg-[#22d37b]' : state.busy ? 'bg-amber-400 animate-pulse' : 'bg-[#7b8798]'
              }`}
            />
            <span className="truncate">
              {isBoosted ? 'Ускорение активно' : state.busy ? 'Настройка маршрута…' : 'Ядро Wintun готово'}
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-[#a1acbd]">
            <span>{activeGame.shortCode} процесс</span>
            <span className={state.radar.gameRunning ? 'text-[#22d37b] font-semibold' : 'text-[#7b8798]'}>
              {state.radar.gameRunning ? 'В сети' : 'Ожидание'}
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-[#a1acbd]">
            <span>Трафик игры</span>
            <span className="font-mono-num">
              ↓ {formatBytes(state.tunnelStats.rxBytes)} · ↑ {formatBytes(state.tunnelStats.txBytes)}
            </span>
          </div>
        </div>
      </aside>

      {/* Main Workspace */}
      <main className="flex flex-col min-w-0 h-full">
        {/* Custom Frameless Titlebar */}
        <header className="h-[56px] px-6 border-b border-white/[0.07] flex items-center justify-between gap-4 shrink-0 wails-drag">
          <div className="flex items-center gap-3 wails-no-drag">
            {tab === 'library' ? (
              <label className="flex items-center gap-2 bg-[#131820] border border-white/[0.08] rounded-xl px-3 py-1.5 w-[290px] text-[#a1acbd] focus-within:border-[#22d37b]/50">
                <SearchIcon className="w-4 h-4 shrink-0" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Поиск игры или процесса (.exe)…"
                  className="bg-transparent border-none outline-none text-xs text-[#f3f6fa] placeholder-[#7b8798] w-full"
                />
              </label>
            ) : (
              <div className="flex items-center gap-2.5">
                <button
                  onClick={() => setTab('library')}
                  className="px-2.5 py-1 rounded-lg bg-[#131820] hover:bg-[#19202b] border border-white/[0.08] text-xs text-[#a1acbd] hover:text-[#f3f6fa] cursor-pointer"
                >
                  ← Игры
                </button>
                <span className="text-sm font-bold">{activeGame.name}</span>
                <span className="px-2 py-0.5 rounded-md bg-[#131820] border border-white/[0.07] text-[11px] font-mono-num text-[#a1acbd]">
                  {state.appliedRouteCount || activeGame.presetRanges.length} подсетей
                </span>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2.5 wails-no-drag">
            {!state.isAdmin && (
              <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-amber-500/15 border border-amber-500/35 text-amber-300">
                Запустите от имени администратора для Wintun
              </span>
            )}
            {isBoosted && (
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-[#22d37b]/12 border border-[#22d37b]/35 text-[#22d37b] font-mono-num">
                В работе · {formatDuration(state.startedAt, nowSec)}
              </span>
            )}
            <div className="flex items-center gap-1 ml-1">
              <button
                onClick={() => Bridge.minimize()}
                className="w-7 h-7 rounded-lg hover:bg-[#19202b] text-[#a1acbd] hover:text-[#f3f6fa] flex items-center justify-center text-xs cursor-pointer"
                aria-label="Свернуть"
              >
                —
              </button>
              <button
                onClick={() => Bridge.toggleMax()}
                className="w-7 h-7 rounded-lg hover:bg-[#19202b] text-[#a1acbd] hover:text-[#f3f6fa] flex items-center justify-center text-xs cursor-pointer"
                aria-label="Развернуть"
              >
                □
              </button>
              <button
                onClick={handleCloseClick}
                className="w-7 h-7 rounded-lg hover:bg-red-500/20 text-[#a1acbd] hover:text-red-300 flex items-center justify-center text-xs cursor-pointer"
                aria-label="Закрыть"
              >
                ✕
              </button>
            </div>
          </div>
        </header>

        {/* Progress Bar during active scan/connect */}
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

        {/* Content Body */}
        <div className="p-6 flex-1 overflow-y-auto flex flex-col gap-4">
          {/* TAB 1: GAME LIBRARY (GearUP Home) */}
          {tab === 'library' && (
            <>
              {/* Hero Active Game Card */}
              <section
                className="grid grid-cols-[1.35fr_1fr] gap-5 p-5 rounded-2xl border border-[#22d37b]/35 items-center"
                style={{
                  background:
                    'radial-gradient(120% 140% at 0% 0%, rgba(34,211,123,0.14) 0%, rgba(19,24,32,0.97) 58%), #131820',
                }}
              >
                <div className="flex flex-col gap-2.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#22d37b]/14 border border-[#22d37b]/35 text-[#22d37b]">
                      Выбранная игра · Авто-радар ETW
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono-num bg-[#0d1015]/80 border border-white/[0.08] text-[#a1acbd]">
                      {activeGame.processes[0]}
                    </span>
                  </div>
                  <h1 className="text-[26px] font-bold tracking-tight leading-tight">{activeGame.name}</h1>
                  <p className="text-[13px] text-[#a1acbd] leading-relaxed max-w-[470px]">{activeGame.description}</p>
                  <div className="flex items-center gap-2.5 pt-1">
                    {isBoosted ? (
                      <button
                        onClick={() => setTab('boost')}
                        className="px-6 py-3 rounded-xl text-sm font-bold bg-[#22d37b] hover:bg-[#3ae08e] text-[#061b10] flex items-center gap-2 cursor-pointer active:scale-[0.98]"
                      >
                        <ActivityIcon className="w-4.5 h-4.5" />
                        Открыть телеметрию ({state.routeMetrics.boostedPingMs || '…'} мс)
                      </button>
                    ) : (
                      <button
                        onClick={() => handleBoostGame(activeGame.id)}
                        disabled={state.busy}
                        className="px-6 py-3 rounded-xl text-sm font-bold bg-[#22d37b] hover:bg-[#3ae08e] disabled:opacity-50 text-[#061b10] flex items-center gap-2 cursor-pointer active:scale-[0.98]"
                      >
                        <BoltIcon className="w-4.5 h-4.5" />
                        {state.busy ? 'Подключение…' : 'Ускорить в 1 клик'}
                      </button>
                    )}
                    <button
                      onClick={() => setTab('nodes')}
                      className="px-4 py-3 rounded-xl text-sm font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] cursor-pointer"
                    >
                      Сменить узел
                    </button>
                  </div>
                </div>

                <div className="bg-[#0a0d11]/75 border border-white/[0.08] rounded-xl p-3.5 flex flex-col gap-2">
                  <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#131820] border border-white/[0.06] text-xs">
                    <span className="text-[#a1acbd]">Узел маршрута</span>
                    <button onClick={() => setTab('nodes')} className="font-semibold flex items-center gap-1.5 cursor-pointer">
                      <span>{state.activeNode.city || 'Автовыбор (Лучший)'}</span>
                      {state.activeNode.tunnelPingMs > 0 && (
                        <span className="text-[#22d37b] font-mono-num">{state.activeNode.tunnelPingMs} мс</span>
                      )}
                    </button>
                  </div>
                  <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#131820] border border-white/[0.06] text-xs">
                    <span className="text-[#a1acbd]">Протокол обхода</span>
                    <button onClick={() => setTab('nodes')} className="font-semibold cursor-pointer">
                      {state.activeProtocolTitle}
                    </button>
                  </div>
                  <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#131820] border border-white/[0.06] text-xs">
                    <span className="text-[#a1acbd]">Резерв при блокировке</span>
                    <span className="text-[#a1acbd] font-medium">MASQUE HTTP/3 (:443)</span>
                  </div>
                  <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#131820] border border-white/[0.06] text-xs">
                    <span className="text-[#a1acbd]">Защита активного рейда</span>
                    <span className={state.settings.raidProtection ? 'text-[#22d37b] font-semibold' : 'text-[#7b8798]'}>
                      {state.settings.raidProtection ? 'Включена' : 'Выключена'}
                    </span>
                  </div>
                </div>
              </section>

              {/* Other Games Grid */}
              <div className="flex items-baseline justify-between pt-1">
                <h2 className="text-base font-bold tracking-tight">Каталог игр и приложений</h2>
                <span className="text-xs text-[#a1acbd]">Встроенный Wintun — никаких сторонних установок</span>
              </div>

              <section className="grid grid-cols-4 gap-3.5">
                {otherGames.slice(0, 3).map((g) => (
                  <article
                    key={g.id}
                    className="bg-[#131820] hover:bg-[#19202b] border border-white/[0.08] hover:border-white/[0.15] rounded-2xl p-3.5 flex flex-col justify-between gap-3 transition"
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2">
                        <div className="w-10 h-10 rounded-xl bg-[#19202b] border border-white/[0.12] flex items-center justify-center text-xs font-bold tracking-tight">
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

                {/* Add Custom App Card */}
                <article
                  onClick={() => setAddModal(true)}
                  className="bg-[#131820]/70 hover:bg-[#19202b] border border-dashed border-white/[0.16] hover:border-[#22d37b]/50 rounded-2xl p-3.5 flex flex-col justify-between gap-3 transition cursor-pointer"
                >
                  <div>
                    <div className="flex items-start justify-between">
                      <div className="w-10 h-10 rounded-xl bg-[#22d37b]/12 border border-[#22d37b]/35 text-[#22d37b] flex items-center justify-center text-lg font-bold">
                        +
                      </div>
                      <span className="px-2 py-0.5 rounded-full text-[10.5px] bg-[#0d1015] border border-white/[0.07] text-[#a1acbd]">
                        Любой .exe
                      </span>
                    </div>
                    <div className="font-bold text-sm mt-2.5">Добавить свою игру</div>
                    <div className="text-[11.5px] text-[#a1acbd] mt-0.5">Игра, лаунчер или голосовой чат</div>
                  </div>
                  <div className="flex items-center justify-between pt-2.5 border-t border-white/[0.07]">
                    <span className="text-[11.5px] text-[#22d37b] font-semibold">ETW-автопоиск</span>
                    <span className="text-xs font-semibold">Настроить →</span>
                  </div>
                </article>
              </section>

              {/* Bottom Utility Bar */}
              <section className="grid grid-cols-2 gap-3.5 mt-auto">
                <div className="flex items-center justify-between gap-3 p-3.5 rounded-xl bg-[#131820] border border-white/[0.07]">
                  <div>
                    <div className="text-[13px] font-semibold">Свой сервер AmneziaWG или ключ vpn://</div>
                    <div className="text-[11.5px] text-[#a1acbd]">Импорт собственного VPS с сохранением split-tunnel</div>
                  </div>
                  <button
                    onClick={() => setImportModal(true)}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] shrink-0 cursor-pointer"
                  >
                    Импорт
                  </button>
                </div>

                <div className="flex items-center justify-between gap-3 p-3.5 rounded-xl bg-[#131820] border border-white/[0.07]">
                  <div>
                    <div className="text-[13px] font-semibold">Не стартует матч или высокий пинг?</div>
                    <div className="text-[11.5px] text-[#a1acbd]">Самодиагностика всех 5 участков сети за несколько секунд</div>
                  </div>
                  <button
                    onClick={handleRunDiag}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] shrink-0 cursor-pointer"
                  >
                    Проверить
                  </button>
                </div>
              </section>
            </>
          )}

          {/* TAB 2: BOOST COCKPIT */}
          {tab === 'boost' && (
            <>
              <div className="flex items-center justify-between gap-4 bg-[#131820] border border-white/[0.08] rounded-2xl px-5 py-3.5">
                <div>
                  <div className="text-sm font-bold text-[#f3f6fa]">{state.statusText}</div>
                  <div className="text-xs text-[#a1acbd] mt-0.5">
                    Профиль: {activeGame.name} · Процессы: {activeGame.processes.join(', ')}
                  </div>
                </div>
                <div className="flex items-center gap-2.5 shrink-0">
                  {state.busy && (
                    <button
                      onClick={() => Bridge.cancelOperation()}
                      className="px-4 py-2 rounded-xl text-xs font-semibold bg-amber-500/15 border border-amber-500/35 text-amber-300 cursor-pointer"
                    >
                      Прервать
                    </button>
                  )}
                  {isBoosted ? (
                    <button
                      onClick={() => Bridge.stopBoost().then(setState)}
                      className="px-5 py-2.5 rounded-xl text-sm font-semibold bg-red-500/14 hover:bg-red-500/24 border border-red-500/35 text-red-300 cursor-pointer"
                    >
                      Остановить
                    </button>
                  ) : (
                    <button
                      onClick={() => Bridge.boostOneClick(activeGame.id)}
                      disabled={state.busy}
                      className="px-6 py-2.5 rounded-xl text-sm font-bold bg-[#22d37b] hover:bg-[#3ae08e] disabled:opacity-50 text-[#061b10] flex items-center gap-2 cursor-pointer"
                    >
                      <BoltIcon className="w-4 h-4" />
                      Ускорить сейчас
                    </button>
                  )}
                </div>
              </div>

              <section className="grid grid-cols-[264px_1fr] gap-4">
                {/* Honest Ping Gauge */}
                <div
                  className="rounded-2xl p-5 border border-[#22d37b]/35 flex flex-col justify-between"
                  style={{
                    background:
                      'radial-gradient(110% 110% at 50% 0%, rgba(34,211,123,0.14) 0%, rgba(19,24,32,0.98) 68%), #131820',
                  }}
                >
                  <div>
                    <div className="text-xs font-semibold text-[#a1acbd]">Честный пинг до сервера игры</div>
                    <div className="mt-2 flex items-baseline gap-1.5">
                      <span className="text-[52px] font-bold leading-none tracking-tight text-[#22d37b] font-mono-num">
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

                {/* Live 3-Hop Route Map */}
                <RouteMap
                  boosted={isBoosted}
                  node={state.activeNode}
                  metrics={state.routeMetrics}
                  gameShort={activeGame.shortCode}
                  onChangeNode={() => setTab('nodes')}
                />
              </section>

              <section className="grid grid-cols-[1.35fr_1fr] gap-4 flex-1 min-h-0">
                {/* Stability Graph */}
                <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-5 flex flex-col justify-between">
                  <div className="flex items-center justify-between gap-2">
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

                {/* Quick Controls Stack */}
                <div className="flex flex-col justify-between gap-2.5">
                  <div className="p-3.5 rounded-xl bg-[#131820] border border-white/[0.08] flex items-center justify-between gap-3">
                    <div>
                      <div className="text-[13px] font-semibold">Протокол обхода DPI</div>
                      <div className="text-[11.5px] text-[#a1acbd]">{state.activeProtocolTitle}</div>
                    </div>
                    <button
                      onClick={() => setTab('nodes')}
                      className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-[#22d37b]/12 border border-[#22d37b]/35 text-[#22d37b] cursor-pointer"
                    >
                      Изменить
                    </button>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#131820] border border-white/[0.08] flex items-center justify-between gap-3">
                    <div>
                      <div className="text-[13px] font-semibold">Защита активного рейда</div>
                      <div className="text-[11.5px] text-[#a1acbd]">Не переключать маршрут во время боя</div>
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
                      className={`px-3 py-1 rounded-lg text-xs font-semibold border cursor-pointer ${
                        state.settings.raidProtection
                          ? 'bg-[#22d37b]/14 border-[#22d37b]/35 text-[#22d37b]'
                          : 'bg-[#19202b] border-white/[0.1] text-[#a1acbd]'
                      }`}
                    >
                      {state.settings.raidProtection ? 'Активна' : 'Выкл'}
                    </button>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#131820] border border-white/[0.08] flex items-center justify-between gap-3">
                    <div>
                      <div className="text-[13px] font-semibold">Автосмена при сбое узла</div>
                      <div className="text-[11.5px] text-[#a1acbd]">
                        В запасе {state.settings.nodes.length || 'авто'} узлов + MASQUE :443
                      </div>
                    </div>
                    <button
                      onClick={() =>
                        Bridge.updateOptions(
                          state.settings.protocol,
                          state.settings.selectedEndpoint,
                          state.settings.raidProtection,
                          !state.settings.autoFailover,
                          state.settings.autoLearn,
                          state.settings.subnetPrefix
                        ).then(setState)
                      }
                      className={`px-3 py-1 rounded-lg text-xs font-semibold border cursor-pointer ${
                        state.settings.autoFailover
                          ? 'bg-[#22d37b]/14 border-[#22d37b]/35 text-[#22d37b]'
                          : 'bg-[#19202b] border-white/[0.1] text-[#a1acbd]'
                      }`}
                    >
                      {state.settings.autoFailover ? 'Вкл' : 'Выкл'}
                    </button>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#131820] border border-white/[0.08] flex items-center justify-between gap-3">
                    <div>
                      <div className="text-[13px] font-semibold">Самодиагностика сети</div>
                      <div className="text-[11.5px] text-[#a1acbd]">Проверить роутер, DPI и серверы игры</div>
                    </div>
                    <button
                      onClick={handleRunDiag}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] cursor-pointer"
                    >
                      Открыть
                    </button>
                  </div>
                </div>
              </section>
            </>
          )}

          {/* TAB 3: NODES & ANTI-DPI */}
          {tab === 'nodes' && (
            <section className="grid grid-cols-[1.25fr_1fr] gap-4 flex-1 min-h-0">
              {/* Left: Cloudflare City Nodes */}
              <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-5 flex flex-col gap-3 min-h-0">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <h2 className="text-base font-bold">Узлы маршрутизации</h2>
                    <p className="text-xs text-[#a1acbd]">Город определяется по DNS id.server внутри туннеля</p>
                  </div>
                  <button
                    onClick={() => Bridge.scanEndpoints()}
                    disabled={state.busy}
                    className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] disabled:opacity-50 border border-white/[0.12] flex items-center gap-1.5 cursor-pointer"
                  >
                    <RefreshIcon className={`w-3.5 h-3.5 ${state.busy ? 'animate-spin' : ''}`} />
                    {scanProg ? `${scanProg.done}/${scanProg.total}` : 'Сканировать (420)'}
                  </button>
                </div>

                <div className="flex flex-col gap-2 overflow-y-auto pr-1 flex-1">
                  {/* Auto option */}
                  <div
                    onClick={() =>
                      Bridge.updateOptions(
                        state.settings.protocol,
                        'auto',
                        state.settings.raidProtection,
                        state.settings.autoFailover,
                        state.settings.autoLearn,
                        state.settings.subnetPrefix
                      ).then(setState)
                    }
                    className={`grid grid-cols-[1fr_76px_100px] items-center px-3.5 py-2.5 rounded-xl border cursor-pointer transition ${
                      state.settings.selectedEndpoint === 'auto'
                        ? 'bg-[#22d37b]/12 border-[#22d37b]/40'
                        : 'bg-[#0d1015] border-white/[0.07] hover:border-white/[0.16]'
                    }`}
                  >
                    <div>
                      <div className="text-sm font-semibold">Автоматический выбор (Лучший)</div>
                      <div className="text-[11.5px] text-[#a1acbd]">
                        Самый быстрый рабочий узел по пингу, джиттеру и потерям
                      </div>
                    </div>
                    <div className="text-xs font-bold text-[#22d37b] font-mono-num">
                      {state.settings.nodes[0] ? `${state.settings.nodes[0].tunnelPingMs} мс` : 'Авто'}
                    </div>
                    <div className="text-right">
                      <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#22d37b]/15 text-[#22d37b]">
                        Рекомендуется
                      </span>
                    </div>
                  </div>

                  {state.settings.nodes.map((n, idx) => {
                    const sel = state.settings.selectedEndpoint === n.endpoint
                    return (
                      <div
                        key={n.endpoint}
                        onClick={() =>
                          Bridge.updateOptions(
                            state.settings.protocol,
                            n.endpoint,
                            state.settings.raidProtection,
                            state.settings.autoFailover,
                            state.settings.autoLearn,
                            state.settings.subnetPrefix
                          ).then(setState)
                        }
                        className={`grid grid-cols-[1fr_76px_100px] items-center px-3.5 py-2.5 rounded-xl border cursor-pointer transition ${
                          sel
                            ? 'bg-[#22d37b]/12 border-[#22d37b]/40'
                            : 'bg-[#0d1015] border-white/[0.07] hover:border-white/[0.16]'
                        }`}
                      >
                        <div>
                          <div className="text-sm font-semibold">
                            {n.city} · {n.country} ({n.coloCode})
                          </div>
                          <div className="text-[11.5px] text-[#a1acbd] font-mono-num">
                            {n.endpoint} · ±{n.jitterMs} мс · потери {n.lossPct}%
                          </div>
                        </div>
                        <div className="text-xs font-bold text-[#22d37b] font-mono-num">{n.tunnelPingMs} мс</div>
                        <div className="text-right">
                          <span className="px-2 py-0.5 rounded-full text-[11px] bg-[#19202b] border border-white/[0.08] text-[#a1acbd]">
                            {sel ? 'Выбран' : `Резерв #${idx + 1}`}
                          </span>
                        </div>
                      </div>
                    )
                  })}

                  {state.settings.nodes.length === 0 && (
                    <div className="p-5 rounded-xl bg-[#0d1015]/60 border border-white/[0.06] text-center text-xs text-[#a1acbd]">
                      Нажмите «Сканировать (420)» или сразу «Ускорить в 1 клик» — программа сама проверит узлы и определит их города.
                    </div>
                  )}
                </div>

                {/* Profile Actions Footer */}
                <div className="flex items-center justify-between gap-2 pt-2 border-t border-white/[0.07]">
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
              </div>

              {/* Right: Protocol & Anti-DPI Engine */}
              <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-5 flex flex-col justify-between gap-3 min-h-0">
                <div className="flex flex-col gap-2.5 overflow-y-auto pr-1">
                  <div>
                    <h2 className="text-base font-bold">Движок туннеля и обход DPI</h2>
                    <p className="text-xs text-[#a1acbd]">Выберите режим маскировки трафика под вашего провайдера</p>
                  </div>

                  {PROTOCOLS.map((p) => {
                    const sel = state.settings.protocol === p.id
                    return (
                      <div
                        key={p.id}
                        onClick={() =>
                          Bridge.updateOptions(
                            p.id,
                            state.settings.selectedEndpoint,
                            state.settings.raidProtection,
                            state.settings.autoFailover,
                            state.settings.autoLearn,
                            state.settings.subnetPrefix
                          ).then(setState)
                        }
                        className={`p-3.5 rounded-xl border cursor-pointer transition ${
                          sel
                            ? 'bg-[#22d37b]/12 border-[#22d37b]/40'
                            : 'bg-[#0d1015] border-white/[0.07] hover:border-white/[0.16]'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[13.5px] font-bold">{p.title}</span>
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10.5px] font-semibold ${
                              sel ? 'bg-[#22d37b] text-[#061b10]' : 'bg-[#19202b] text-[#a1acbd]'
                            }`}
                          >
                            {sel ? 'Выбран' : p.badge}
                          </span>
                        </div>
                        <p className="text-[11.5px] text-[#a1acbd] mt-1 leading-relaxed">{p.desc}</p>
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
                      className={`p-3.5 rounded-xl border cursor-pointer transition ${
                        state.settings.protocol === 'custom'
                          ? 'bg-[#22d37b]/12 border-[#22d37b]/40'
                          : 'bg-[#0d1015] border-white/[0.07]'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[13.5px] font-bold">{state.settings.customTunnel.name}</span>
                        <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-[#22d37b]/15 text-[#22d37b]">
                          Свой сервер
                        </span>
                      </div>
                      <div className="text-[11.5px] text-[#a1acbd] font-mono-num mt-1">
                        {state.settings.customTunnel.endpoint} · {state.settings.customTunnel.addressV4}
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

          {/* TAB 4: DIAGNOSTICS & ETW RADAR */}
          {tab === 'diag' && (
            <>
              {/* 5-Step Self-Diagnosis */}
              <section className="bg-[#131820] border border-white/[0.08] rounded-2xl p-4 flex flex-col gap-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-bold">Цепочка прохождения игрового трафика (5 этапов)</h2>
                    <p className="text-xs text-[#a1acbd]">
                      {diag ? diag.recommendation : 'Нажмите «Проверить всё», чтобы протестировать роутер, DPI, узел и серверы игры'}
                    </p>
                  </div>
                  <button
                    onClick={handleRunDiag}
                    disabled={diagRunning}
                    className="px-4 py-2 rounded-xl text-xs font-bold bg-[#22d37b] hover:bg-[#3ae08e] disabled:opacity-50 text-[#061b10] shrink-0 cursor-pointer"
                  >
                    {diagRunning ? 'Проверка…' : 'Проверить всё (5 шагов)'}
                  </button>
                </div>

                <div className="grid grid-cols-5 gap-2.5">
                  {(diag?.steps && diag.steps.length > 0
                    ? diag.steps
                    : [
                        { step: 1, title: 'Локальная сеть', status: 'ok', detail: 'Готово к тесту' },
                        { step: 2, title: 'Обход DPI', status: 'ok', detail: state.activeProtocolTitle },
                        { step: 3, title: 'Узел Cloudflare', status: 'ok', detail: state.activeNode.city || 'Автовыбор' },
                        { step: 4, title: 'Драйвер Wintun', status: state.isAdmin ? 'ok' : 'warn', detail: state.isAdmin ? 'Админ права ОК' : 'Нужен Админ' },
                        { step: 5, title: `Серверы ${activeGame.shortCode}`, status: 'ok', detail: `${activeGame.presetRanges.length} подсетей` },
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
                      <div key={s.step} className={`p-3 rounded-xl bg-[#0d1015] border ${borderCol} flex flex-col gap-1`}>
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

              {/* Radar Table + Live Logs */}
              <section className="grid grid-cols-[1.4fr_1fr] gap-4 flex-1 min-h-0">
                <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-4 flex flex-col gap-3 min-h-0">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <h3 className="text-sm font-bold">
                        ETW-радар подключений игры {state.radar.etwActive ? '· Активен' : '· Таблица сокетов'}
                      </h3>
                      <p className="text-[11.5px] text-[#a1acbd]">
                        Автоматически захватывает UDP-серверы матчей без блокировки со стороны Windows Firewall
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

                  <div className="overflow-y-auto flex-1">
                    <table className="w-full text-xs border-collapse">
                      <thead>
                        <tr className="text-[#a1acbd] border-b border-white/[0.08]">
                          <th className="text-left py-2 px-2 font-semibold">Адрес сервера</th>
                          <th className="text-left py-2 px-2 font-semibold">Назначение</th>
                          <th className="text-left py-2 px-2 font-semibold">Маршрут</th>
                          <th className="text-right py-2 px-2 font-semibold">Задержка</th>
                        </tr>
                      </thead>
                      <tbody>
                        {state.servers.map((srv) => (
                          <tr key={srv.ip} className="border-b border-white/[0.05]">
                            <td className="py-2 px-2 font-mono-num">
                              {srv.ip}
                              {srv.port ? `:${srv.port}` : ''}
                            </td>
                            <td className="py-2 px-2 text-[#a1acbd]">{srv.role}</td>
                            <td className="py-2 px-2">
                              <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-[#22d37b]/14 text-[#22d37b]">
                                Через туннель
                              </span>
                            </td>
                            <td className="py-2 px-2 text-right font-mono-num text-[#22d37b] font-semibold">
                              {srv.directMs > 0 && srv.tunnelMs > 0
                                ? `${srv.directMs} → ${srv.tunnelMs} мс`
                                : srv.tunnelMs > 0
                                ? `${srv.tunnelMs} мс`
                                : srv.directMs > 0
                                ? `${srv.directMs} мс`
                                : 'в маршруте'}
                            </td>
                          </tr>
                        ))}
                        {state.servers.length === 0 && (
                          <tr>
                            <td colSpan={4} className="py-8 text-center text-[#a1acbd]">
                              Предустановлено {activeGame.presetRanges.length} подсетей {activeGame.shortCode}. Запустите игру — активные серверы рейдов появятся здесь автоматически.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="bg-[#131820] border border-white/[0.08] rounded-2xl p-4 flex flex-col gap-2.5 min-h-0">
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
        </div>
      </main>

      <AddGameModal open={addModal} onClose={() => setAddModal(false)} onAdded={setState} />
      <ImportModal open={importModal} onClose={() => setImportModal(false)} />
      <CloseModal
        open={closeModal}
        onClose={() => setCloseModal(false)}
        onMinimize={() => {
          setCloseModal(false)
          Bridge.minimize()
        }}
        onStopAndQuit={() => {
          setCloseModal(false)
          Bridge.quit()
        }}
      />
    </div>
  )
}
