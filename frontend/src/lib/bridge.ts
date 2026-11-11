import type { DashboardState, DiagReport } from '../types'

declare global {
  interface Window {
    go?: {
      main?: {
        App?: Record<string, (...args: any[]) => Promise<any>>
      }
    }
    runtime?: {
      EventsOn: (eventName: string, callback: (...data: any[]) => void) => () => void
      EventsOff: (eventName: string) => void
    }
  }
}

const fallbackState: DashboardState = {
  version: '4.0.0',
  isAdmin: true,
  status: 'idle',
  statusText: 'Готов к ускорению в 1 клик',
  busy: false,
  startedAt: 0,
  activeGame: {
    id: 'abi',
    name: 'Arena Breakout: Infinite',
    shortCode: 'ABI',
    category: 'Тактический экстракшен-шутер',
    regionHint: 'Европа · Азия · Америка',
    description: 'Точечный split-tunnel только для серверов лобби и рейдов. Остальной трафик ПК идёт напрямую.',
    featured: true,
    processes: ['UAGame.exe', 'ArenaBreakoutInfinite.exe'],
    presetRanges: ['43.174.251.0/24'],
    ignoreRanges: ['92.122.0.0/15'],
  },
  catalog: [
    {
      id: 'abi',
      name: 'Arena Breakout: Infinite',
      shortCode: 'ABI',
      category: 'Тактический экстракшен-шутер',
      regionHint: 'Европа · Азия · Америка',
      description: 'Точечный split-tunnel только для серверов лобби и рейдов. Остальной трафик ПК идёт напрямую.',
      featured: true,
      processes: ['UAGame.exe', 'ArenaBreakoutInfinite.exe'],
      presetRanges: ['43.174.251.0/24'],
      ignoreRanges: ['92.122.0.0/15'],
    },
    {
      id: 'delta-force',
      name: 'Delta Force',
      shortCode: 'DF',
      category: 'Тактический шутер',
      regionHint: 'Европа · Франкфурт / Стокгольм',
      description: 'Оптимизация маршрута к серверам Level Infinite и захват матчей ETW-радаром.',
      processes: ['DeltaForceClient-Win64-Shipping.exe'],
      presetRanges: ['43.153.253.0/24'],
      ignoreRanges: ['92.122.0.0/15'],
    },
    {
      id: 'eft',
      name: 'Escape from Tarkov',
      shortCode: 'EFT',
      category: 'Хардкорный экстракшен',
      regionHint: 'Европа · Хельсинки / Франкфурт',
      description: 'Снижение потерь пакетов при входе в рейд.',
      processes: ['EscapeFromTarkov.exe'],
      presetRanges: ['92.223.80.0/24'],
      ignoreRanges: [],
    },
    {
      id: 'pubg',
      name: 'PUBG: Battlegrounds',
      shortCode: 'PUBG',
      category: 'Королевская битва',
      regionHint: 'Европа · AWS Франкфурт',
      description: 'Прямой маршрут до европейских серверов.',
      processes: ['TslGame.exe'],
      presetRanges: ['3.64.0.0/16'],
      ignoreRanges: [],
    },
  ],
  settings: {
    activeGameId: 'abi',
    protocol: 'auto',
    selectedEndpoint: 'auto',
    mimicSni: 'www.google.com',
    mtu: 1280,
    subnetPrefix: 24,
    raidProtection: true,
    autoFailover: true,
    autoLearn: true,
    closeToTray: true,
    nodes: [],
  },
  activeProtocol: 'auto',
  activeProtocolTitle: 'AmneziaWG 2.0 · QUIC (HTTP/3)',
  activeNode: {
    endpoint: '',
    coloCode: 'AUTO',
    city: 'Автовыбор',
    country: 'Cloudflare',
    handshakeMs: 0,
    tunnelPingMs: 0,
    jitterMs: 0,
    lossPct: 0,
    score: 0,
  },
  routeMetrics: {
    routerPingMs: 1,
    hop1NodeMs: 0,
    hop2GameMs: 0,
    boostedPingMs: 0,
    directPingMs: 0,
    jitterMs: 0,
    lossPct: 0,
    targetServerIp: '43.174.251.100',
  },
  tunnelStats: { rxBytes: 0, txBytes: 0, lastHandshakeSec: 0, connected: false },
  appliedRouteCount: 0,
  deferredRouteCount: 0,
  history: [],
  radar: { gameRunning: false, activePids: [], etwActive: true, hits: [] },
  servers: [],
  logs: [],
}

function appMethod(name: string) {
  return window.go?.main?.App?.[name]
}

export const Bridge = {
  async getState(): Promise<DashboardState> {
    const fn = appMethod('GetState')
    return fn ? await fn() : fallbackState
  },
  async selectGame(gameId: string): Promise<DashboardState> {
    const fn = appMethod('SelectGame')
    return fn ? await fn(gameId) : fallbackState
  },
  async addCustomGame(name: string, exes: string, subnets: string): Promise<DashboardState> {
    const fn = appMethod('AddCustomGame')
    if (!fn) return fallbackState
    return await fn(name, exes, subnets)
  },
  async boostOneClick(gameId: string): Promise<void> {
    const fn = appMethod('BoostOneClick')
    if (fn) await fn(gameId)
  },
  async stopBoost(): Promise<DashboardState> {
    const fn = appMethod('StopBoost')
    return fn ? await fn() : fallbackState
  },
  async scanEndpoints(): Promise<void> {
    const fn = appMethod('ScanEndpoints')
    if (fn) await fn()
  },
  async cancelOperation(): Promise<void> {
    const fn = appMethod('CancelOperation')
    if (fn) await fn()
  },
  async updateOptions(
    protocol: string,
    selectedEndpoint: string,
    raidProtection: boolean,
    autoFailover: boolean,
    autoLearn: boolean,
    subnetPrefix: number
  ): Promise<DashboardState> {
    const fn = appMethod('UpdateOptions')
    return fn
      ? await fn(protocol, selectedEndpoint, raidProtection, autoFailover, autoLearn, subnetPrefix)
      : fallbackState
  },
  async generateWarpProfile(): Promise<void> {
    const fn = appMethod('GenerateWarpProfile')
    if (fn) await fn()
  },
  async importTunnelText(input: string, name: string): Promise<void> {
    const fn = appMethod('ImportTunnelText')
    if (fn) await fn(input, name)
  },
  async importConfFile(): Promise<void> {
    const fn = appMethod('ImportConfFile')
    if (fn) await fn()
  },
  async exportConfFile(): Promise<string> {
    const fn = appMethod('ExportConfFile')
    return fn ? await fn() : ''
  },
  async runDiagnostics(): Promise<DiagReport> {
    const fn = appMethod('RunDiagnostics')
    if (fn) return await fn()
    return { overallOk: true, summary: 'Готово', recommendation: '', steps: [] }
  },
  minimize() {
    appMethod('WindowMinimize')?.()
  },
  toggleMax() {
    appMethod('WindowToggleMax')?.()
  },
  quit() {
    appMethod('QuitApp')?.()
  },
  onEvent(event: string, cb: (payload: any) => void): () => void {
    if (window.runtime?.EventsOn) {
      return window.runtime.EventsOn(event, cb)
    }
    return () => {}
  },
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 Б'
  const units = ['Б', 'КБ', 'МБ', 'ГБ']
  let val = bytes
  let idx = 0
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024
    idx++
  }
  return idx === 0 ? `${Math.round(val)} ${units[idx]}` : `${val.toFixed(1)} ${units[idx]}`
}

export function formatDuration(startedAtSec: number, nowSec: number): string {
  if (!startedAtSec || nowSec <= startedAtSec) return '00:00:00'
  const diff = Math.max(0, Math.floor(nowSec - startedAtSec))
  const h = String(Math.floor(diff / 3600)).padStart(2, '0')
  const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0')
  const s = String(diff % 60).padStart(2, '0')
  return `${h}:${m}:${s}`
}
