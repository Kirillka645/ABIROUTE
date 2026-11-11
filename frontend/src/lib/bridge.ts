import type { DashboardState, DiagReport, UpdateInfo } from '../types'

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
  version: '5.0.0',
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
  catalog: [],
  settings: {
    activeGameId: 'abi',
    protocol: 'auto',
    selectedEndpoint: 'auto',
    activeProxyId: '',
    subscriptionUrl: '',
    mimicSni: 'www.google.com',
    mtu: 1280,
    subnetPrefix: 24,
    raidProtection: true,
    autoFailover: true,
    autoLearn: true,
    autoBoost: false,
    autoStopOnExit: false,
    closeToTray: true,
    startWithWindows: false,
    globalHotkey: true,
    blockHighPing: false,
    maxPingThresholdMs: 120,
    blockedIps: [],
    proxies: [],
    nodes: [],
    manualRanges: {},
    excludedRanges: {},
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
  effectiveRoutes: [],
  updateInfo: { available: false, currentVer: '5.0.0', latestVer: '5.0.0', downloadUrl: '', releaseUrl: '', notes: '' },
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
  async launchActiveGame(): Promise<void> {
    const fn = appMethod('LaunchActiveGame')
    if (fn) await fn()
  },
  async addCustomGame(name: string, exes: string, subnets: string): Promise<DashboardState> {
    const fn = appMethod('AddCustomGame')
    return fn ? await fn(name, exes, subnets) : fallbackState
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
  async updateSystemPrefs(
    autoBoost: boolean,
    autoStop: boolean,
    closeToTray: boolean,
    startWithWin: boolean,
    globalHotkey: boolean,
    mtu: number
  ): Promise<DashboardState> {
    const fn = appMethod('UpdateSystemPrefs')
    return fn ? await fn(autoBoost, autoStop, closeToTray, startWithWin, globalHotkey, mtu) : fallbackState
  },
  async generateWarpProfile(): Promise<void> {
    const fn = appMethod('GenerateWarpProfile')
    if (fn) await fn()
  },
  async applyWarpPlus(licenseKey: string): Promise<DashboardState> {
    const fn = appMethod('ApplyWarpPlus')
    return fn ? await fn(licenseKey) : fallbackState
  },
  async autoOptimizeMTU(): Promise<DashboardState> {
    const fn = appMethod('AutoOptimizeMTU')
    return fn ? await fn() : fallbackState
  },
  async addProxyLinks(rawText: string): Promise<DashboardState> {
    const fn = appMethod('AddProxyLinks')
    return fn ? await fn(rawText) : fallbackState
  },
  async syncSubscription(subUrl: string): Promise<DashboardState> {
    const fn = appMethod('SyncSubscription')
    return fn ? await fn(subUrl) : fallbackState
  },
  async selectProxy(proxyId: string): Promise<DashboardState> {
    const fn = appMethod('SelectProxy')
    return fn ? await fn(proxyId) : fallbackState
  },
  async deleteProxy(proxyId: string): Promise<DashboardState> {
    const fn = appMethod('DeleteProxy')
    return fn ? await fn(proxyId) : fallbackState
  },
  async setHighPingFilter(enabled: boolean, thresholdMs: number): Promise<DashboardState> {
    const fn = appMethod('SetHighPingFilter')
    return fn ? await fn(enabled, thresholdMs) : fallbackState
  },
  async toggleBlockServer(ip: string): Promise<DashboardState> {
    const fn = appMethod('ToggleBlockServer')
    return fn ? await fn(ip) : fallbackState
  },
  async clearBlockedServers(): Promise<DashboardState> {
    const fn = appMethod('ClearBlockedServers')
    return fn ? await fn() : fallbackState
  },
  async saveManualRoutes(manualLines: string, excludedLines: string): Promise<DashboardState> {
    const fn = appMethod('SaveManualRoutes')
    return fn ? await fn(manualLines, excludedLines) : fallbackState
  },
  async resetLearnedRoutes(): Promise<DashboardState> {
    const fn = appMethod('ResetLearnedRoutes')
    return fn ? await fn() : fallbackState
  },
  async checkUpdatesNow(): Promise<UpdateInfo> {
    const fn = appMethod('CheckUpdatesNow')
    return fn
      ? await fn()
      : { available: false, currentVer: '5.0.0', latestVer: '5.0.0', downloadUrl: '', releaseUrl: '', notes: '' }
  },
  async installUpdateNow(): Promise<void> {
    const fn = appMethod('InstallUpdateNow')
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
    return fn ? await fn() : { overallOk: true, summary: 'Готово', recommendation: '', steps: [] }
  },
  hideToTray() {
    appMethod('HideToTray')?.()
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
