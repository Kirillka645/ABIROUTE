export interface GameProfile {
  id: string
  name: string
  shortCode: string
  category: string
  regionHint: string
  description: string
  featured?: boolean
  custom?: boolean
  processes: string[]
  presetRanges: string[]
  wideRanges?: string[]
  ignoreRanges: string[]
  verifyTargets?: string[]
}

export interface NodeInfo {
  endpoint: string
  coloCode: string
  city: string
  country: string
  handshakeMs: number
  tunnelPingMs: number
  jitterMs: number
  lossPct: number
  score: number
}

export interface WarpAccount {
  privateKey: string
  publicKey: string
  peerPublicKey: string
  ipv4: string
  ipv6: string
  deviceId: string
  created: string
  source: string
}

export interface CustomTunnelConfig {
  name: string
  addressV4: string
  endpoint: string
  mtu: number
  created: string
}

export interface Settings {
  activeGameId: string
  protocol: string
  selectedEndpoint: string
  mimicSni: string
  mtu: number
  subnetPrefix: number
  raidProtection: boolean
  autoFailover: boolean
  autoLearn: boolean
  closeToTray: boolean
  warp?: WarpAccount
  customTunnel?: CustomTunnelConfig
  nodes: NodeInfo[]
}

export interface RouteMetrics {
  routerPingMs: number
  hop1NodeMs: number
  hop2GameMs: number
  boostedPingMs: number
  directPingMs: number
  jitterMs: number
  lossPct: number
  targetServerIp: string
}

export interface TunnelStats {
  rxBytes: number
  txBytes: number
  lastHandshakeSec: number
  connected: boolean
}

export interface PingSample {
  ts: number
  boostedMs: number
  directMs: number
}

export interface EndpointHit {
  ip: string
  port: number
  proto: string
  role: string
  packets: number
  lastSeen: number
}

export interface RadarSnapshot {
  gameRunning: boolean
  activePids: number[]
  etwActive: boolean
  hits: EndpointHit[]
}

export interface SeenServer {
  ip: string
  port: number
  proto: string
  role: string
  directMs: number
  tunnelMs: number
  routed: boolean
  lastSeen: number
}

export interface LogEntry {
  time: string
  level: 'info' | 'ok' | 'warn' | 'err' | string
  message: string
}

export interface DashboardState {
  version: string
  isAdmin: boolean
  status: 'idle' | 'connecting' | 'boosted' | 'scanning' | string
  statusText: string
  busy: boolean
  startedAt: number
  activeGame: GameProfile
  catalog: GameProfile[]
  settings: Settings
  activeProtocol: string
  activeProtocolTitle: string
  activeNode: NodeInfo
  routeMetrics: RouteMetrics
  tunnelStats: TunnelStats
  appliedRouteCount: number
  deferredRouteCount: number
  history: PingSample[]
  radar: RadarSnapshot
  servers: SeenServer[]
  logs: LogEntry[]
}

export interface DiagStep {
  step: number
  title: string
  status: 'ok' | 'warn' | 'fail' | string
  detail: string
}

export interface DiagReport {
  overallOk: boolean
  summary: string
  recommendation: string
  steps: DiagStep[]
}
