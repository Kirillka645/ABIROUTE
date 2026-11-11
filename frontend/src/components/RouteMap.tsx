import React from 'react'
import type { NodeInfo, RouteMetrics } from '../types'

interface Props {
  boosted: boolean
  node: NodeInfo
  metrics: RouteMetrics
  gameShort: string
  onChangeNode: () => void
}

export const RouteMap: React.FC<Props> = ({ boosted, node, metrics, gameShort, onChangeNode }) => {
  const hop1 = metrics.hop1NodeMs > 0 ? `${metrics.hop1NodeMs} мс` : node.tunnelPingMs > 0 ? `${node.tunnelPingMs} мс` : '—'
  const hop2 = metrics.hop2GameMs > 0 ? `${metrics.hop2GameMs} мс` : boosted ? '~18 мс' : '—'
  const directTxt = metrics.directPingMs > 0 ? `напрямую: ${metrics.directPingMs} мс` : 'прямой канал провайдера'
  const cityLabel = node.city && node.city !== '' ? `${node.city} (${node.coloCode || 'CF'})` : 'Автовыбор узла'
  const epLabel = node.endpoint || 'Автоматический подбор'
  const targetLabel = metrics.targetServerIp || '43.174.251.100'

  return (
    <div className="bg-[#131820] border border-white/[0.08] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] rounded-2xl p-4 sm:p-5 flex flex-col justify-between min-w-0">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="text-[15px] font-bold tracking-tight text-[#f3f6fa] truncate">Карта маршрута в реальном времени</div>
          <div className="text-xs text-[#a1acbd] truncate">Обход перегруженных стыков провайдера через защищённый узел</div>
        </div>
        <button
          onClick={onChangeNode}
          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.12] text-[#f3f6fa] transition active:scale-[0.98] shrink-0 cursor-pointer"
        >
          Сменить узел
        </button>
      </div>

      <svg
        viewBox="0 0 576 154"
        preserveAspectRatio="xMidYMid meet"
        fill="none"
        className="w-full h-auto max-h-[154px] mt-1"
      >
        <path
          d="M 68 86 Q 288 142 508 86"
          stroke={boosted ? 'rgba(255,255,255,0.16)' : 'rgba(245,158,11,0.55)'}
          strokeWidth="1.75"
          strokeDasharray="4 5"
        />
        <rect x="206" y="110" width="164" height="22" rx="6" fill="#0d1015" stroke="rgba(255,255,255,0.12)" />
        <text x="288" y="125" textAnchor="middle" fill="#a1acbd" fontSize="11.5" className="font-mono-num">
          {directTxt}
        </text>

        <path
          d="M 68 80 Q 178 32 288 46 T 508 80"
          stroke={boosted ? '#22d37b' : 'rgba(255,255,255,0.14)'}
          strokeWidth={boosted ? '2.75' : '1.75'}
        />

        {boosted && <circle r="4" fill="#22d37b" className="packet-dot" />}

        <rect
          x="138"
          y="33"
          width="66"
          height="22"
          rx="6"
          fill="#0d1015"
          stroke={boosted ? 'rgba(34,211,123,0.45)' : 'rgba(255,255,255,0.12)'}
        />
        <text
          x="171"
          y="48"
          textAnchor="middle"
          fill={boosted ? '#22d37b' : '#7b8798'}
          fontSize="11.5"
          fontWeight="600"
          className="font-mono-num"
        >
          {hop1}
        </text>

        <rect
          x="372"
          y="33"
          width="66"
          height="22"
          rx="6"
          fill="#0d1015"
          stroke={boosted ? 'rgba(34,211,123,0.45)' : 'rgba(255,255,255,0.12)'}
        />
        <text
          x="405"
          y="48"
          textAnchor="middle"
          fill={boosted ? '#22d37b' : '#7b8798'}
          fontSize="11.5"
          fontWeight="600"
          className="font-mono-num"
        >
          {hop2}
        </text>

        <circle cx="68" cy="82" r="14" fill="#131820" stroke="#f3f6fa" strokeWidth="2" />
        <circle cx="68" cy="82" r="4.5" fill="#f3f6fa" />
        <text x="68" y="114" textAnchor="middle" fill="#f3f6fa" fontSize="12.5" fontWeight="600">
          Этот ПК
        </text>
        <text x="68" y="130" textAnchor="middle" fill="#7b8798" fontSize="11" className="font-mono-num">
          Роутер: {metrics.routerPingMs || 1} мс
        </text>

        <rect
          x="272"
          y="30"
          width="32"
          height="32"
          rx="8"
          fill={boosted ? '#10291e' : '#19202b'}
          stroke={boosted ? '#22d37b' : 'rgba(255,255,255,0.28)'}
          strokeWidth="2"
        />
        <circle cx="288" cy="46" r="5" fill={boosted ? '#22d37b' : '#7b8798'} />
        <text x="288" y="18" textAnchor="middle" fill={boosted ? '#22d37b' : '#a1acbd'} fontSize="12" fontWeight="700">
          {cityLabel}
        </text>
        <text x="288" y="80" textAnchor="middle" fill="#a1acbd" fontSize="11" className="font-mono-num">
          {epLabel}
        </text>

        <rect x="492" y="66" width="32" height="32" rx="8" fill="#131820" stroke="#f3f6fa" strokeWidth="2" />
        <rect x="503" y="77" width="10" height="10" rx="2" fill={boosted ? '#22d37b' : '#f59e0b'} />
        <text x="508" y="114" textAnchor="middle" fill="#f3f6fa" fontSize="12.5" fontWeight="600">
          Сервер {gameShort}
        </text>
        <text x="508" y="130" textAnchor="middle" fill="#a1acbd" fontSize="11" className="font-mono-num">
          {targetLabel}
        </text>
      </svg>
    </div>
  )
}
