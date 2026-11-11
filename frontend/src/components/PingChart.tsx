import React from 'react'
import type { PingSample } from '../types'

interface Props {
  samples: PingSample[]
  boosted: boolean
}

export const PingChart: React.FC<Props> = ({ samples, boosted }) => {
  if (!samples || samples.length < 2) {
    return (
      <div className="h-[146px] flex flex-col items-center justify-center rounded-xl bg-[#0d1015]/70 border border-white/[0.05] text-center px-6">
        <div className="text-xs font-semibold text-[#a1acbd]">
          {boosted ? 'Собираем первые точки телеметрии маршрута…' : 'График стабильности активируется сразу после запуска ускорения'}
        </div>
        <div className="text-[11px] text-[#7b8798] mt-1">
          Сравнение пинга через туннель и прямого канала провайдера без разрыва соединения
        </div>
      </div>
    )
  }

  const allVals: number[] = []
  samples.forEach((s) => {
    if (s.boostedMs > 0) allVals.push(s.boostedMs)
    if (s.directMs > 0) allVals.push(s.directMs)
  })
  const minVal = Math.max(0, (allVals.length ? Math.min(...allVals) : 20) - 10)
  const maxVal = Math.max(minVal + 25, (allVals.length ? Math.max(...allVals) : 80) + 10)
  const midVal = Math.round((minVal + maxVal) / 2)

  const xStart = 44
  const xEnd = 452
  const yTop = 22
  const yBottom = 128

  const toY = (v: number) => {
    const ratio = (v - minVal) / Math.max(1, maxVal - minVal)
    return yBottom - ratio * (yBottom - yTop)
  }

  const stepX = (xEnd - xStart) / Math.max(1, samples.length - 1)

  const boostedPts: string[] = []
  const directPts: string[] = []

  samples.forEach((s, idx) => {
    const x = xStart + idx * stepX
    if (s.boostedMs > 0) boostedPts.push(`${x.toFixed(1)},${toY(s.boostedMs).toFixed(1)}`)
    if (s.directMs > 0) directPts.push(`${x.toFixed(1)},${toY(s.directMs).toFixed(1)}`)
  })

  const areaPoints =
    boostedPts.length >= 2
      ? `${boostedPts.join(' ')} ${xEnd},${yBottom + 8} ${xStart},${yBottom + 8}`
      : ''

  return (
    <svg width="100%" height="146" viewBox="0 0 460 146" fill="none">
      <line x1="0" y1={yTop} x2="460" y2={yTop} stroke="rgba(255,255,255,0.05)" />
      <line x1="0" y1={(yTop + yBottom) / 2} x2="460" y2={(yTop + yBottom) / 2} stroke="rgba(255,255,255,0.05)" />
      <line x1="0" y1={yBottom} x2="460" y2={yBottom} stroke="rgba(255,255,255,0.05)" />

      <text x="4" y={yTop - 4} fill="#7b8798" fontSize="10" className="font-mono-num">
        {maxVal} мс
      </text>
      <text x="4" y={(yTop + yBottom) / 2 - 4} fill="#7b8798" fontSize="10" className="font-mono-num">
        {midVal} мс
      </text>
      <text x="4" y={yBottom - 4} fill="#7b8798" fontSize="10" className="font-mono-num">
        {minVal} мс
      </text>

      {directPts.length >= 2 && (
        <polyline
          points={directPts.join(' ')}
          stroke="rgba(255,255,255,0.28)"
          strokeWidth="1.75"
          strokeDasharray="4 4"
          fill="none"
        />
      )}

      {areaPoints && <polygon points={areaPoints} fill="rgba(34,211,123,0.10)" />}

      {boostedPts.length >= 2 && (
        <polyline points={boostedPts.join(' ')} stroke="#22d37b" strokeWidth="2.5" fill="none" />
      )}
    </svg>
  )
}
