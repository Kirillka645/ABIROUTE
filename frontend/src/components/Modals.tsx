import React, { useState } from 'react'
import { Bridge } from '../lib/bridge'
import type { DashboardState } from '../types'

export const AddGameModal: React.FC<{
  open: boolean
  onClose: () => void
  onAdded: (st: DashboardState) => void
}> = ({ open, onClose, onAdded }) => {
  const [name, setName] = useState('')
  const [exes, setExes] = useState('')
  const [subnets, setSubnets] = useState('')
  const [err, setErr] = useState('')
  const [saving, setSaving] = useState(false)

  if (!open) return null

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    setSaving(true)
    try {
      const next = await Bridge.addCustomGame(name, exes, subnets)
      setName('')
      setExes('')
      setSubnets('')
      onAdded(next)
      onClose()
    } catch (ex: any) {
      setErr(typeof ex === 'string' ? ex : ex?.message || 'Ошибка сохранения профиля')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <form
        onSubmit={submit}
        className="w-full max-w-[460px] bg-[#131820] border border-white/[0.12] rounded-2xl p-6 flex flex-col gap-4 shadow-2xl"
      >
        <div>
          <h3 className="text-lg font-bold text-[#f3f6fa]">Добавить игру или приложение</h3>
          <p className="text-xs text-[#a1acbd] mt-1">
            ETW-радар автоматически найдёт серверы выбранного процесса и пустит через туннель только их.
          </p>
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-semibold text-[#a1acbd]">Название</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Например: Deadlock или Discord Voice"
            className="px-3.5 py-2.5 rounded-xl bg-[#0d1015] border border-white/[0.1] text-sm text-[#f3f6fa] outline-none focus:border-[#22d37b]"
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-semibold text-[#a1acbd]">Имена процессов (.exe через запятую)</label>
          <input
            value={exes}
            onChange={(e) => setExes(e.target.value)}
            placeholder="project8.exe, Discord.exe"
            className="px-3.5 py-2.5 rounded-xl bg-[#0d1015] border border-white/[0.1] text-sm text-[#f3f6fa] font-mono-num outline-none focus:border-[#22d37b]"
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-semibold text-[#a1acbd]">Известные IP-диапазоны (необязательно)</label>
          <textarea
            rows={2}
            value={subnets}
            onChange={(e) => setSubnets(e.target.value)}
            placeholder="Оставьте пустым для автоматического поиска ETW-радаром"
            className="px-3.5 py-2 rounded-xl bg-[#0d1015] border border-white/[0.1] text-xs text-[#f3f6fa] font-mono-num outline-none focus:border-[#22d37b] resize-none"
          />
        </div>

        {err && <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">{err}</div>}

        <div className="flex items-center justify-end gap-2.5 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-sm font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.1] cursor-pointer"
          >
            Отмена
          </button>
          <button
            type="submit"
            disabled={saving}
            className="px-5 py-2 rounded-xl text-sm font-bold bg-[#22d37b] hover:bg-[#3ae08e] text-[#061b10] cursor-pointer active:scale-[0.98]"
          >
            {saving ? 'Сохранение…' : 'Добавить'}
          </button>
        </div>
      </form>
    </div>
  )
}

export const ImportModal: React.FC<{
  open: boolean
  onClose: () => void
}> = ({ open, onClose }) => {
  const [text, setText] = useState('')
  const [name, setName] = useState('')
  const [err, setErr] = useState('')

  if (!open) return null

  const handlePasteImport = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    try {
      await Bridge.importTunnelText(text, name)
      setText('')
      setName('')
      onClose()
    } catch (ex: any) {
      setErr(typeof ex === 'string' ? ex : ex?.message || 'Не удалось разобрать конфиг')
    }
  }

  const handleFileImport = async () => {
    setErr('')
    try {
      await Bridge.importConfFile()
      onClose()
    } catch (ex: any) {
      if (ex) setErr(typeof ex === 'string' ? ex : ex?.message || 'Ошибка чтения файла')
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <form
        onSubmit={handlePasteImport}
        className="w-full max-w-[500px] bg-[#131820] border border-white/[0.12] rounded-2xl p-6 flex flex-col gap-4 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-bold text-[#f3f6fa]">Импорт своего сервера или ключа WARP</h3>
            <p className="text-xs text-[#a1acbd] mt-1">
              Поддерживаются файлы <span className="font-mono-num">.conf</span> (AmneziaWG / WireGuard) и ссылки <span className="font-mono-num">vpn://</span>.
            </p>
          </div>
          <button
            type="button"
            onClick={handleFileImport}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.14] whitespace-nowrap cursor-pointer"
          >
            Выбрать .conf файл
          </button>
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-semibold text-[#a1acbd]">Название сервера (необязательно)</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Например: Мой VPS Германия"
            className="px-3.5 py-2 rounded-xl bg-[#0d1015] border border-white/[0.1] text-sm text-[#f3f6fa] outline-none focus:border-[#22d37b]"
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-semibold text-[#a1acbd]">Текст конфига или ключ vpn://</label>
          <textarea
            rows={5}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Вставьте сюда vpn://... или содержимое файла [Interface] / [Peer]"
            className="px-3.5 py-2.5 rounded-xl bg-[#0d1015] border border-white/[0.1] text-xs text-[#f3f6fa] font-mono-num outline-none focus:border-[#22d37b] resize-none"
          />
        </div>

        {err && <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">{err}</div>}

        <div className="flex items-center justify-end gap-2.5 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-sm font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.1] cursor-pointer"
          >
            Закрыть
          </button>
          <button
            type="submit"
            disabled={!text.trim()}
            className="px-5 py-2 rounded-xl text-sm font-bold bg-[#22d37b] hover:bg-[#3ae08e] disabled:opacity-40 text-[#061b10] cursor-pointer"
          >
            Импортировать
          </button>
        </div>
      </form>
    </div>
  )
}

export const CloseModal: React.FC<{
  open: boolean
  onClose: () => void
  onMinimize: () => void
  onStopAndQuit: () => void
}> = ({ open, onClose, onMinimize, onStopAndQuit }) => {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="w-full max-w-[430px] bg-[#131820] border border-white/[0.12] rounded-2xl p-6 flex flex-col gap-4 shadow-2xl">
        <div>
          <h3 className="text-lg font-bold text-[#f3f6fa]">Ускорение игры сейчас активно</h3>
          <p className="text-xs text-[#a1acbd] mt-1">
            Вы можете свернуть окно, чтобы туннель, защита рейда и ETW-радар продолжали работать в фоне.
          </p>
        </div>

        <div className="flex flex-col gap-2">
          <button
            onClick={onMinimize}
            className="w-full py-2.5 rounded-xl text-sm font-bold bg-[#22d37b] hover:bg-[#3ae08e] text-[#061b10] cursor-pointer"
          >
            Свернуть окно (оставить туннель включённым)
          </button>
          <button
            onClick={onStopAndQuit}
            className="w-full py-2.5 rounded-xl text-sm font-semibold bg-red-500/15 hover:bg-red-500/25 border border-red-500/35 text-red-300 cursor-pointer"
          >
            Выключить ускорение и выйти
          </button>
          <button
            onClick={onClose}
            className="w-full py-2 rounded-xl text-xs font-semibold text-[#a1acbd] hover:text-[#f3f6fa] cursor-pointer"
          >
            Отмена
          </button>
        </div>
      </div>
    </div>
  )
}
