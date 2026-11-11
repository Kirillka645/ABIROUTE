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
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
      <form
        onSubmit={submit}
        className="w-full max-w-[460px] bg-[#131820] border border-white/[0.12] rounded-2xl p-5 flex flex-col gap-3.5 shadow-2xl"
      >
        <div>
          <h3 className="text-base font-bold text-[#f3f6fa]">Добавить игру или приложение</h3>
          <p className="text-xs text-[#a1acbd] mt-1">
            ETW-радар автоматически найдёт серверы процесса и пустит через туннель только их.
          </p>
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-xs font-semibold text-[#a1acbd]">Название</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Например: Deadlock или Discord Voice"
            className="px-3 py-2 rounded-xl bg-[#0d1015] border border-white/[0.1] text-sm text-[#f3f6fa] outline-none focus:border-[#22d37b]"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-xs font-semibold text-[#a1acbd]">Процессы (.exe или полный путь к игре)</label>
          <input
            value={exes}
            onChange={(e) => setExes(e.target.value)}
            placeholder="project8.exe, Discord.exe"
            className="px-3 py-2 rounded-xl bg-[#0d1015] border border-white/[0.1] text-sm text-[#f3f6fa] font-mono-num outline-none focus:border-[#22d37b]"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-xs font-semibold text-[#a1acbd]">Известные IP-диапазоны (необязательно)</label>
          <textarea
            rows={2}
            value={subnets}
            onChange={(e) => setSubnets(e.target.value)}
            placeholder="Оставьте пустым для автоматического поиска ETW-радаром"
            className="px-3 py-2 rounded-xl bg-[#0d1015] border border-white/[0.1] text-xs text-[#f3f6fa] font-mono-num outline-none focus:border-[#22d37b] resize-none"
          />
        </div>

        {err && <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">{err}</div>}

        <div className="flex items-center justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.1] cursor-pointer"
          >
            Отмена
          </button>
          <button
            type="submit"
            disabled={saving}
            className="px-5 py-2 rounded-xl text-xs font-bold bg-[#22d37b] hover:bg-[#3ae08e] text-[#061b10] cursor-pointer active:scale-[0.98]"
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
  onUpdated: (st: DashboardState) => void
}> = ({ open, onClose, onUpdated }) => {
  const [text, setText] = useState('')
  const [name, setName] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  if (!open) return null

  const handlePasteImport = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    setLoading(true)
    try {
      await Bridge.importTunnelText(text, name)
      const st = await Bridge.getState()
      onUpdated(st)
      setText('')
      setName('')
      onClose()
    } catch (ex: any) {
      setErr(typeof ex === 'string' ? ex : ex?.message || 'Не удалось разобрать ключ или конфиг')
    } finally {
      setLoading(false)
    }
  }

  const handleFileImport = async () => {
    setErr('')
    try {
      await Bridge.importConfFile()
      const st = await Bridge.getState()
      onUpdated(st)
      onClose()
    } catch (ex: any) {
      if (ex) setErr(typeof ex === 'string' ? ex : ex?.message || 'Ошибка чтения файла')
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
      <form
        onSubmit={handlePasteImport}
        className="w-full max-w-[520px] bg-[#131820] border border-white/[0.12] rounded-2xl p-5 flex flex-col gap-3.5 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-[#f3f6fa]">Универсальный импорт ключей и подписок</h3>
            <p className="text-xs text-[#a1acbd] mt-1">
              Поддерживаются <span className="font-mono-num text-[#22d37b]">vless://</span>,{' '}
              <span className="font-mono-num text-[#22d37b]">hy2://</span>, <span className="font-mono-num">trojan://</span>,{' '}
              <span className="font-mono-num">ss://</span>, подписки <span className="font-mono-num">https://</span>, ссылки{' '}
              <span className="font-mono-num">vpn://</span> и файлы <span className="font-mono-num">.conf</span>.
            </p>
          </div>
          <button
            type="button"
            onClick={handleFileImport}
            className="px-3 py-2 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.14] whitespace-nowrap cursor-pointer"
          >
            Файл .conf
          </button>
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-xs font-semibold text-[#a1acbd]">Название (для .conf без тега)</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Например: Мой VPS Франкфурт"
            className="px-3 py-2 rounded-xl bg-[#0d1015] border border-white/[0.1] text-sm text-[#f3f6fa] outline-none focus:border-[#22d37b]"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-xs font-semibold text-[#a1acbd]">Ключи, ссылка подписки или текст конфига</label>
          <textarea
            rows={5}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={'vless://...\nhy2://...\nhttps://sub.example.com/api/v1/client/subscribe?token=...\nили [Interface] / vpn://...'}
            className="px-3 py-2 rounded-xl bg-[#0d1015] border border-white/[0.1] text-xs text-[#f3f6fa] font-mono-num outline-none focus:border-[#22d37b] resize-none"
          />
        </div>

        {err && <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">{err}</div>}

        <div className="flex items-center justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.1] cursor-pointer"
          >
            Закрыть
          </button>
          <button
            type="submit"
            disabled={!text.trim() || loading}
            className="px-5 py-2 rounded-xl text-xs font-bold bg-[#22d37b] hover:bg-[#3ae08e] disabled:opacity-40 text-[#061b10] cursor-pointer"
          >
            {loading ? 'Проверка и загрузка…' : 'Импортировать'}
          </button>
        </div>
      </form>
    </div>
  )
}

export const RouteEditorModal: React.FC<{
  open: boolean
  gameName: string
  initialManual: string[]
  initialExcluded: string[]
  onClose: () => void
  onSaved: (st: DashboardState) => void
}> = ({ open, gameName, initialManual, initialExcluded, onClose, onSaved }) => {
  const [manual, setManual] = useState(() => (initialManual || []).join('\n'))
  const [excl, setExcl] = useState(() => (initialExcluded || []).join('\n'))

  React.useEffect(() => {
    setManual((initialManual || []).join('\n'))
    setExcl((initialExcluded || []).join('\n'))
  }, [open, initialManual, initialExcluded])

  if (!open) return null

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    const next = await Bridge.saveManualRoutes(manual, excl)
    onSaved(next)
    onClose()
  }

  const resetLearned = async () => {
    const next = await Bridge.resetLearnedRoutes()
    onSaved(next)
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
      <form
        onSubmit={save}
        className="w-full max-w-[520px] bg-[#131820] border border-white/[0.12] rounded-2xl p-5 flex flex-col gap-3.5 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-[#f3f6fa]">Редактор подсетей — {gameName}</h3>
            <p className="text-xs text-[#a1acbd] mt-1">
              Добавьте дополнительные IP/подсети в туннель или исключите адреса, которые должны идти напрямую.
            </p>
          </div>
          <button
            type="button"
            onClick={resetLearned}
            className="px-3 py-1.5 rounded-xl text-[11px] font-semibold bg-amber-500/15 border border-amber-500/35 text-amber-300 whitespace-nowrap cursor-pointer"
          >
            Сбросить радар
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="flex flex-col gap-1">
            <label className="text-xs font-semibold text-[#22d37b]">Дополнительные подсети в туннель</label>
            <textarea
              rows={5}
              value={manual}
              onChange={(e) => setManual(e.target.value)}
              placeholder={'43.174.251.0/24\n185.136.168.0/24'}
              className="px-3 py-2 rounded-xl bg-[#0d1015] border border-white/[0.1] text-xs text-[#f3f6fa] font-mono-num outline-none focus:border-[#22d37b] resize-none"
            />
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs font-semibold text-amber-300">Исключения (всегда напрямую)</label>
            <textarea
              rows={5}
              value={excl}
              onChange={(e) => setExcl(e.target.value)}
              placeholder={'92.122.0.0/15\nCDN или лаунчер'}
              className="px-3 py-2 rounded-xl bg-[#0d1015] border border-white/[0.1] text-xs text-[#f3f6fa] font-mono-num outline-none focus:border-[#22d37b] resize-none"
            />
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#19202b] hover:bg-[#202938] border border-white/[0.1] cursor-pointer"
          >
            Отмена
          </button>
          <button
            type="submit"
            className="px-5 py-2 rounded-xl text-xs font-bold bg-[#22d37b] hover:bg-[#3ae08e] text-[#061b10] cursor-pointer"
          >
            Сохранить маршруты
          </button>
        </div>
      </form>
    </div>
  )
}
