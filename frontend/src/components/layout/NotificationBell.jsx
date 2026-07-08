import React, { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Bell, Check, Trash2, ExternalLink } from 'lucide-react'
import { useNotifications } from '../../context/NotificationContext'
import useFocusTrap from '../../hooks/useFocusTrap'

const SEVERITY_DOT = {
  critical: '#ef4444',
  error: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#6b7280',
}

function relativeTime(ts, t) {
  const diff = Math.max(0, Date.now() - ts)
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return t('notifications.just_now')
  const min = Math.floor(sec / 60)
  if (min < 60) return t('notifications.minutes_ago', { count: min })
  const hr = Math.floor(min / 60)
  if (hr < 24) return t('notifications.hours_ago', { count: hr })
  const day = Math.floor(hr / 24)
  return t('notifications.days_ago', { count: day })
}

/**
 * Header notification inbox — durable, unread-tracked history of noteworthy
 * telemetry events. Complements the transient toast system.
 */
export default function NotificationBell() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { notifications, unreadCount, markRead, markAllRead, clearAll } = useNotifications()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  const panelRef = useRef(null)
  useFocusTrap(panelRef, open)

  useEffect(() => {
    if (!open) return undefined
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    const onClick = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onClick)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onClick)
    }
  }, [open])

  const badge = unreadCount > 99 ? '99+' : String(unreadCount)

  const onItemClick = (n) => {
    markRead(n.id)
    if (n.link) {
      setOpen(false)
      navigate(n.link)
    }
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="relative inline-flex items-center justify-center w-8 h-8 rounded-lg border border-white/10 bg-black/30 text-white/70 hover:border-white/30 hover:text-white transition-colors"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={
          unreadCount > 0
            ? t('notifications.aria_with_unread', { count: unreadCount })
            : t('notifications.aria_label')
        }
      >
        <Bell className="w-4 h-4" strokeWidth={1.75} aria-hidden />
        {unreadCount > 0 && (
          <span
            className="absolute -top-1 -end-1 min-w-[16px] h-[16px] px-1 rounded-full bg-rose-500 text-[9px] font-bold text-white flex items-center justify-center tabular-nums"
            aria-hidden
          >
            {badge}
          </span>
        )}
      </button>

      {open && (
        <div
          ref={panelRef}
          role="menu"
          aria-label={t('notifications.title')}
          className="absolute end-0 mt-2 w-80 max-w-[90vw] rounded-xl border border-white/10 bg-[#0b1120]/98 backdrop-blur-md shadow-2xl z-50 overflow-hidden"
        >
          <div className="flex items-center justify-between gap-2 px-3 py-2.5 border-b border-white/10">
            <span className="text-[12px] font-semibold text-white/85">
              {t('notifications.title')}
              {unreadCount > 0 && (
                <span className="ml-1.5 text-[10px] font-mono text-rose-300">
                  {t('notifications.unread_count', { count: unreadCount })}
                </span>
              )}
            </span>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={markAllRead}
                disabled={unreadCount === 0}
                title={t('notifications.mark_all_read')}
                aria-label={t('notifications.mark_all_read')}
                className="p-1.5 rounded text-white/50 hover:text-white hover:bg-white/5 disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <Check className="w-3.5 h-3.5" aria-hidden />
              </button>
              <button
                type="button"
                onClick={clearAll}
                disabled={notifications.length === 0}
                title={t('notifications.clear_all')}
                aria-label={t('notifications.clear_all')}
                className="p-1.5 rounded text-white/50 hover:text-white hover:bg-white/5 disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <Trash2 className="w-3.5 h-3.5" aria-hidden />
              </button>
            </div>
          </div>

          <div className="max-h-[60vh] overflow-y-auto custom-scroll">
            {notifications.length === 0 ? (
              <div className="px-4 py-8 text-center text-[12px] text-white/40 font-mono">
                {t('notifications.empty')}
              </div>
            ) : (
              notifications.map((n) => (
                <button
                  key={n.id}
                  type="button"
                  onClick={() => onItemClick(n)}
                  className={`w-full text-start flex items-start gap-2.5 px-3 py-2.5 border-b border-white/5 transition-colors ${
                    n.read ? 'hover:bg-white/[0.02]' : 'bg-cyan-500/[0.05] hover:bg-cyan-500/[0.08]'
                  }`}
                  role="menuitem"
                >
                  <span
                    className="mt-1 w-2 h-2 rounded-full shrink-0"
                    style={{ backgroundColor: SEVERITY_DOT[n.severity] || SEVERITY_DOT.info }}
                    aria-hidden
                  />
                  <span className="flex-1 min-w-0">
                    <span className="flex items-center gap-1.5">
                      {!n.read && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0" aria-hidden />}
                      <span className="text-[12px] text-white/85 line-clamp-2 break-words">
                        {n.message || t('notifications.untitled')}
                      </span>
                      {n.link && <ExternalLink className="w-3 h-3 text-white/30 shrink-0" aria-hidden />}
                    </span>
                    <span className="flex items-center gap-2 mt-1 text-[10px] font-mono text-white/40">
                      {n.engine && <span className="truncate max-w-[8rem]">{n.engine}</span>}
                      {n.engine && <span aria-hidden>·</span>}
                      <span>{relativeTime(n.ts, t)}</span>
                    </span>
                  </span>
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
