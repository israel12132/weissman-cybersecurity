import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Bell, Check, Trash2, ExternalLink } from 'lucide-react'
import { useNotifications } from '../../context/NotificationContext'
import useFocusTrap from '../../hooks/useFocusTrap'
import Button from '../ui/Button'

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
      <Button variant="unstyled"
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="relative inline-flex items-center justify-center w-8 h-8 rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--text-primary)] transition-colors"
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
      </Button>

      {open && (
        <div
          ref={panelRef}
          role="menu"
          aria-label={t('notifications.title')}
          className="absolute end-0 mt-2 w-80 max-w-[90vw] rounded-xl border border-[var(--border-default)] bg-[var(--bg-elevated)] backdrop-blur-md shadow-2xl z-50 overflow-hidden"
        >
          <div className="flex items-center justify-between gap-2 px-3 py-2.5 border-b border-[var(--border-default)]">
            <span className="text-[12px] font-semibold text-[var(--text-primary)]">
              {t('notifications.title')}
              {unreadCount > 0 && (
                <span className="ml-1.5 text-[10px] font-mono text-rose-300">
                  {t('notifications.unread_count', { count: unreadCount })}
                </span>
              )}
            </span>
            <div className="flex items-center gap-1">
              <Button variant="unstyled"
                type="button"
                onClick={markAllRead}
                disabled={unreadCount === 0}
                title={t('notifications.mark_all_read')}
                aria-label={t('notifications.mark_all_read')}
                className="p-1.5 rounded text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)] disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <Check className="w-3.5 h-3.5" aria-hidden />
              </Button>
              <Button variant="unstyled"
                type="button"
                onClick={clearAll}
                disabled={notifications.length === 0}
                title={t('notifications.clear_all')}
                aria-label={t('notifications.clear_all')}
                className="p-1.5 rounded text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)] disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <Trash2 className="w-3.5 h-3.5" aria-hidden />
              </Button>
            </div>
          </div>

          <div className="max-h-[60vh] overflow-y-auto custom-scroll">
            {notifications.length === 0 ? (
              <div className="px-4 py-8 text-center text-[12px] text-[var(--text-muted)] font-mono">
                {t('notifications.empty')}
              </div>
            ) : (
              notifications.map((n) => (
                <Button variant="unstyled"
                  key={n.id}
                  type="button"
                  onClick={() => onItemClick(n)}
                  className={`w-full text-start flex items-start gap-2.5 px-3 py-2.5 border-b border-[var(--border-subtle)] transition-colors ${
                    n.read ? 'hover:bg-[var(--row-hover-bg)]' : 'bg-cyan-500/[0.05] hover:bg-cyan-500/[0.08]'
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
                      <span className="text-[12px] text-[var(--text-primary)] line-clamp-2 break-words">
                        {n.message || t('notifications.untitled')}
                      </span>
                      {n.link && <ExternalLink className="w-3 h-3 text-[var(--text-disabled)] shrink-0" aria-hidden />}
                    </span>
                    <span className="flex items-center gap-2 mt-1 text-[10px] font-mono text-[var(--text-muted)]">
                      {n.engine && <span className="truncate max-w-[8rem]">{n.engine}</span>}
                      {n.engine && <span aria-hidden>·</span>}
                      <span>{relativeTime(n.ts, t)}</span>
                    </span>
                  </span>
                </Button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
