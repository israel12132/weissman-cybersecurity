import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Monitor, LogOut, RefreshCw } from 'lucide-react'
import Button from '../ui/Button'
import { api } from '../../utils/apiFetch'
import { confirmDialog } from '../../utils/confirmDialog'
import { clearStepUpToken } from '../../lib/stepUpToken'

const NS = 'components.activeSessions'

/** Format an ISO-8601 timestamp with the active locale, or return null when absent/invalid. */
function formatTs(iso, locale) {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  try {
    return d.toLocaleString(locale || undefined, { dateStyle: 'medium', timeStyle: 'short' })
  } catch {
    return d.toISOString()
  }
}

/**
 * Active Sessions panel for the account security settings.
 *
 * Lists the caller's own active refresh sessions from `GET /api/auth/sessions`
 * (created_at, last_used_at, origin ip) and offers "Sign out everywhere" via
 * `POST /api/auth/sessions/revoke-all`. Revoke-all also clears the current session's cookies
 * server-side, so on success we drop any cached step-up token and send the operator to the
 * login gate.
 */
export default function ActiveSessionsPanel() {
  const { t, i18n } = useTranslation()
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(true)
  const [unavailable, setUnavailable] = useState(false)
  const [err, setErr] = useState('')
  const [revoking, setRevoking] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const d = await api.get('/api/auth/sessions')
      if (d?.ok === false || d?.unavailable) {
        throw new Error(d?.detail || t(`${NS}.errors.load_failed`))
      }
      setSessions(Array.isArray(d?.sessions) ? d.sessions : [])
      setUnavailable(false)
    } catch (e) {
      setUnavailable(true)
      setErr(e?.message || t(`${NS}.errors.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const revokeAll = useCallback(async () => {
    const ok = await confirmDialog({
      title: t(`${NS}.revoke_all_title`),
      message: t(`${NS}.revoke_all_confirm`),
      confirmLabel: t(`${NS}.revoke_all_action`),
      cancelLabel: t('common.cancel'),
      variant: 'danger',
    })
    if (!ok) return
    setRevoking(true)
    setErr('')
    try {
      await api.post('/api/auth/sessions/revoke-all')
      // Server cleared our cookies too — abandon the now-dead session cleanly.
      clearStepUpToken()
      window.location.assign('/login')
    } catch (e) {
      setErr(e?.message || t(`${NS}.errors.revoke_failed`))
      setRevoking(false)
    }
  }, [t])

  return (
    <div className="bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg p-4">
      <div className="flex items-center justify-between gap-3 mb-3">
        <h4 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2">
          <Monitor className="size-4 text-[var(--text-tertiary)]" aria-hidden="true" />
          {t(`${NS}.title`)}
        </h4>
        <Button
          variant="ghost"
          size="xs"
          onClick={load}
          disabled={loading || revoking}
          leftIcon={<RefreshCw />}
        >
          {t(`${NS}.refresh`)}
        </Button>
      </div>

      <p className="text-[11px] text-[var(--text-tertiary)] mb-3">{t(`${NS}.description`)}</p>

      {loading && <p className="text-[11px] text-[var(--text-muted)]">{t(`${NS}.loading`)}</p>}

      {!loading && unavailable && (
        <p data-testid="sessions-unavailable" className="text-[11px] text-rose-400" role="alert">
          {err || t(`${NS}.errors.load_failed`)}
        </p>
      )}

      {!loading && !unavailable && sessions.length === 0 && (
        <p className="text-[11px] text-[var(--text-muted)]">{t(`${NS}.empty`)}</p>
      )}

      {!loading && !unavailable && sessions.length > 0 && (
        <ul className="space-y-2">
          {sessions.map((s) => {
            const created = formatTs(s.created_at, i18n.language)
            const lastUsed = formatTs(s.last_used_at, i18n.language)
            return (
              <li
                key={s.id}
                className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 rounded-md border border-[var(--border-default)] bg-[var(--bg-2)] px-3 py-2 text-[11px]"
              >
                <span className="font-mono text-[var(--text-secondary)]">
                  {t(`${NS}.ip_label`)} {s.ip || t(`${NS}.ip_unknown`)}
                </span>
                <span className="text-[var(--text-tertiary)]">
                  {t(`${NS}.created_label`)} {created || t(`${NS}.unknown_time`)}
                </span>
                <span className="text-[var(--text-tertiary)]">
                  {t(`${NS}.last_used_label`)} {lastUsed || t(`${NS}.never`)}
                </span>
              </li>
            )
          })}
        </ul>
      )}

      {err && !unavailable && (
        <p className="mt-2 text-[11px] text-rose-400" role="alert">
          {err}
        </p>
      )}

      <div className="mt-3 border-t border-[var(--border-default)] pt-3">
        <Button
          variant="danger"
          size="sm"
          onClick={revokeAll}
          loading={revoking}
          disabled={loading}
          leftIcon={<LogOut />}
        >
          {t(`${NS}.revoke_all_action`)}
        </Button>
      </div>
    </div>
  )
}
