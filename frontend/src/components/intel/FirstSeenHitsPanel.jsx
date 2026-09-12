import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/apiFetch'
import EmptyState from '../ui/EmptyState'

const NS = 'pages.attackSurfaceManagement'

function nvdBadge(t, hit) {
  if (hit.claimed_first_seen) return t(`${NS}.first_seen_badge_pre`)
  if (hit.nvd_status === 'listed') return t(`${NS}.first_seen_status_listed`)
  if (hit.nvd_status === 'skipped_no_key') return t(`${NS}.first_seen_status_skipped`)
  if (hit.nvd_status === 'unpublished') return t(`${NS}.first_seen_status_unpublished`)
  if (hit.nvd_status === 'absent_cve') return t(`${NS}.first_seen_badge_pre`)
  return t(`${NS}.first_seen_status_unknown`)
}

/**
 * Live SBOM × OSV hits. `listed` is shown but never titled first-seen.
 */
export default function FirstSeenHitsPanel({ clientId }) {
  const { t } = useTranslation()
  const [payload, setPayload] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (clientId == null) {
      setPayload(null)
      setError('')
      setLoading(false)
      return undefined
    }
    let cancelled = false
    setLoading(true)
    setError('')
    apiFetch(`/api/clients/${encodeURIComponent(clientId)}/first-seen-hits`)
      .then((data) => {
        if (cancelled) return
        if (!data || data.ok === false || data.unavailable) {
          throw new Error(data?.detail || t(`${NS}.first_seen_load_failed`))
        }
        setPayload(data)
      })
      .catch((e) => {
        if (cancelled) return
        setError(e.message || t(`${NS}.first_seen_load_failed`))
        setPayload(null)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [clientId, t])

  if (clientId == null) return null

  const hits = Array.isArray(payload?.hits) ? payload.hits : []
  const firstSeen = hits.filter((h) => h.claimed_first_seen)
  const listed = hits.filter((h) => h.nvd_status === 'listed')

  return (
    <div
      data-testid="first-seen-hits-panel"
      className="rounded-2xl border border-cyan-500/25 bg-gradient-to-br from-cyan-950/30 via-black/30 to-amber-950/20 p-4 mb-5"
    >
      <div className="flex items-start justify-between gap-3 mb-3">
        <div>
          <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-cyan-300/80">
            {t(`${NS}.first_seen_title`)}
          </p>
          <p className="text-[12px] text-[var(--text-tertiary)] font-mono mt-1 max-w-2xl">
            {t(`${NS}.first_seen_subtitle`)}
          </p>
        </div>
        <span className="text-[10px] font-mono text-cyan-200/80">
          {payload?.nvd_api_key_configured
            ? t(`${NS}.nerve_live`)
            : t(`${NS}.nerve_nvd_osv_only`)}
        </span>
      </div>

      {error && (
        <p role="alert" className="text-[11px] font-mono text-rose-300 mb-2">{error}</p>
      )}

      {loading && (
        <p className="text-[11px] font-mono text-[var(--text-muted)]">{t(`${NS}.first_seen_loading`)}</p>
      )}

      {!loading && !error && (
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2 mb-3">
          <div className="rounded-lg border border-white/[0.07] bg-black/30 px-3 py-2">
            <p className="text-[9px] font-mono uppercase tracking-wider text-[var(--text-muted)]">
              {t(`${NS}.first_seen_pre_nvd`)}
            </p>
            <p className="text-xl font-bold tabular-nums text-amber-300">
              {payload?.first_seen_count ?? firstSeen.length}
            </p>
          </div>
          <div className="rounded-lg border border-white/[0.07] bg-black/30 px-3 py-2">
            <p className="text-[9px] font-mono uppercase tracking-wider text-[var(--text-muted)]">
              {t(`${NS}.first_seen_listed`)}
            </p>
            <p className="text-xl font-bold tabular-nums text-slate-300">
              {payload?.listed_count ?? listed.length}
            </p>
          </div>
          <div className="rounded-lg border border-white/[0.07] bg-black/30 px-3 py-2">
            <p className="text-[9px] font-mono uppercase tracking-wider text-[var(--text-muted)]">
              {t(`${NS}.first_seen_skipped`)}
            </p>
            <p className="text-xl font-bold tabular-nums text-cyan-200">
              {payload?.skipped_count ?? 0}
            </p>
          </div>
        </div>
      )}

      {!loading && !error && hits.length === 0 && (
        <EmptyState
          icon="shield"
          title={t(`${NS}.first_seen_empty_title`)}
          body={t(`${NS}.first_seen_empty_body`)}
        />
      )}

      {!loading && !error && hits.length > 0 && (
        <ul className="space-y-2 max-h-64 overflow-y-auto">
          {hits.map((h) => (
            <li
              key={h.id}
              className="rounded-lg border border-white/[0.06] bg-black/25 px-3 py-2"
              data-testid={`first-seen-row-${h.id}`}
            >
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="text-[12px] font-mono text-[var(--text-primary)]">
                  {h.package_name}@{h.version_spec || '—'}
                </span>
                <span
                  className={`text-[9px] font-mono uppercase tracking-widest px-1.5 py-0.5 rounded border ${
                    h.claimed_first_seen
                      ? 'border-amber-500/40 text-amber-200 bg-amber-500/10'
                      : h.nvd_status === 'listed'
                        ? 'border-slate-500/40 text-slate-300 bg-slate-500/10'
                        : 'border-cyan-500/40 text-cyan-200 bg-cyan-500/10'
                  }`}
                >
                  {nvdBadge(t, h)}
                </span>
              </div>
              <p className="text-[10px] font-mono text-[var(--text-muted)] mt-1">
                {h.osv_id}
                {h.cve_id ? ` · ${h.cve_id}` : ''}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
