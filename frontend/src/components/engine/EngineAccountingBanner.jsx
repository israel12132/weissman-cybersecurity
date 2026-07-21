import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../lib/apiBase'

/**
 * Honest engine accounting banner — surfaces GET /api/engines/accounting.
 *
 * The platform advertises many engine IDs, but a share of them are aliases that
 * resolve to a shared canonical probe. This banner reports the truthful split —
 * advertised IDs vs distinct real probe implementations vs aliases vs
 * agent-required — so the roster is never read as inflated capability.
 */
export default function EngineAccountingBanner() {
  const { t } = useTranslation()
  const [a, setA] = useState(null)
  const [err, setErr] = useState(false)

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/engines/accounting')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((j) => {
        if (!cancelled) setA(j)
      })
      .catch(() => {
        if (!cancelled) setErr(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (err || !a) return null

  const ratioPct = Math.round((Number(a.distinct_ratio) || 0) * 100)
  const cells = [
    { label: t('engineAccounting.advertisedIds'), value: a.total_ids, tone: 'text-text-secondary' },
    { label: t('engineAccounting.distinctReal'), value: a.distinct_canonical, tone: 'text-emerald-300' },
    { label: t('engineAccounting.aliases'), value: a.alias_ids, tone: 'text-amber-300' },
    { label: t('engineAccounting.agentRequired'), value: a.agent_required, tone: 'text-sky-300' },
    { label: t('engineAccounting.remotelyDetecting'), value: a.remotely_detecting, tone: 'text-cyan-300' },
  ]

  return (
    <section className="rounded-xl border border-white/10 bg-bg-2/40 p-4">
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-text-tertiary">
          {t('engineAccounting.title')}
        </h2>
        <span className="text-[11px] font-mono text-text-muted">GET /api/engines/accounting</span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-3">
        {cells.map((c) => (
          <div key={c.label} className="rounded-lg border border-white/10 bg-bg-1/40 px-3 py-2">
            <div className="text-[10px] uppercase tracking-wider text-text-muted">{c.label}</div>
            <div className={`text-xl font-mono font-semibold tabular-nums ${c.tone}`}>
              {Number(c.value).toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      <div className="mb-1 flex items-center justify-between text-[11px] text-text-muted">
        <span>{t('engineAccounting.ratioLabel')}</span>
        <span className="font-mono text-text-secondary tabular-nums">{ratioPct}%</span>
      </div>
      <div className="h-2 rounded-full bg-white/10 overflow-hidden">
        <div
          className={`h-full ${ratioPct >= 80 ? 'bg-emerald-500' : ratioPct >= 55 ? 'bg-amber-500' : 'bg-rose-500'}`}
          style={{ width: `${Math.max(0, Math.min(100, ratioPct))}%` }}
        />
      </div>

      {a.note && <p className="mt-3 text-xs text-text-muted leading-relaxed">{a.note}</p>}
    </section>
  )
}
