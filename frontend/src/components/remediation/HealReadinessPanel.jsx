import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { CheckCircle, XCircle, ShieldCheck, AlertTriangle, RefreshCw } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

/**
 * HealReadinessPanel — bilingual auto-heal readiness self-diagnostics from GET /api/heal-readiness.
 * The API returns each capability's label/detail/fix in BOTH he and en; this picks the active
 * language. Shows a 0-100 readiness score, a summary, and a per-capability checklist where every
 * missing capability carries a concrete "how to connect" hint. Theme-aware dark.
 */
export default function HealReadinessPanel() {
  const { t, i18n } = useTranslation()
  const he = (i18n.language || '').toLowerCase().startsWith('he')
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const r = await apiFetch('/api/heal-readiness')
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      setReport(await r.json())
    } catch (e) {
      setError(e.message || 'failed')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const pick = (en, heStr) => (he ? heStr : en) || en

  const scoreColor = (s) => (s >= 90 ? '#22c55e' : s >= 55 ? '#eab308' : '#f43f5e')

  return (
    <section className="rounded-2xl border border-white/10 bg-black/40 p-4 sm:p-5" dir={he ? 'rtl' : 'ltr'}>
      <div className="flex items-center justify-between gap-3 mb-3">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          {t('pages.healReadiness.title')}
        </h3>
        <button
          type="button"
          onClick={load}
          disabled={loading}
          className="inline-flex items-center gap-1.5 text-[11px] text-white/50 hover:text-white/80 disabled:opacity-40"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          {t('pages.healReadiness.refresh')}
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-lg border border-red-500/30 bg-red-900/20 text-red-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
        </div>
      )}

      {report && !error && (
        <>
          <div className="flex items-center gap-4 mb-4">
            <div
              className="relative shrink-0 grid place-items-center rounded-full"
              style={{
                width: 76, height: 76,
                background: `conic-gradient(${scoreColor(report.score)} ${report.score * 3.6}deg, rgba(255,255,255,0.08) 0deg)`,
              }}
            >
              <div className="grid place-items-center rounded-full bg-[#0b1120]" style={{ width: 60, height: 60 }}>
                <span className="text-lg font-bold tabular-nums text-white">{report.score}</span>
              </div>
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                {report.ready
                  ? <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                  : <XCircle className="w-4 h-4 text-rose-400 shrink-0" />}
                <span className={`text-sm font-semibold ${report.ready ? 'text-emerald-300' : 'text-rose-300'}`}>
                  {report.ready
                    ? t('pages.healReadiness.ready')
                    : t('pages.healReadiness.not_ready')}
                </span>
              </div>
              <p className="text-xs text-white/50 mt-1">{pick(report.summary_en, report.summary_he)}</p>
            </div>
          </div>

          <ul className="space-y-1.5">
            {(report.checks || []).map((c) => (
              <li key={c.key} className="rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-2">
                <div className="flex items-start gap-2">
                  {c.ok
                    ? <CheckCircle className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                    : <XCircle className={`w-4 h-4 mt-0.5 shrink-0 ${c.required ? 'text-rose-400' : 'text-amber-400'}`} />}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-medium text-white/85">{pick(c.label_en, c.label_he)}</span>
                      {c.required && (
                        <span className="text-[9px] uppercase tracking-wide text-rose-300/70 border border-rose-400/30 rounded px-1">
                          {t('pages.healReadiness.required')}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-white/40 mt-0.5">{pick(c.detail_en, c.detail_he)}</p>
                    {!c.ok && (c.fix_en || c.fix_he) && (
                      <p className="text-[11px] text-cyan-300/80 mt-1 font-mono break-words">
                        → {pick(c.fix_en, c.fix_he)}
                      </p>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  )
}
