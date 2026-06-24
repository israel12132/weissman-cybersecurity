import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertTriangle, CheckCircle2 } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

export default function ClientReadinessBanner({ clientId }) {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!clientId) return
    let cancelled = false
    ;(async () => {
      setLoading(true)
      try {
        const r = await apiFetch(`/api/clients/${clientId}/readiness`)
        if (r.ok && !cancelled) setData(await r.json())
      } catch { /* ignore */ }
      if (!cancelled) setLoading(false)
    })()
    return () => { cancelled = true }
  }, [clientId])

  if (loading || !data?.readiness) return null

  const { readiness } = data
  const ready = readiness.ready

  return (
    <div
      className={`rounded-xl border px-4 py-3 flex flex-wrap items-center justify-between gap-3 ${
        ready
          ? 'border-emerald-500/30 bg-emerald-950/20'
          : 'border-amber-500/30 bg-amber-950/20'
      }`}
    >
      <div className="flex items-center gap-2">
        {ready ? (
          <CheckCircle2 className="w-5 h-5 text-emerald-400" />
        ) : (
          <AlertTriangle className="w-5 h-5 text-amber-400" />
        )}
        <div>
          <div className="text-sm font-medium text-white">
            {ready
              ? t('pages.clientOnboarding.ready_title')
              : t('pages.clientOnboarding.gaps_title', { pct: readiness.percent })}
          </div>
          <div className="text-xs text-white/45">
            {readiness.satisfied}/{readiness.total} {t('pages.clientOnboarding.requirements_met')}
          </div>
        </div>
      </div>
      {!ready && (
        <span className="text-xs font-mono text-amber-200/70">
          {t('pages.clientOnboarding.fix_in_settings')}
        </span>
      )}
    </div>
  )
}
