import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Crosshair } from 'lucide-react'
import { apiFetch } from '../lib/apiBase'

/**
 * PortfolioAttackPanel — fleet-wide MITRE ATT&CK exposure across all clients.
 *
 * Renders GET /api/portfolio/attack-exposure (tenant-scoped): the techniques the whole client base
 * is most exposed to, each with the total findings and how many distinct clients are affected — so
 * an MSSP SOC aligns detections to what's actually widespread, not just one noisy client.
 */

/** Pure: largest fleet finding_count (for bar scaling); >=1 to avoid a zero denominator. */
export function maxFindingCount(techniques) {
  if (!Array.isArray(techniques) || techniques.length === 0) return 1
  return Math.max(1, ...techniques.map((t) => Number(t?.finding_count) || 0))
}

export default function PortfolioAttackPanel() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await apiFetch('/api/portfolio/attack-exposure')
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
      setData(d && typeof d === 'object' ? d : null)
    } catch (e) {
      setError(e?.message || 'load failed')
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const techniques = Array.isArray(data?.techniques) ? data.techniques : []
  if (loading || error || techniques.length === 0) return null

  const top = techniques.slice(0, 10)
  const barMax = maxFindingCount(techniques)

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-rose-400" />
          {t('clients_page.fleet_attack_heading')}
        </h3>
        <span className="text-[10px] font-mono text-white/40">
          {t('clients_page.fleet_attack_summary', {
            techniques: Number(data.unique_techniques) || techniques.length,
            clients: Number(data.exposed_clients) || 0,
          })}
        </span>
      </div>

      <div className="p-4 space-y-2">
        {top.map((tech) => (
          <div key={tech.technique} className="flex items-center gap-2">
            <span className="w-20 shrink-0 text-[11px] font-mono text-rose-300">{tech.technique}</span>
            <span className="hidden sm:block w-44 shrink-0 text-[11px] text-white/60 truncate" title={tech.name || tech.tactic}>
              {tech.name || tech.tactic}
            </span>
            <div className="flex-1 h-2 rounded-full bg-white/5 overflow-hidden">
              <div className="h-full rounded-full bg-gradient-to-r from-rose-500/70 to-amber-400/70" style={{ width: `${((Number(tech.finding_count) || 0) / barMax) * 100}%` }} />
            </div>
            <span className="w-10 shrink-0 text-right text-xs font-bold tabular-nums text-white">{tech.finding_count}</span>
            <span className="w-16 shrink-0 text-right text-[10px] font-mono text-violet-300" title={t('clients_page.fleet_attack_clients_hint')}>
              {t('clients_page.fleet_attack_clients', { count: tech.client_count })}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
