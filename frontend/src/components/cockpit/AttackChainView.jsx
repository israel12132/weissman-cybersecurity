import { useEffect, useMemo, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import { ShieldAlert, ListOrdered } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'
import StandaloneLabShell from '../ui/StandaloneLabShell'

const NS = 'components.tools.attackChainView'

/** Coerce API / partial rows into safe render models */
function normalizeSteps(raw, t) {
  if (!Array.isArray(raw)) return []
  return raw
    .map((s, i) => {
      if (s == null || typeof s !== 'object') return null
      let order = s.step_order
      if (typeof order === 'string' && /^\d+$/.test(order)) order = parseInt(order, 10)
      if (typeof order !== 'number' || Number.isNaN(order)) order = i + 1
      const label = s.step_label != null && String(s.step_label).trim() !== ''
        ? String(s.step_label)
        : t(`${NS}.step_fallback`, { n: i + 1 })
      const payload = s.payload_or_action != null ? String(s.payload_or_action) : ''
      return { step_order: order, step_label: label, payload_or_action: payload }
    })
    .filter(Boolean)
}

function parseAttackChainPayload(json, t) {
  if (json == null || typeof json !== 'object' || Array.isArray(json)) {
    return { steps: [], run_id: null }
  }
  const run_id = json.run_id != null ? json.run_id : null
  const steps = normalizeSteps(json.steps, t)
  return { steps, run_id }
}

export default function AttackChainView() {
  const { t } = useTranslation()
  const { clientId } = useParams()
  const [data, setData] = useState({ steps: [], run_id: null })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!clientId) {
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    setError(null)
    apiFetch(`/api/clients/${clientId}/attack-chain`)
      .then((r) => {
        if (!r.ok) throw new Error(r.statusText || `HTTP ${r.status}`)
        return r.json()
      })
      .then((d) => {
        if (cancelled) return
        try {
          setData(parseAttackChainPayload(d, t))
        } catch {
          setData({ steps: [], run_id: null })
        }
      })
      .catch((e) => {
        if (!cancelled) setError(e?.message || String(e))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [clientId, t])

  const steps = useMemo(() => (Array.isArray(data?.steps) ? data.steps : []), [data])
  const runId = data?.run_id

  if (!clientId) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#09090b]">
        <p className="text-white/60">{t(`${NS}.no_client`)}</p>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#09090b]">
        <div className="text-cyan-400/80 animate-pulse">{t(`${NS}.loading`)}</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#09090b] gap-4">
        <div className="text-red-400">{error}</div>
        <Link to="/" className="text-sm text-cyan-400/90 hover:text-cyan-300">{t(`${NS}.back_war_room`)}</Link>
      </div>
    )
  }

  return (
    <StandaloneLabShell
      title={t(`${NS}.title`)}
      subtitle={runId != null && runId !== '' ? t(`${NS}.run_label`, { id: String(runId) }) : undefined}
    >
        {steps.length === 0 ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="rounded-xl border border-white/10 bg-black/40 backdrop-blur-sm p-8 text-center"
          >
            <ListOrdered className="w-12 h-12 mx-auto mb-3 text-white/30" />
            <p className="text-white/60">{t(`${NS}.no_chain`)}</p>
            <p className="text-sm text-white/40 mt-1">{t(`${NS}.no_chain_hint`)}</p>
          </motion.div>
        ) : (
          <div className="space-y-0">
            {steps.map((step, index) => {
              const order = typeof step?.step_order === 'number' && !Number.isNaN(step.step_order)
                ? step.step_order
                : index + 1
              const badge = order < 100 ? String(order) : '∞'
              const isHighOrderStyle = order >= 999
              const label = step?.step_label ?? '—'
              const payload = step?.payload_or_action ?? ''
              return (
                <motion.div
                  key={`${order}-${index}`}
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.06 }}
                  className="flex gap-4"
                >
                  <div className="flex flex-col items-center">
                    <div
                      className={`
                      w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold shrink-0
                      ${isHighOrderStyle ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'}
                    `}
                    >
                      {badge}
                    </div>
                    {index < steps.length - 1 && (
                      <div className="w-0.5 flex-1 min-h-[24px] bg-gradient-to-b from-cyan-500/40 to-transparent my-0.5" />
                    )}
                  </div>
                  <div className="pb-8 flex-1">
                    <div className="rounded-lg border border-white/10 bg-black/40 backdrop-blur-sm p-4">
                      <p className="text-white/95 font-medium leading-snug">{label}</p>
                      {payload ? (
                        <pre className="mt-2 text-xs text-white/60 whitespace-pre-wrap break-words font-mono">
                          {payload}
                        </pre>
                      ) : null}
                    </div>
                  </div>
                </motion.div>
              )
            })}
          </div>
        )}
    </StandaloneLabShell>
  )
}
