/**
 * Attack Vector Analytics
 *
 * Surfaces the cross-domain attack-vector synthesis engine (GET /api/analytics/attack-vectors):
 * composite, multi-stage attack vectors fused from live findings across engines. Each vector is
 * evidence-gated on real findings, carries a MITRE technique chain, a confidence, a novelty rating,
 * business impact, and prioritized remediation. Route: /attack-vectors
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { motion } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import EmptyState from '../components/ui/EmptyState'
import { apiFetch } from '../utils/apiFetch'

const SEVERITY_META = {
  critical: { color: '#ef4444', rank: 5 },
  high: { color: '#f97316', rank: 4 },
  medium: { color: '#f59e0b', rank: 3 },
  low: { color: '#22d3ee', rank: 2 },
  info: { color: '#6b7280', rank: 1 },
}

function sevMeta(sev) {
  return SEVERITY_META[(sev || 'info').toLowerCase()] || SEVERITY_META.info
}

function mitreUrl(technique) {
  return `https://attack.mitre.org/techniques/${String(technique).replace('.', '/')}/`
}

/** Novelty pips (1..5) — how rarely this cross-domain chain is detected elsewhere. */
function NoveltyPips({ value }) {
  return (
    <span className="inline-flex items-center gap-0.5" aria-hidden>
      {[1, 2, 3, 4, 5].map((n) => (
        <span
          key={n}
          className="inline-block w-1.5 h-1.5 rounded-full"
          style={{ backgroundColor: n <= value ? '#a78bfa' : 'rgba(255,255,255,0.12)' }}
        />
      ))}
    </span>
  )
}

function VectorCard({ vector, t }) {
  const sm = sevMeta(vector.severity)
  const confidencePct = Math.round((vector.confidence || 0) * 100)
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border bg-[var(--row-hover-bg)] overflow-hidden"
      style={{ borderColor: `${sm.color}40` }}
    >
      <div className="h-1" style={{ background: `linear-gradient(90deg, ${sm.color}, transparent)` }} />
      <div className="p-5">
        <div className="flex items-start justify-between gap-4 mb-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className="text-[10px] font-mono px-2 py-0.5 rounded border uppercase tracking-wider"
                style={{ color: sm.color, borderColor: `${sm.color}40`, backgroundColor: `${sm.color}12` }}
              >
                {t(`pages.attackVectors.severity_${(vector.severity || 'info').toLowerCase()}`, { defaultValue: vector.severity })}
              </span>
              {vector.tactics?.map((ta) => (
                <span key={ta} className="text-[10px] font-mono text-[var(--text-disabled)]">{ta}</span>
              ))}
            </div>
            <h3 className="text-base font-bold text-white mt-2">{vector.name}</h3>
          </div>
          <div className="text-right flex-shrink-0">
            <div className="text-2xl font-bold" style={{ color: sm.color }}>{vector.priority}</div>
            <div className="text-[10px] text-[var(--text-muted)]">{t('pages.attackVectors.priority')}</div>
          </div>
        </div>

        {/* MITRE technique chain */}
        <div className="flex items-center flex-wrap gap-1.5 mb-4">
          {vector.mitre_chain?.map((tech, i) => (
            <span key={tech} className="flex items-center gap-1.5">
              <a
                href={mitreUrl(tech)}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#6366f1]/20 text-[#a5b4fc] border border-[#6366f1]/30 hover:bg-[#6366f1]/30 transition-colors"
              >
                {tech}
              </a>
              {i < vector.mitre_chain.length - 1 && <span className="text-[var(--text-disabled)]">→</span>}
            </span>
          ))}
        </div>

        <p className="text-sm text-[var(--text-secondary)] leading-relaxed mb-4">{vector.narrative}</p>

        {/* Confidence + novelty */}
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <div className="flex justify-between text-[10px] text-[var(--text-muted)] mb-1">
              <span>{t('pages.attackVectors.confidence')}</span>
              <span className="font-mono" style={{ color: sm.color }}>{confidencePct}%</span>
            </div>
            <div className="w-full bg-[var(--bg-2)] rounded-full h-1.5">
              <div className="h-1.5 rounded-full" style={{ width: `${confidencePct}%`, backgroundColor: sm.color }} />
            </div>
          </div>
          <div>
            <div className="text-[10px] text-[var(--text-muted)] mb-1">{t('pages.attackVectors.novelty')}</div>
            <NoveltyPips value={vector.novelty} />
          </div>
        </div>

        {/* Business impact */}
        <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-1)] p-3 mb-4">
          <div className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mb-1">{t('pages.attackVectors.business_impact')}</div>
          <p className="text-xs text-[var(--text-tertiary)] leading-relaxed">{vector.business_impact}</p>
        </div>

        {/* Evidence */}
        {vector.evidence?.length > 0 && (
          <div className="mb-4">
            <div className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mb-2">
              {t('pages.attackVectors.evidence', { count: vector.evidence.length })}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {vector.evidence.map((ev) => {
                const evSm = sevMeta(ev.severity)
                return (
                  <Link
                    key={ev.id}
                    to={`/findings?q=${encodeURIComponent(ev.title || '')}`}
                    className="inline-flex items-center gap-1.5 text-[10px] px-2 py-1 rounded bg-[var(--bg-1)] border border-[var(--border-default)] hover:border-[var(--border-strong)] transition-colors"
                    title={ev.title}
                  >
                    <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: evSm.color }} />
                    <span className="text-[var(--text-tertiary)] font-mono">{ev.engine}</span>
                    <span className="text-[var(--text-muted)] truncate max-w-[220px]">{ev.title}</span>
                  </Link>
                )
              })}
            </div>
          </div>
        )}

        {/* Recommended actions */}
        {vector.recommended_actions?.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mb-2">{t('pages.attackVectors.recommended_actions')}</div>
            <ul className="space-y-1.5">
              {vector.recommended_actions.map((action, i) => (
                <li key={i} className="text-xs text-[var(--text-secondary)] flex items-start gap-2">
                  <span className="text-[#10b981] mt-0.5 flex-shrink-0">✓</span>
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </motion.div>
  )
}

export default function AttackVectorAnalytics() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await apiFetch('/api/analytics/attack-vectors')
      setData(res)
    } catch (e) {
      setError(e?.message || String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const vectors = useMemo(() => (Array.isArray(data?.vectors) ? data.vectors : []), [data])

  const kpis = useMemo(() => {
    const critical = vectors.filter((v) => (v.severity || '').toLowerCase() === 'critical').length
    const avgConf = vectors.length
      ? Math.round((vectors.reduce((a, v) => a + (v.confidence || 0), 0) / vectors.length) * 100)
      : 0
    return {
      total: vectors.length,
      highest: data?.highest_severity || 'info',
      critical,
      avgConf,
    }
  }, [vectors, data])

  return (
    <PageShell
      title={t('pages.attackVectors.title')}
      subtitle={t('pages.attackVectors.subtitle')}
      badge="SYNTHESIS"
      badgeColor="#a78bfa"
      actions={<ShellScanActions onRefresh={load} refreshLoading={loading} exportDisabled />}
    >
      <p className="text-xs text-[var(--text-muted)] font-mono mb-6">
        {t('pages.attackVectors.data_source_note', {
          rules: data?.coverage?.rules_total ?? 0,
          findings: data?.coverage?.findings_analyzed ?? 0,
        })}
      </p>

      {error && (
        <div className="mb-6 p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm">
          {t('pages.attackVectors.load_error', { error })}
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
        {[
          { label: t('pages.attackVectors.kpi_vectors'), value: loading ? '…' : kpis.total, color: '#a78bfa' },
          { label: t('pages.attackVectors.kpi_highest'), value: loading ? '…' : t(`pages.attackVectors.severity_${kpis.highest}`, { defaultValue: kpis.highest }), color: sevMeta(kpis.highest).color },
          { label: t('pages.attackVectors.kpi_critical'), value: loading ? '…' : kpis.critical, color: '#ef4444' },
          { label: t('pages.attackVectors.kpi_confidence'), value: loading ? '…' : `${kpis.avgConf}%`, color: '#22d3ee' },
        ].map((kpi) => (
          <div key={kpi.label} className="rounded-2xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] p-4 text-center">
            <div className="text-2xl font-bold" style={{ color: kpi.color }}>{kpi.value}</div>
            <div className="text-[11px] text-[var(--text-tertiary)] mt-1">{kpi.label}</div>
          </div>
        ))}
      </div>

      {loading ? (
        <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] p-8 text-center text-sm text-[var(--text-muted)]">
          {t('pages.attackVectors.loading')}
        </div>
      ) : vectors.length === 0 ? (
        <EmptyState
          icon="radar"
          title={t('pages.attackVectors.empty_title')}
          body={t('pages.attackVectors.empty_body')}
          cta={{ label: t('pages.attackVectors.cta_findings'), to: '/findings' }}
          secondary={{ label: t('pages.attackVectors.cta_engines'), to: '/engines' }}
        />
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
          {vectors.map((v) => (
            <VectorCard key={v.id} vector={v} t={t} />
          ))}
        </div>
      )}
    </PageShell>
  )
}
