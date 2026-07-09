/**
 * MITRE ATT&CK Coverage Matrix.
 *
 * Wired to the live GET /api/attack-coverage endpoint, which reports which
 * ATT&CK techniques the platform's engines cover (tactic → technique → engines)
 * plus rollup totals. Global capability view — no client selection. Route:
 * /attack-coverage
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Grid3x3, Search } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import { SkeletonWidgetGrid, SkeletonCard } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../lib/apiBase'

const NS = 'pages.attackCoverage'

/** Deterministic accent per tactic so the matrix reads as one system. */
const TACTIC_COLORS = [
  '#22d3ee', '#a78bfa', '#f97316', '#4ade80', '#f43f5e',
  '#facc15', '#38bdf8', '#c084fc', '#fb7185', '#34d399',
  '#fbbf24', '#60a5fa', '#f472b6', '#2dd4bf',
]
function tacticColor(i) {
  return TACTIC_COLORS[i % TACTIC_COLORS.length]
}

function coverageCsv(tactics) {
  const header = ['tactic', 'technique_id', 'technique_name', 'engine_count', 'engines']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const rows = []
  for (const tac of tactics) {
    for (const tech of tac.techniques || []) {
      rows.push([tac.tactic, tech.id, tech.name, tech.engine_count, (tech.engines || []).join(' ')].map(esc).join(','))
    }
  }
  const blob = new Blob([[header.join(','), ...rows].join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `weissman-attack-coverage-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function AttackCoverage() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const r = await apiFetch('/api/attack-coverage')
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`)
      setData(d)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const tactics = useMemo(() => (Array.isArray(data?.tactics) ? data.tactics : []), [data])
  const totals = data?.totals || {}

  const filteredTactics = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return tactics
    return tactics
      .map((tac) => {
        const techniques = (tac.techniques || []).filter((tech) => {
          const hay = `${tac.tactic} ${tech.id} ${tech.name} ${(tech.engines || []).join(' ')}`.toLowerCase()
          return hay.includes(q)
        })
        return { ...tac, techniques }
      })
      .filter((tac) => tac.techniques.length > 0)
  }, [tactics, search])

  const shownTechniques = useMemo(
    () => filteredTactics.reduce((n, tac) => n + (tac.techniques?.length || 0), 0),
    [filteredTactics],
  )

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={data?.framework || 'MITRE ATT&CK'}
      badgeColor="#f43f5e"
      icon={<Grid3x3 className="w-5 h-5" />}
      actions={
        <ShellScanActions
          onRefresh={load}
          onExport={() => coverageCsv(tactics)}
          refreshLoading={loading}
          exportDisabled={!tactics.length}
        />
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading && <SkeletonWidgetGrid count={3} />}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && !error && (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_techniques`)} value={totals.techniques_covered ?? 0} hint={t(`${NS}.kpi_techniques_hint`)} accent="#f43f5e" />
              <ExecutiveWidget label={t(`${NS}.kpi_tactics`)} value={totals.tactics_covered ?? 0} hint={t(`${NS}.kpi_tactics_hint`)} accent="#a78bfa" />
              <ExecutiveWidget label={t(`${NS}.kpi_engine_refs`)} value={totals.engine_references ?? 0} hint={t(`${NS}.kpi_engine_refs_hint`)} accent="#22d3ee" />
            </div>

            <div className="relative max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                aria-label={t(`${NS}.search_placeholder`)}
                placeholder={t(`${NS}.search_placeholder`)}
                className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-rose-500/40"
              />
            </div>

            {search && (
              <div className="text-[11px] font-mono text-[var(--text-muted)]">
                {t(`${NS}.showing`, { techniques: shownTechniques, tactics: filteredTactics.length })}
              </div>
            )}

            {loading ? (
              <SkeletonCard lines={8} />
            ) : filteredTactics.length === 0 ? (
              <EmptyState icon="🔍" title={t(`${NS}.no_match_title`)} body={t(`${NS}.no_match_body`)} />
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {filteredTactics.map((tac, i) => {
                  const color = tacticColor(i)
                  return (
                    <section
                      key={tac.tactic}
                      className="rounded-2xl border bg-[var(--table-surface)] backdrop-blur-md p-4"
                      style={{ borderColor: `${color}30` }}
                    >
                      <div className="flex items-center justify-between mb-3">
                        <h2 className="text-xs font-bold uppercase tracking-wider" style={{ color }}>
                          {tac.tactic}
                        </h2>
                        <span
                          className="text-[10px] font-mono px-2 py-0.5 rounded-full border tabular-nums"
                          style={{ color, borderColor: `${color}40`, background: `${color}10` }}
                        >
                          {tac.techniques?.length ?? tac.technique_count ?? 0}
                        </span>
                      </div>
                      <ul className="space-y-2">
                        {(tac.techniques || []).map((tech) => (
                          <li key={tech.id} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--table-surface)] p-2.5">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] border border-[var(--border-default)] text-[var(--text-tertiary)]">
                                {tech.id}
                              </span>
                              <span className="text-[12px] text-[var(--text-primary)] truncate" title={tech.name}>
                                {tech.name}
                              </span>
                            </div>
                            {(tech.engines || []).length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-1.5">
                                {tech.engines.map((eng) => (
                                  <span
                                    key={eng}
                                    className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/5 text-cyan-300/75"
                                  >
                                    {eng}
                                  </span>
                                ))}
                              </div>
                            )}
                          </li>
                        ))}
                      </ul>
                    </section>
                  )
                })}
              </div>
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
