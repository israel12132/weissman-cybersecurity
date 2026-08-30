/**
 * CEM-DAGO Cognitive Mesh — live blackboard, DAG waves, engine manifests.
 *
 * Wired to GET /api/cem-dago/status, /api/cem-dago/blackboard, /api/cem-dago/manifests,
 * /api/cem-dago/waves. Evidence is Redis-backed scan memory written by the worker;
 * empty blackboard is a real idle state, not placeholder findings.
 * Route: /cem-dago
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { GitBranch, RefreshCw } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import Button from '../components/ui/Button'

const NS = 'pages.cemDago'
const columnHelper = createColumnHelper()

function evidenceCsv(rows) {
  const header = ['key', 'source_engine', 'timestamp', 'value']
  const data = rows.map((r) => [r.key, r.source_engine, r.timestamp, r.value])
  downloadCsv(data, header, 'weissman-cem-dago-blackboard')
}

export default function CemDagoMesh() {
  const { t } = useTranslation()
  const { clients, selectedClientId, setSelectedClientId } = useClient()

  const [status, setStatus] = useState(null)
  const [blackboard, setBlackboard] = useState(null)
  const [manifests, setManifests] = useState([])
  const [waves, setWaves] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [searchTerm, setSearchTerm] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [st, man, wv] = await Promise.all([
        apiFetch('/api/cem-dago/status'),
        apiFetch('/api/cem-dago/manifests?limit=563'),
        apiFetch('/api/cem-dago/waves?signals=internet_exposed,web_port_active'),
      ])
      setStatus(st)
      setManifests(Array.isArray(man?.manifests) ? man.manifests : [])
      setWaves(Array.isArray(wv?.waves) ? wv.waves : [])
      if (selectedClientId != null) {
        const bb = await apiFetch(`/api/cem-dago/blackboard?client_id=${encodeURIComponent(selectedClientId)}`)
        setBlackboard(bb)
      } else {
        setBlackboard(null)
      }
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [selectedClientId, t])

  useEffect(() => {
    load()
  }, [load])

  const evidenceRows = useMemo(() => {
    const ev = blackboard?.evidence && typeof blackboard.evidence === 'object' ? blackboard.evidence : {}
    return Object.entries(ev).map(([key, v]) => ({
      key,
      source_engine: v?.source_engine || '—',
      timestamp: v?.timestamp || '',
      value: typeof v?.value === 'string' ? v.value : JSON.stringify(v?.value ?? {}),
    }))
  }, [blackboard])

  const failureRows = useMemo(
    () => (Array.isArray(blackboard?.failures) ? blackboard.failures : []),
    [blackboard],
  )

  const filteredManifests = useMemo(() => {
    const q = searchTerm.trim().toLowerCase()
    if (!q) return manifests
    return manifests.filter((m) => {
      const hay = `${m.id} ${m.group} ${(m.required_inputs || []).join(' ')} ${(m.output_signals || []).join(' ')} ${(m.mitre_techniques || []).join(' ')}`.toLowerCase()
      return hay.includes(q)
    })
  }, [manifests, searchTerm])

  const manifestColumns = useMemo(
    () => [
      columnHelper.accessor('id', {
        header: t(`${NS}.col_engine`),
        cell: (ctx) => (
          <span className="font-mono text-[11px] text-[var(--text-primary)]">{ctx.getValue()}</span>
        ),
      }),
      columnHelper.accessor('group', {
        header: t(`${NS}.col_group`),
        cell: (ctx) => <span className="text-[var(--text-tertiary)] text-[11px]">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor('required_inputs', {
        header: t(`${NS}.col_inputs`),
        cell: (ctx) => (
          <span className="font-mono text-[10px] text-cyan-300/80">{(ctx.getValue() || []).join(', ') || '—'}</span>
        ),
      }),
      columnHelper.accessor('output_signals', {
        header: t(`${NS}.col_outputs`),
        cell: (ctx) => (
          <span className="font-mono text-[10px] text-orange-200/80">{(ctx.getValue() || []).join(', ') || '—'}</span>
        ),
      }),
      columnHelper.accessor('mitre_techniques', {
        header: 'MITRE',
        cell: (ctx) => (
          <span className="font-mono text-[10px] text-[var(--text-muted)]">{(ctx.getValue() || []).join(' ')}</span>
        ),
      }),
    ],
    [t],
  )

  const evidenceColumns = useMemo(
    () => [
      columnHelper.accessor('key', {
        header: t(`${NS}.col_signal`),
        cell: (ctx) => <span className="font-mono text-[11px] text-cyan-200">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor('source_engine', {
        header: t(`${NS}.col_source`),
        cell: (ctx) => <span className="font-mono text-[11px]">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor('value', {
        header: t(`${NS}.col_value`),
        cell: (ctx) => (
          <span className="font-mono text-[10px] text-[var(--text-tertiary)] truncate max-w-[28rem] block" title={ctx.getValue()}>
            {ctx.getValue()}
          </span>
        ),
      }),
    ],
    [t],
  )

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#22d3ee"
      icon={<GitBranch className="w-5 h-5" />}
      actions={
        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value ? Number(e.target.value) : null)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40"
            aria-label={t(`${NS}.select_client`)}
          >
            <option value="">{t(`${NS}.select_client`)}</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name || c.domain || `#${c.id}`}
              </option>
            ))}
          </select>
          <Button
            variant="unstyled"
            type="button"
            onClick={load}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-200 text-xs font-medium hover:bg-cyan-500/20 disabled:opacity-40"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {t(`${NS}.reload`)}
          </Button>
          <ShellScanActions
            onRefresh={load}
            onExport={() => evidenceCsv(evidenceRows)}
            refreshLoading={loading}
            exportDisabled={!evidenceRows.length}
          />
        </div>
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {loading && !status && <SkeletonWidgetGrid count={4} />}

        {status && (
          <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-7 gap-3">
            <ExecutiveWidget
              label={t(`${NS}.kpi_enabled`)}
              value={status.enabled ? t(`${NS}.on`) : t(`${NS}.off`)}
              hint={t(`${NS}.kpi_enabled_hint`)}
              accent="#22d3ee"
            />
            <ExecutiveWidget
              label={t(`${NS}.kpi_parallel`)}
              value={status.max_parallel ?? '—'}
              hint={t(`${NS}.kpi_parallel_hint`)}
              accent="#a78bfa"
            />
            <ExecutiveWidget
              label={t(`${NS}.kpi_lanes`)}
              value={`OT ${status.ot_max_parallel ?? '—'} · APT ${status.apt_max_parallel ?? '—'}`}
              hint={t(`${NS}.kpi_lanes_hint`)}
              accent="#fb923c"
            />
            <ExecutiveWidget
              label={t(`${NS}.kpi_redis`)}
              value={status.redis_configured ? t(`${NS}.on`) : t(`${NS}.off`)}
              hint={t(`${NS}.kpi_redis_hint`)}
              accent={status.redis_configured ? '#22d3ee' : '#f97316'}
            />
            <ExecutiveWidget
              label={t(`${NS}.kpi_ro`)}
              value={status.weissman_ro_configured ? t(`${NS}.on`) : t(`${NS}.off`)}
              hint={t(`${NS}.kpi_ro_hint`)}
              accent={status.weissman_ro_configured ? '#22d3ee' : '#f97316'}
            />
            <ExecutiveWidget
              label={t(`${NS}.kpi_evidence`)}
              value={blackboard?.evidence_count ?? 0}
              hint={t(`${NS}.kpi_evidence_hint`)}
              accent="#f97316"
            />
            <ExecutiveWidget
              label={t(`${NS}.kpi_trie`)}
              value={
                status.trie_prewarm
                  ? `${status.trie_prewarm.window_days}d · ${(status.trie_prewarm.batch_size ?? 0).toLocaleString()}`
                  : '—'
              }
              hint={t(`${NS}.kpi_trie_hint`)}
              accent="#34d399"
            />
          </div>
        )}

        <div>
          <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
            {t(`${NS}.waves_heading`)}
          </h2>
          {waves.length === 0 ? (
            <EmptyState icon="network" title={t(`${NS}.no_waves_title`)} body={t(`${NS}.no_waves_body`)} />
          ) : (
            <div className="flex flex-col gap-2">
              {waves.map((wave, i) => (
                <div
                  key={`wave-${i}`}
                  className="rounded-xl border border-[var(--border-subtle)] bg-[var(--table-surface)] p-3 flex items-center gap-3 flex-wrap"
                >
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/40 text-cyan-300">
                    {t(`${NS}.wave`, { n: i })}
                  </span>
                  {(wave || []).map((id) => (
                    <span
                      key={id}
                      className="text-[10px] font-mono px-2 py-1 rounded border border-[var(--border-default)] text-[var(--text-secondary)]"
                    >
                      {id}
                    </span>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>

        <div>
          <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
            {t(`${NS}.blackboard_heading`)}
          </h2>
          {selectedClientId == null ? (
            <EmptyState icon="building" title={t(`${NS}.pick_client_title`)} body={t(`${NS}.pick_client_body`)} />
          ) : evidenceRows.length === 0 ? (
            <EmptyState icon="shield" title={t(`${NS}.no_evidence_title`)} body={t(`${NS}.no_evidence_body`)} />
          ) : (
            <DataTable
              id="cem-dago-evidence"
              columns={evidenceColumns}
              data={evidenceRows}
              animateRows={false}
              searchable
              getRowId={(r) => r.key}
            />
          )}
          {failureRows.length > 0 && (
            <div className="mt-3 rounded-xl border border-rose-500/25 bg-rose-950/10 p-3">
              <h3 className="text-[10px] font-mono uppercase tracking-widest text-rose-300 mb-2">{t(`${NS}.failures`)}</h3>
              <ul className="space-y-1">
                {failureRows.map((f, i) => (
                  <li key={`${f.engine_id}-${i}`} className="text-[11px] font-mono text-rose-200/90">
                    {f.engine_id} @ {f.target}: {f.error_message}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div>
          <div className="flex items-center justify-between gap-3 mb-2 flex-wrap">
            <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
              {t(`${NS}.manifests_heading`)}
            </h2>
            <input
              type="search"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-secondary)] w-full max-w-xs focus:outline-none focus:border-cyan-500/40"
            />
          </div>
          {filteredManifests.length === 0 ? (
            <EmptyState icon="chart" title={t(`${NS}.no_manifests_title`)} body={t(`${NS}.no_manifests_body`)} />
          ) : (
            <DataTable
              id="cem-dago-manifests"
              columns={manifestColumns}
              data={filteredManifests}
              animateRows={false}
              searchable
              getRowId={(r) => r.id}
            />
          )}
        </div>
      </div>
    </PageShell>
  )
}
