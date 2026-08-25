/**
 * AI Key Readiness — live catalog of LLM providers and enrichment keys.
 * Secrets never leave the server; only SHA-256 fingerprints are shown.
 * Route: /ai-readiness
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { KeyRound, Radio, CheckCircle2, XCircle } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { SkeletonTable } from '../components/ui/Skeleton'
import EmptyState from '../components/ui/EmptyState'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { exportWorkbook, tableToWorkbookSpec } from '../lib/exportWorkbook'
import { exportDocument, tableToDocumentSpec } from '../lib/documentExport'
import Button from '../components/ui/Button'

const NS = 'pages.aiReadiness'

function flattenRows(data) {
  const providers = Array.isArray(data?.providers) ? data.providers : []
  const enrichment = Array.isArray(data?.enrichment) ? data.enrichment : []
  return [
    ...providers.map((p) => ({
      kind: 'llm',
      id: p.provider,
      label: p.label,
      key_env: p.key_env,
      configured: !!p.configured,
      fingerprint: p.key_fingerprint || '',
      model: p.model || '',
      base_url: p.base_url || '',
    })),
    ...enrichment.map((e) => ({
      kind: 'enrichment',
      id: e.id,
      label: e.id,
      key_env: e.key_env,
      configured: !!e.configured,
      fingerprint: e.key_fingerprint || '',
      model: '',
      base_url: '',
    })),
  ]
}

export default function AiReadiness() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [probe, setProbe] = useState(null)
  const [loading, setLoading] = useState(true)
  const [probing, setProbing] = useState(false)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const payload = await apiFetch('/api/ai/readiness')
      setData(payload)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const rows = useMemo(() => flattenRows(data), [data])
  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return rows
    return rows.filter((r) =>
      `${r.id} ${r.label} ${r.key_env} ${r.kind} ${r.model}`.toLowerCase().includes(q),
    )
  }, [rows, searchQuery])

  const exportTable = useMemo(
    () => ({
      header: ['kind', 'id', 'label', 'key_env', 'configured', 'fingerprint', 'model', 'base_url'],
      rows: filtered.map((r) => [
        r.kind,
        r.id,
        r.label,
        r.key_env,
        r.configured ? 'yes' : 'no',
        r.fingerprint,
        r.model,
        r.base_url,
      ]),
    }),
    [filtered],
  )

  const onExport = () => downloadCsv(exportTable.rows, exportTable.header, 'weissman-ai-readiness')
  const onExportXlsx = () =>
    exportWorkbook(
      tableToWorkbookSpec({ title: t(`${NS}.title`), header: exportTable.header, rows: exportTable.rows }),
      'weissman-ai-readiness',
    )
  const onExportPdf = () =>
    exportDocument(
      tableToDocumentSpec({ title: t(`${NS}.title`), header: exportTable.header, rows: exportTable.rows }),
      'weissman-ai-readiness',
    )

  const runProbe = async () => {
    setProbing(true)
    setProbe(null)
    try {
      const payload = await apiFetch('/api/ai/readiness/probe', { method: 'POST' })
      setProbe(payload)
    } catch (e) {
      setProbe({ ok: false, detail: e.message })
    } finally {
      setProbing(false)
    }
  }

  const configured = rows.filter((r) => r.configured).length

  return (
    <PageShell
      hideHubParams
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      actions={
        <ShellScanActions
          onRefresh={load}
          onExport={onExport}
          onExportXlsx={onExportXlsx}
          onExportPdf={onExportPdf}
          refreshLoading={loading}
          exportDisabled={!filtered.length}
        />
      }
    >
      <div className="space-y-4">
        <EvidenceNotice>{t(`${NS}.evidence`)}</EvidenceNotice>

        <div className="flex flex-wrap items-center gap-3">
          <label className="relative flex-1 min-w-[220px]">
            <span className="sr-only">{t(`${NS}.search`)}</span>
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t(`${NS}.search`)}
              className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] px-3 py-2 text-[12px] font-mono text-[var(--text-primary)] placeholder:text-[var(--text-muted)]"
            />
          </label>
          <Button
            variant="unstyled"
            type="button"
            onClick={runProbe}
            disabled={probing}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-cyan-500/35 text-[11px] font-mono text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-40"
          >
            <Radio className={`w-3.5 h-3.5 ${probing ? 'animate-pulse' : ''}`} />
            {t(`${NS}.probe`)}
          </Button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
            <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t(`${NS}.kpi_providers`)}</p>
            <p className="text-2xl font-mono text-cyan-300">{rows.filter((r) => r.kind === 'llm').length}</p>
          </div>
          <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
            <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t(`${NS}.kpi_ready`)}</p>
            <p className="text-2xl font-mono text-emerald-300">{configured}</p>
          </div>
          <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
            <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t(`${NS}.kpi_missing`)}</p>
            <p className="text-2xl font-mono text-amber-300">{rows.length - configured}</p>
          </div>
          <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
            <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t(`${NS}.kpi_chain`)}</p>
            <p className="text-2xl font-mono text-[var(--text-primary)]">{Array.isArray(data?.active_endpoints) ? data.active_endpoints.length : 0}</p>
          </div>
        </div>

        {probe && (
          <div className={`rounded-xl border px-4 py-3 text-[12px] font-mono ${probe.ok ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200' : 'border-rose-500/30 bg-rose-500/10 text-rose-200'}`}>
            {probe.ok
              ? t(`${NS}.probe_ok`, { label: probe.label || probe.provider, ms: probe.latency_ms, status: probe.http_status })
              : t(`${NS}.probe_fail`, { detail: probe.detail || `HTTP ${probe.http_status || '—'}` })}
          </div>
        )}

        {error && (
          <EmptyState title={t(`${NS}.load_failed`)} body={error} />
        )}

        {loading && !data ? (
          <SkeletonTable rows={8} />
        ) : (
          <div className="overflow-x-auto rounded-2xl border border-[var(--border-default)]">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[var(--border-default)] text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
                  <th className="px-3 py-2">{t(`${NS}.col_status`)}</th>
                  <th className="px-3 py-2">{t(`${NS}.col_provider`)}</th>
                  <th className="px-3 py-2">{t(`${NS}.col_env`)}</th>
                  <th className="px-3 py-2">{t(`${NS}.col_fingerprint`)}</th>
                  <th className="px-3 py-2">{t(`${NS}.col_model`)}</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => (
                  <tr key={`${r.kind}-${r.id}`} className="border-b border-[var(--border-default)]/60 hover:bg-[var(--row-hover-bg)]">
                    <td className="px-3 py-2">
                      {r.configured ? (
                        <span className="inline-flex items-center gap-1 text-emerald-300 text-[11px] font-mono">
                          <CheckCircle2 className="w-3.5 h-3.5" /> {t(`${NS}.ready`)}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-amber-300 text-[11px] font-mono">
                          <XCircle className="w-3.5 h-3.5" /> {t(`${NS}.missing`)}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]">
                      <span className="text-[var(--text-muted)]">{r.kind}</span>
                      {' · '}
                      {r.label}
                    </td>
                    <td className="px-3 py-2 text-[11px] font-mono text-cyan-200 inline-flex items-center gap-1">
                      <KeyRound className="w-3 h-3" />
                      {r.key_env}
                    </td>
                    <td className="px-3 py-2 text-[11px] font-mono text-[var(--text-tertiary)]">{r.fingerprint || '—'}</td>
                    <td className="px-3 py-2 text-[11px] font-mono text-[var(--text-tertiary)]">{r.model || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <EmptyState title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
            )}
          </div>
        )}
      </div>
    </PageShell>
  )
}
