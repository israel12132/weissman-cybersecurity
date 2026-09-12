/**
 * Dominion Board Pack — CISO/client theater.
 *
 * Live JSON from GET /api/clients/:id/dominion-pack (findings + FAIR + attack paths +
 * crypto proof). Downloads: real PDF and real XLSX (not CSV labeled Excel).
 * Route: /dominion
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { Crown, FileSpreadsheet, FileText, ShieldAlert } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { apiUrl } from '../lib/apiBase'
import { fmtUsd } from '../lib/riskFormat'
import Button from '../components/ui/Button'

const NS = 'pages.dominionBoardPack'
const columnHelper = createColumnHelper()

const LEAK_SOURCES = new Set([
  'leak_hunter',
  'darkweb_intel',
  'dark_web_monitor',
  'typosquatting_monitor',
  'dominion_fusion',
  'public_leak_osint',
])

export function isLeakFinding(f) {
  return LEAK_SOURCES.has(String(f?.source || f.type || '').toLowerCase())
}

export function filterPackFindings(findings, search) {
  const q = String(search || '').trim().toLowerCase()
  const rows = Array.isArray(findings) ? findings : []
  if (!q) return rows
  return rows.filter((f) => {
    const hay = `${f.title || ''} ${f.severity || ''} ${f.source || ''} ${f.status || ''}`.toLowerCase()
    return hay.includes(q)
  })
}

export default function DominionBoardPack() {
  const { t } = useTranslation()
  const { clients, selectedClientId, setSelectedClientId } = useClient()
  const [pack, setPack] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    if (selectedClientId == null) {
      setPack(null)
      setError('')
      return
    }
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch(`/api/clients/${selectedClientId}/dominion-pack`)
      setPack(d && d.ok !== false ? d : null)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
      setPack(null)
    } finally {
      setLoading(false)
    }
  }, [selectedClientId, t])

  useEffect(() => {
    load()
  }, [load])

  const findings = useMemo(() => filterPackFindings(pack?.findings, search), [pack, search])
  const kpis = pack?.kpis || {}
  const financial = pack?.financial || null
  const paths = pack?.attack_paths || null

  const columns = useMemo(
    () => [
      columnHelper.accessor('severity', { header: t(`${NS}.col_severity`) }),
      columnHelper.accessor('title', { header: t(`${NS}.col_title`) }),
      columnHelper.accessor('source', { header: t(`${NS}.col_source`) }),
      columnHelper.accessor('status', { header: t(`${NS}.col_status`) }),
      columnHelper.accessor('kev_listed', {
        header: t(`${NS}.col_kev`),
        cell: (ctx) => (ctx.getValue() ? t(`${NS}.yes`) : '—'),
      }),
      columnHelper.accessor('has_proof', {
        header: t(`${NS}.col_proof`),
        cell: (ctx) => (ctx.getValue() ? t(`${NS}.yes`) : '—'),
      }),
    ],
    [t],
  )

  const gradeAccent = (pack?.grade || '').startsWith('P0')
    ? '#ef4444'
    : (pack?.grade || '').startsWith('P1')
      ? '#f59e0b'
      : (pack?.grade || '').includes('NO LEDGER')
        ? '#64748b'
        : '#22d3ee'

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor={gradeAccent}
      icon={Crown}
      engineId="dominion_fusion"
      actions={
        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value ? Number(e.target.value) : null)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-amber-500/40"
            aria-label={t(`${NS}.select_client`)}
          >
            <option value="">{t(`${NS}.select_client`)}</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name || c.domain || `#${c.id}`}
              </option>
            ))}
          </select>
          {selectedClientId != null && (
            <>
              <a
                href={apiUrl(`/api/clients/${selectedClientId}/report/pdf`)}
                download
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/40 text-cyan-200 text-xs font-medium hover:bg-cyan-500/10"
              >
                <FileText className="w-3.5 h-3.5" />
                {t(`${NS}.download_pdf`)}
              </a>
              <a
                href={apiUrl(`/api/clients/${selectedClientId}/report/xlsx`)}
                download
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-500/40 text-emerald-200 text-xs font-medium hover:bg-emerald-500/10"
              >
                <FileSpreadsheet className="w-3.5 h-3.5" />
                {t(`${NS}.download_xlsx`)}
              </a>
            </>
          )}
          <ShellScanActions
            onRefresh={load}
            onExport={() => {
              if (selectedClientId == null) return
              const a = document.createElement('a')
              a.href = apiUrl(`/api/clients/${selectedClientId}/report/xlsx`)
              a.download = ''
              a.click()
            }}
            refreshLoading={loading}
            exportDisabled={selectedClientId == null}
            exportLabel={t(`${NS}.download_xlsx`)}
          />
        </div>
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {selectedClientId == null && (
          <EmptyState icon="building" title={t(`${NS}.pick_client_title`)} body={t(`${NS}.pick_client_body`)} />
        )}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {selectedClientId != null && loading && <SkeletonWidgetGrid count={4} />}

        {selectedClientId != null && !loading && pack && (
          <>
            <div
              className="rounded-2xl border p-5"
              style={{
                borderColor: `${gradeAccent}55`,
                boxShadow: `0 0 40px ${gradeAccent}22`,
              }}
            >
              <div className="flex items-start gap-3 flex-wrap">
                <ShieldAlert className="w-5 h-5 mt-0.5" style={{ color: gradeAccent }} />
                <div className="min-w-0">
                  <p className="text-xs font-mono uppercase tracking-[0.16em]" style={{ color: gradeAccent }}>
                    {pack.grade}
                  </p>
                  <p className="text-sm text-[var(--text-secondary)] mt-1">{pack.grade_reason}</p>
                  <p className="text-[10px] font-mono text-[var(--text-muted)] mt-2 break-all">
                    SHA-256 {pack.pack_sha256}
                  </p>
                  {pack.generated_at && (
                    <p className="text-[10px] font-mono text-[var(--text-muted)] mt-1">
                      {t(`${NS}.generated_at`, { time: pack.generated_at })}
                    </p>
                  )}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_total`)} value={kpis.total ?? 0} hint={t(`${NS}.kpi_total_hint`)} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_critical`)} value={kpis.critical ?? 0} hint={t(`${NS}.kpi_critical_hint`)} accent="#ef4444" />
              <ExecutiveWidget label={t(`${NS}.kpi_kev`)} value={kpis.kev ?? 0} hint={t(`${NS}.kpi_kev_hint`)} accent="#f97316" />
              <ExecutiveWidget label={t(`${NS}.kpi_leak`)} value={kpis.leak ?? 0} hint={t(`${NS}.kpi_leak_hint`)} accent="#a78bfa" />
              <ExecutiveWidget
                label={t(`${NS}.kpi_ale`)}
                value={financial ? fmtUsd(financial.ale_annualised_usd) : '—'}
                hint={t(`${NS}.kpi_ale_hint`)}
                accent="#f59e0b"
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_paths`)}
                value={paths?.path_count ?? paths?.paths?.length ?? '—'}
                hint={t(`${NS}.kpi_paths_hint`)}
                accent="#38bdf8"
              />
              <ExecutiveWidget label={t(`${NS}.kpi_proof`)} value={kpis.with_proof ?? 0} hint={t(`${NS}.kpi_proof_hint`)} accent="#34d399" />
              <ExecutiveWidget label={t(`${NS}.kpi_engines`)} value={kpis.engines ?? 0} hint={t(`${NS}.kpi_engines_hint`)} accent="#818cf8" />
            </div>

            <div className="flex flex-wrap gap-3 text-xs">
              <Link className="text-cyan-300 hover:underline" to={`/report/${selectedClientId}`}>{t(`${NS}.open_report`)}</Link>
              <Link className="text-cyan-300 hover:underline" to="/financial-risk">{t(`${NS}.open_financial`)}</Link>
              <Link className="text-cyan-300 hover:underline" to="/attack-paths">{t(`${NS}.open_paths`)}</Link>
              <Link className="text-cyan-300 hover:underline" to="/dark-web">{t(`${NS}.open_darkweb`)}</Link>
            </div>

            <div>
              <label className="sr-only" htmlFor="dominion-search">{t(`${NS}.search`)}</label>
              <input
                id="dominion-search"
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t(`${NS}.search`)}
                className="w-full max-w-md bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)]"
              />
            </div>

            {findings.length === 0 ? (
              <EmptyState icon="search" title={t(`${NS}.no_findings_title`)} body={t(`${NS}.no_findings_body`)} />
            ) : (
              <DataTable columns={columns} data={findings} />
            )}

            {pack.crypto_proof?.audit_root_hash && (
              <p className="text-[11px] font-mono text-[var(--text-muted)] break-all">
                {t(`${NS}.audit_hash`)} {pack.crypto_proof.audit_root_hash}
              </p>
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
