/**
 * Threat-Informed Board Pack — live CISO/board deliverable.
 *
 * Composes tenant findings + ATT&CK + CISA KEV + BOD 26-04 triage + FAIR $ +
 * attack paths + first-mover delta into PDF (Helvetica/EN) and true Excel (UTF-8).
 * Route: /board-pack  APIs: GET /api/clients/:id/board-pack[ /pdf | /xlsx ]
 *
 * @weissman-forensic-page
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { FileSpreadsheet, FileText, Search, ShieldAlert } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'

const NS = 'pages.boardPack'
const columnHelper = createColumnHelper()

function fmtUsd(n) {
  return `$${(Number(n) || 0).toLocaleString()}`
}

async function downloadBinary(path, toast, okKey, failKey, t) {
  const r = await apiFetch(path, { raw: true })
  const disposition = r.headers.get('content-disposition') || ''
  const match = disposition.match(/filename="?([^";\s]+)"?/)
  const filename = match?.[1] ?? path.split('/').pop()
  const blob = await r.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
  toast.success(t(okKey, { filename }))
}

export default function BoardPack() {
  const { t, i18n } = useTranslation()
  const { toast } = useToast()
  const { clients, selectedClientId, setSelectedClientId } = useClient()
  const [pack, setPack] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [busy, setBusy] = useState('')

  const lang = (i18n.language || 'en').toLowerCase().startsWith('he') ? 'he' : 'en'

  const load = useCallback(async () => {
    if (selectedClientId == null) return
    setLoading(true)
    setError('')
    try {
      const data = await apiFetch(
        `/api/clients/${encodeURIComponent(selectedClientId)}/board-pack?lang=${lang}`,
      )
      if (data?.ok === false) throw new Error(data.detail || data.error || 'load failed')
      setPack(data)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
      setPack(null)
    } finally {
      setLoading(false)
    }
  }, [selectedClientId, lang, t])

  useEffect(() => {
    setPack(null)
    if (selectedClientId != null) load()
  }, [selectedClientId, load])

  const kpis = pack?.kpis || {}
  const techniques = useMemo(
    () => (Array.isArray(pack?.top_techniques) ? pack.top_techniques : []),
    [pack],
  )
  const p0 = useMemo(
    () => (Array.isArray(pack?.p0_findings) ? pack.p0_findings : []),
    [pack],
  )

  const filteredTech = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return techniques
    return techniques.filter((r) =>
      `${r.technique} ${r.name || ''} ${r.tactic || ''}`.toLowerCase().includes(q),
    )
  }, [techniques, search])

  const columns = useMemo(
    () => [
      columnHelper.accessor((r) => r.technique || '', {
        id: 'technique',
        header: t(`${NS}.col_technique`),
        cell: (ctx) => (
          <span className="font-mono text-[12px] text-cyan-300">{ctx.getValue()}</span>
        ),
      }),
      columnHelper.accessor((r) => r.name || '', {
        id: 'name',
        header: t(`${NS}.col_name`),
      }),
      columnHelper.accessor((r) => r.tactic || '', {
        id: 'tactic',
        header: t(`${NS}.col_tactic`),
      }),
      columnHelper.accessor((r) => Number(r.count) || 0, {
        id: 'count',
        header: t(`${NS}.col_count`),
        cell: (ctx) => <span className="tabular-nums">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor((r) => Number(r.critical) || 0, {
        id: 'critical',
        header: t(`${NS}.col_critical`),
        cell: (ctx) => (
          <span className="tabular-nums text-rose-300">{ctx.getValue()}</span>
        ),
      }),
    ],
    [t],
  )

  const onDownload = async (kind) => {
    if (selectedClientId == null) return
    setBusy(kind)
    try {
      const path = `/api/clients/${encodeURIComponent(selectedClientId)}/board-pack/${kind}?lang=${lang}`
      await downloadBinary(
        path,
        toast,
        `${NS}.download_ok`,
        `${NS}.download_failed`,
        t,
      )
    } catch (e) {
      toast.error(t(`${NS}.download_failed`, { detail: e?.message || '' }))
    } finally {
      setBusy('')
    }
  }

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#22d3ee"
      icon={<ShieldAlert className="w-5 h-5" />}
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <ShellScanActions onRefresh={load} refreshLoading={loading} exportDisabled />
          <Button
            type="button"
            disabled={!selectedClientId || Boolean(busy)}
            onClick={() => onDownload('pdf')}
            className="inline-flex items-center gap-1.5"
          >
            <FileText className="w-4 h-4" />
            {busy === 'pdf' ? t(`${NS}.preparing`) : t(`${NS}.download_pdf`)}
          </Button>
          <Button
            type="button"
            disabled={!selectedClientId || Boolean(busy)}
            onClick={() => onDownload('xlsx')}
            className="inline-flex items-center gap-1.5"
          >
            <FileSpreadsheet className="w-4 h-4" />
            {busy === 'xlsx' ? t(`${NS}.preparing`) : t(`${NS}.download_xlsx`)}
          </Button>
        </div>
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        <div className="flex flex-wrap items-center gap-3">
          <label className="text-xs uppercase tracking-wider text-[var(--text-muted)]">
            {t(`${NS}.select_client`)}
          </label>
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value ? Number(e.target.value) : null)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl px-3 py-2 text-sm text-[var(--text-primary)]"
          >
            <option value="">{t(`${NS}.select_client`)}</option>
            {(clients || []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name || `client ${c.id}`}
              </option>
            ))}
          </select>
        </div>

        {selectedClientId == null && (
          <EmptyState icon="file" title={t(`${NS}.pick_client_title`)} body={t(`${NS}.pick_client_body`)} />
        )}

        {loading && <SkeletonWidgetGrid count={4} />}

        {error && (
          <div
            role="alert"
            className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono"
          >
            {error}
          </div>
        )}

        {!loading && !error && pack && (
          <>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_p0`)} value={kpis.bod_p0 ?? 0} accent="#fb7185" />
              <ExecutiveWidget label={t(`${NS}.kpi_kev`)} value={kpis.kev_listed ?? 0} accent="#f97316" />
              <ExecutiveWidget label={t(`${NS}.kpi_ale`)} value={fmtUsd(kpis.ale_usd)} accent="#22d3ee" />
              <ExecutiveWidget
                label={t(`${NS}.kpi_paths`)}
                value={kpis.attack_paths ?? 0}
                accent="#a78bfa"
              />
            </div>

            <p className="text-xs font-mono text-[var(--text-tertiary)]">
              {pack.fair_note} · {pack.paths_message} · {pack.first_mover_message}
            </p>

            {p0.length > 0 && (
              <div className="rounded-xl border border-rose-500/30 bg-rose-950/10 px-4 py-3">
                <div className="text-[11px] uppercase tracking-widest text-rose-300 font-semibold mb-2">
                  {t(`${NS}.p0_banner`)}
                </div>
                <ul className="space-y-1 text-sm">
                  {p0.map((f) => (
                    <li key={f.id} className="font-mono text-[12px] text-[var(--text-primary)]">
                      [{f.severity}] {f.title} {f.cve ? `· ${f.cve}` : ''}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="relative flex-1 min-w-[220px] max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                aria-label={t(`${NS}.search_placeholder`)}
                placeholder={t(`${NS}.search_placeholder`)}
                className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
              />
            </div>

            {filteredTech.length === 0 ? (
              <EmptyState icon="search-x" title={t(`${NS}.empty_ttp_title`)} body={t(`${NS}.empty_ttp_body`)} />
            ) : (
              <DataTable
                id="board-pack-ttp-table"
                columns={columns}
                data={filteredTech}
                animateRows={false}
                getRowId={(r) => r.technique}
              />
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
