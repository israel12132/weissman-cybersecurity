/**
 * Finding Suppressions — false-positive registry / noise management.
 *
 * Wired to the live GET /api/intel/suppressions endpoint (the
 * `finding_suppressions` table): each row silences a finding signature for a
 * target glob, with a reason, hit counter, and optional expiry. Operators can
 * revoke a suppression via the live DELETE /api/intel/suppressions/:id.
 * Route: /suppressions
 */
import React, { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { EyeOff, Search, Trash2 } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import CopyButton from '../components/ui/CopyButton'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useToast } from '../components/ui/Toaster'
import { usePermissions } from '../context/AuthContext'
import { confirmDialog } from '../utils/confirmDialog'
import { apiFetch } from '../lib/apiBase'

const NS = 'pages.findingSuppressions'
const columnHelper = createColumnHelper()

/** A suppression is expired when it has an expiry in the past. */
function isExpired(s) {
  return s.expires_at != null && new Date(s.expires_at).getTime() < Date.now()
}
/** …expiring soon = active with an expiry inside the next 7 days. */
function isExpiringSoon(s) {
  if (s.expires_at == null) return false
  const ms = new Date(s.expires_at).getTime() - Date.now()
  return ms > 0 && ms <= 7 * 86_400_000
}

function suppressionsCsv(rows) {
  const header = ['engine', 'signature_hash', 'target_glob', 'reason', 'hit_count', 'created_at', 'expires_at']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...rows.map((r) =>
      [r.engine, r.signature_hash, r.target_glob, r.reason, r.hit_count, r.created_at, r.expires_at].map(esc).join(','),
    ),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `weissman-suppressions-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function FindingSuppressions() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { hasRole } = usePermissions()
  const canManage = hasRole('operator')

  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all') // all | active | expired
  const [deletingId, setDeletingId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const r = await apiFetch('/api/intel/suppressions')
      const d = await r.json().catch(() => ({}))
      if (!r.ok || d.ok === false) throw new Error(d.detail || `HTTP ${r.status}`)
      setRows(Array.isArray(d.suppressions) ? d.suppressions : [])
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const handleDelete = useCallback(
    async (s) => {
      const ok = await confirmDialog({
        title: t(`${NS}.delete_title`),
        message: t(`${NS}.delete_confirm`, { engine: s.engine, sig: (s.signature_hash || '').slice(0, 12) }),
        confirmLabel: t(`${NS}.delete_confirm_btn`),
        cancelLabel: t(`${NS}.cancel`),
        variant: 'danger',
      })
      if (!ok) return
      setDeletingId(s.id)
      try {
        const r = await apiFetch(`/api/intel/suppressions/${encodeURIComponent(s.id)}`, { method: 'DELETE' })
        const d = await r.json().catch(() => ({}))
        if (!r.ok || d.ok === false) throw new Error(d.detail || `HTTP ${r.status}`)
        setRows((prev) => prev.filter((x) => x.id !== s.id))
        toast.success(t(`${NS}.delete_ok`))
      } catch (e) {
        toast.error(e.message || t(`${NS}.delete_failed`))
      } finally {
        setDeletingId(null)
      }
    },
    [t, toast],
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return rows.filter((s) => {
      if (statusFilter === 'expired' && !isExpired(s)) return false
      if (statusFilter === 'active' && isExpired(s)) return false
      if (!q) return true
      return `${s.engine} ${s.signature_hash} ${s.target_glob} ${s.reason}`.toLowerCase().includes(q)
    })
  }, [rows, search, statusFilter])

  const stats = useMemo(() => {
    let active = 0
    let hits = 0
    let expiringSoon = 0
    for (const s of rows) {
      if (!isExpired(s)) active += 1
      hits += Number(s.hit_count) || 0
      if (isExpiringSoon(s)) expiringSoon += 1
    }
    return { total: rows.length, active, hits, expiringSoon }
  }, [rows])

  const columns = useMemo(
    () => [
      columnHelper.accessor((s) => s.engine || '', {
        id: 'engine',
        header: t(`${NS}.col_engine`),
        cell: (ctx) => (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/25 bg-cyan-500/5 text-cyan-300/85">
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((s) => s.signature_hash || '', {
        id: 'signature_hash',
        header: t(`${NS}.col_signature`),
        cell: (ctx) => (
          <span className="flex items-center gap-1.5 min-w-0">
            <code className="text-[12px] text-[var(--text-tertiary)] font-mono truncate max-w-[10rem]" title={ctx.getValue()}>
              {ctx.getValue() ? `${ctx.getValue().slice(0, 16)}…` : '—'}
            </code>
            {ctx.getValue() && <CopyButton value={ctx.getValue()} />}
          </span>
        ),
      }),
      columnHelper.accessor((s) => s.target_glob || '', {
        id: 'target_glob',
        header: t(`${NS}.col_target`),
        cell: (ctx) => (
          <code className="text-[12px] text-[var(--text-secondary)] font-mono truncate max-w-[16rem] block" title={ctx.getValue()}>
            {ctx.getValue() || t(`${NS}.any_target`)}
          </code>
        ),
      }),
      columnHelper.accessor((s) => s.reason || '', {
        id: 'reason',
        header: t(`${NS}.col_reason`),
        enableSorting: false,
        cell: (ctx) => (
          <span className="text-[var(--text-tertiary)] text-[12px] block max-w-[20rem] truncate" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((s) => Number(s.hit_count) || 0, {
        id: 'hit_count',
        header: t(`${NS}.col_hits`),
        cell: (ctx) => <span className="tabular-nums text-[var(--text-secondary)] text-[12px]">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor((s) => (isExpired(s) ? 2 : isExpiringSoon(s) ? 1 : 0), {
        id: 'status',
        header: t(`${NS}.col_status`),
        cell: (ctx) => {
          const s = ctx.row.original
          const expired = isExpired(s)
          const soon = isExpiringSoon(s)
          const c = expired ? '#94a3b8' : soon ? '#facc15' : '#4ade80'
          const label = expired ? t(`${NS}.expired`) : soon ? t(`${NS}.expiring_soon`) : t(`${NS}.active`)
          return (
            <span className="flex flex-col gap-0.5">
              <span
                className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-wider w-fit"
                style={{ color: c, borderColor: `${c}40`, background: `${c}12` }}
              >
                {label}
              </span>
              {s.expires_at && (
                <span className="text-[10px] font-mono text-[var(--text-muted)] whitespace-nowrap">
                  {new Date(s.expires_at).toLocaleDateString()}
                </span>
              )}
            </span>
          )
        },
      }),
      ...(canManage
        ? [
            columnHelper.display({
              id: 'actions',
              header: '',
              enableSorting: false,
              cell: (ctx) => {
                const s = ctx.row.original
                return (
                  <button
                    type="button"
                    onClick={() => handleDelete(s)}
                    disabled={deletingId === s.id}
                    aria-label={t(`${NS}.delete_aria`)}
                    className="p-1.5 rounded-md text-rose-400/70 hover:text-rose-300 hover:bg-rose-500/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )
              },
            }),
          ]
        : []),
    ],
    [t, canManage, handleDelete, deletingId],
  )

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#94a3b8"
      icon={<EyeOff className="w-5 h-5" />}
      actions={
        <ShellScanActions
          onRefresh={load}
          onExport={() => suppressionsCsv(filtered)}
          refreshLoading={loading}
          exportDisabled={!filtered.length}
        />
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading && <SkeletonWidgetGrid count={4} />}

        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && !error && (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_total`)} value={stats.total} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_active`)} value={stats.active} accent="#4ade80" />
              <ExecutiveWidget label={t(`${NS}.kpi_hits`)} value={stats.hits} accent="#a78bfa" />
              <ExecutiveWidget label={t(`${NS}.kpi_expiring`)} value={stats.expiringSoon} accent="#facc15" />
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[220px] max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
                <input
                  type="search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder={t(`${NS}.search_placeholder`)}
                  className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
                />
              </div>
              <div className="flex items-center gap-1 shrink-0" role="group" aria-label={t(`${NS}.filter_status`)}>
                {['all', 'active', 'expired'].map((f) => (
                  <button
                    key={f}
                    type="button"
                    onClick={() => setStatusFilter(f)}
                    aria-pressed={statusFilter === f}
                    className={[
                      'px-2.5 py-1.5 rounded-lg text-[10px] font-mono uppercase tracking-wider border transition-colors',
                      statusFilter === f
                        ? 'bg-cyan-500/15 text-cyan-200 border-cyan-500/30'
                        : 'text-[var(--text-muted)] border-[var(--border-default)] hover:text-[var(--text-secondary)]',
                    ].join(' ')}
                  >
                    {t(`${NS}.filter_${f}`)}
                  </button>
                ))}
              </div>
            </div>

            {!canManage && (
              <div className="text-[11px] font-mono text-[var(--text-muted)] flex items-center gap-2">
                <EyeOff className="w-3.5 h-3.5" aria-hidden />
                {t(`${NS}.readonly_hint`)}
              </div>
            )}

            {rows.length === 0 ? (
              <EmptyState icon="🙈" title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
            ) : filtered.length === 0 ? (
              <EmptyState icon="🔍" title={t(`${NS}.no_match_title`)} body={t(`${NS}.no_match_body`)} />
            ) : (
              <DataTable
                id="finding-suppressions-table"
                columns={columns}
                data={filtered}
                animateRows={false}
                getRowId={(s) => s.id}
              />
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
