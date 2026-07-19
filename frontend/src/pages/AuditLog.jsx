import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import {
  Calendar,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  BadgeCheck,
  FileJson,
  Search,
  Shield,
  ShieldAlert,
  User,
} from 'lucide-react'
import { apiFetch } from '../utils/apiFetch'
import ShellScanActions from '../components/engine/ShellScanActions'
import DataTable from '../components/ui/DataTable'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'

const columnHelper = createColumnHelper()

const ACTION_PILLS = [
  { key: '', labelKey: 'audit.all_actions' },
  { key: 'login', labelKey: 'audit.action_login' },
  { key: 'scan', labelKey: 'audit.action_scan' },
  { key: 'client', labelKey: 'audit.action_client' },
  { key: 'mfa', labelKey: 'audit.action_mfa' },
  { key: 'denied', labelKey: 'audit.action_security' },
  { key: 'deleted', labelKey: 'audit.action_delete' },
  { key: 'backup', labelKey: 'audit.action_config' },
]

const PAGE_SIZES = [25, 50, 100]

function fmtTime(iso, locale) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString(locale, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return String(iso)
  }
}

function fmtDateInput(d) {
  const y = d.getFullYear()
  const m = String(d.getMonth() + 1).padStart(2, '0')
  const day = String(d.getDate()).padStart(2, '0')
  return `${y}-${m}-${day}`
}

function parseDetails(raw) {
  if (!raw) return { text: '', json: null }
  const trimmed = raw.trim()
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      return { text: raw, json: JSON.parse(trimmed) }
    } catch {
      return { text: raw, json: null }
    }
  }
  return { text: raw, json: null }
}

function extractTarget(entry) {
  const { text, json } = parseDetails(entry.details)
  if (json) {
    const keys = ['target', 'client_id', 'client', 'path', 'resource', 'email', 'host', 'domain']
    for (const k of keys) {
      if (json[k] != null && json[k] !== '') return String(json[k])
    }
  }
  const m = text.match(/(?:client|target|path|host)=([^\s,;]+)/i)
  if (m) return m[1]
  if (text.length > 80) return `${text.slice(0, 77)}…`
  return text || '—'
}

function ActionBadge({ action }) {
  const a = (action || '').toLowerCase()
  let color = 'border-[var(--border-strong)] text-[var(--text-secondary)] bg-[var(--row-hover-bg)]'
  if (a.includes('login') || a.includes('mfa')) color = 'border-cyan-500/40 text-cyan-200 bg-cyan-500/10'
  if (a.includes('denied') || a.includes('reject') || a.includes('failed')) color = 'border-rose-500/40 text-rose-200 bg-rose-500/10'
  if (a.includes('created') || a.includes('updated')) color = 'border-emerald-500/40 text-emerald-200 bg-emerald-500/10'
  if (a.includes('deleted') || a.includes('removed')) color = 'border-amber-500/40 text-amber-200 bg-amber-500/10'
  if (a.includes('scan')) color = 'border-violet-500/40 text-violet-200 bg-violet-500/10'
  return (
    <span className={`inline-flex text-[10px] font-mono px-2.5 py-1 rounded-full border ${color}`}>
      {action || '—'}
    </span>
  )
}

function exportCsv(rows) {
  const header = ['id', 'created_at', 'action', 'actor', 'target', 'details', 'client_ip']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...rows.map((e) =>
      [
        e.id,
        e.created_at,
        e.action,
        e.actor_email || e.user_id,
        extractTarget(e),
        e.details,
        e.client_ip,
      ].map(esc).join(',')
    ),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `weissman-audit-log-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function AuditLog() {
  const { t, i18n } = useTranslation()
  const { toast } = useToast()
  const [entries, setEntries] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [exportingFull, setExportingFull] = useState(false)
  const [verifyHash, setVerifyHash] = useState('')
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null) // { verified, run_id, created_at } | { verified:false }
  const [actionFilter, setActionFilter] = useState('')
  const [actor, setActor] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [offset, setOffset] = useState(0)
  const [pageSize, setPageSize] = useState(50)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    const qs = new URLSearchParams({ limit: String(pageSize), offset: String(offset) })
    if (actionFilter) qs.set('action', actionFilter)
    if (actor.trim()) qs.set('actor', actor.trim())
    try {
      const d = await apiFetch(`/api/audit-logs?${qs.toString()}`)
      const list = Array.isArray(d) ? d : Array.isArray(d?.entries) ? d.entries : []
      setEntries(list)
      setTotal(Number(d?.total ?? list.length))
    } catch (e) {
      setError(e.message || t('audit.load_error'))
    } finally {
      setLoading(false)
    }
  }, [actionFilter, actor, offset, pageSize, t])

  useEffect(() => { load() }, [load])

  // Full tamper-evident export — the whole audit chain (not just this page),
  // via GET /api/audit/export. The packet carries the SHA-256 chain-integrity
  // flag so an auditor can verify no entry was altered or removed.
  const exportFull = useCallback(async () => {
    setExportingFull(true)
    try {
      const d = await apiFetch('/api/audit/export?format=json&limit=50000')
      if (d.ok === false) throw new Error(d.detail || t('audit.export_full_failed'))
      const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `weissman-audit-export-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
      toast[d.chain_intact ? 'success' : 'warning'](
        d.chain_intact
          ? t('audit.export_full_ok', { count: d.total ?? (d.entries?.length ?? 0) })
          : t('audit.export_full_broken'),
      )
    } catch (e) {
      toast.error(e.message || t('audit.export_full_failed'))
    } finally {
      setExportingFull(false)
    }
  }, [t, toast])

  // Tamper-evidence verifier — resolve a report's audit_root_hash against the
  // live ledger via GET /api/verify-audit/:hash. Proves a report artifact
  // corresponds to a real, unaltered run (or exposes a forgery).
  const verify = useCallback(async () => {
    const h = verifyHash.trim()
    if (!h) return
    setVerifying(true)
    setVerifyResult(null)
    try {
      const d = await apiFetch(`/api/verify-audit/${encodeURIComponent(h)}`)
      if (d.verified) {
        setVerifyResult({ verified: true, ...d })
      } else {
        setVerifyResult({ verified: false, error: d.error || t('audit.verify_error') })
      }
    } catch (e) {
      setVerifyResult({ verified: false, error: e.message || t('audit.verify_error') })
    } finally {
      setVerifying(false)
    }
  }, [verifyHash, t])

  const filteredEntries = useMemo(() => {
    if (!dateFrom && !dateTo) return entries
    const fromMs = dateFrom ? new Date(`${dateFrom}T00:00:00`).getTime() : null
    const toMs = dateTo ? new Date(`${dateTo}T23:59:59.999`).getTime() : null
    return entries.filter((e) => {
      if (!e.created_at) return true
      const ts = new Date(e.created_at).getTime()
      if (fromMs != null && ts < fromMs) return false
      if (toMs != null && ts > toMs) return false
      return true
    })
  }, [entries, dateFrom, dateTo])

  const currentPage = Math.floor(offset / pageSize) + 1
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const rangeStart = total === 0 ? 0 : offset + 1
  const rangeEnd = Math.min(offset + filteredEntries.length, total)

  const setQuickRange = (days) => {
    const end = new Date()
    const start = new Date()
    start.setDate(start.getDate() - days)
    setDateFrom(fmtDateInput(start))
    setDateTo(fmtDateInput(end))
    setOffset(0)
  }

  const clearFilters = () => {
    setActionFilter('')
    setActor('')
    setDateFrom('')
    setDateTo('')
    setOffset(0)
  }

  const hasFilters = actionFilter || actor.trim() || dateFrom || dateTo

  const pageKpi = useMemo(() => {
    const denied = filteredEntries.filter((e) => {
      const a = (e.action || '').toLowerCase()
      return a.includes('denied') || a.includes('reject') || a.includes('failed')
    }).length
    return { shown: filteredEntries.length, denied }
  }, [filteredEntries])

  // Audit rows stay in the server's chronological order — column sorting is left
  // off so a single fetched page can't be reordered into a misleading sequence.
  const columns = useMemo(() => [
    columnHelper.accessor('created_at', {
      id: 'when',
      header: t('audit.col_when'),
      size: 176,
      enableSorting: false,
      cell: ({ getValue }) => (
        <span className="font-mono text-[var(--text-tertiary)] whitespace-nowrap text-[12px]">
          {fmtTime(getValue(), i18n.language)}
        </span>
      ),
    }),
    columnHelper.accessor('action', {
      id: 'action',
      header: t('audit.col_action'),
      size: 160,
      enableSorting: false,
      cell: ({ getValue }) => <ActionBadge action={getValue()} />,
    }),
    columnHelper.accessor((e) => e.actor_email || `user#${e.user_id || '—'}`, {
      id: 'actor',
      header: t('audit.col_actor'),
      size: 208,
      enableSorting: false,
      cell: ({ row, getValue }) => (
        <div className="flex items-center gap-2 min-w-0">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-cyan-500/10 text-[10px] text-cyan-300">
            {(row.original.actor_email || '?')[0]?.toUpperCase()}
          </span>
          <span className="text-cyan-300/90 truncate max-w-[14rem] text-[12px]" title={row.original.actor_email}>
            {getValue()}
          </span>
        </div>
      ),
    }),
    columnHelper.accessor((e) => extractTarget(e), {
      id: 'target',
      header: t('audit.col_target'),
      enableSorting: false,
      cell: ({ getValue }) => (
        <span className="text-[var(--text-tertiary)] font-mono truncate block max-w-[20rem] text-[12px]" title={getValue()}>
          {getValue()}
        </span>
      ),
    }),
    columnHelper.accessor('client_ip', {
      id: 'ip',
      header: t('audit.col_ip'),
      size: 128,
      enableSorting: false,
      cell: ({ getValue }) => <span className="font-mono text-[var(--text-muted)] text-[12px]">{getValue() || '—'}</span>,
    }),
  ], [t, i18n.language])

  const renderAuditDetail = useCallback((entry) => {
    const { text, json } = parseDetails(entry.details)
    return (
      <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-3)] p-4">
        <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
          {t('audit.detail_payload')}
        </div>
        <pre className="text-[11px] font-mono text-emerald-200/90 whitespace-pre-wrap break-words max-h-64 overflow-auto leading-relaxed">
          {json ? JSON.stringify(json, null, 2) : (text || '—')}
        </pre>
      </div>
    )
  }, [t])

  return (
    <div
      className="min-h-[100dvh] text-[var(--text-secondary)] p-4 sm:p-6"
      style={{ background: 'var(--shell-bg)' }}
    >
      <header className="max-w-7xl mx-auto mb-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-500/25 bg-cyan-500/10">
              <Shield className="h-5 w-5 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">{t('audit.title')}</h1>
              <p className="text-sm text-[var(--text-tertiary)] mt-1 max-w-2xl">{t('audit.subtitle')}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="unstyled"
              type="button"
              onClick={exportFull}
              disabled={exportingFull}
              className="flex items-center gap-2 px-3 py-2 rounded-lg border border-violet-500/40 bg-violet-500/10 text-violet-200 text-xs font-mono hover:bg-violet-500/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              title={t('audit.export_full_hint')}
            >
              <FileJson className={`w-4 h-4 ${exportingFull ? 'animate-pulse' : ''}`} />
              {exportingFull ? t('audit.export_full_running') : t('audit.export_full')}
            </Button>
            <ShellScanActions
              onRefresh={load}
              onExport={() => exportCsv(filteredEntries)}
              refreshLoading={loading}
              exportDisabled={filteredEntries.length === 0}
            />
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto mb-4 space-y-4">
        <EvidenceNotice>{t('audit.evidence_notice')}</EvidenceNotice>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <ExecutiveWidget
            label={t('audit.kpi_shown')}
            value={loading ? '—' : pageKpi.shown.toLocaleString()}
            accent="#22d3ee"
          />
          <ExecutiveWidget
            label={t('audit.kpi_denied')}
            value={loading ? '—' : pageKpi.denied.toLocaleString()}
            accent="#f87171"
          />
          <ExecutiveWidget
            label={t('audit.kpi_total')}
            value={loading ? '—' : total.toLocaleString()}
            accent="#a78bfa"
            className="col-span-2 lg:col-span-1"
          />
        </div>

        {/* Tamper-evidence verifier — resolve a report's audit_root_hash */}
        <div className="rounded-2xl border border-emerald-500/20 bg-emerald-950/10 p-4">
          <div className="flex items-center gap-2 mb-2">
            <BadgeCheck className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">{t('audit.verify_title')}</h3>
          </div>
          <p className="text-xs text-[var(--text-tertiary)] mb-3 max-w-2xl">{t('audit.verify_subtitle')}</p>
          <form
            className="flex flex-col sm:flex-row gap-2"
            onSubmit={(e) => { e.preventDefault(); verify() }}
          >
            <input
              type="text"
              value={verifyHash}
              onChange={(e) => setVerifyHash(e.target.value)}
              placeholder={t('audit.verify_placeholder')}
              spellCheck={false}
              className="flex-1 min-w-0 bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl px-3 py-2.5 text-sm font-mono text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-emerald-500/40"
            />
            <Button variant="unstyled"
              type="submit"
              disabled={verifying || !verifyHash.trim()}
              className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-500/90 text-black text-sm font-semibold hover:bg-emerald-500 transition-colors disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
            >
              <BadgeCheck className={`w-4 h-4 ${verifying ? 'animate-pulse' : ''}`} />
              {verifying ? t('audit.verify_running') : t('audit.verify_btn')}
            </Button>
          </form>

          {verifyResult && (
            verifyResult.verified ? (
              <div className="mt-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3">
                <div className="flex items-center gap-2 text-emerald-300 text-sm font-semibold">
                  <BadgeCheck className="w-4 h-4" />
                  {t('audit.verify_ok')}
                </div>
                <div className="mt-1.5 text-[11px] font-mono text-emerald-200/80 flex flex-wrap gap-x-4 gap-y-1">
                  <span>{t('audit.verify_run', { id: verifyResult.run_id })}</span>
                  {verifyResult.created_at && (
                    <span>{t('audit.verify_created', { time: fmtTime(verifyResult.created_at, i18n.language) })}</span>
                  )}
                </div>
              </div>
            ) : (
              <div className="mt-3 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3">
                <div className="flex items-center gap-2 text-rose-300 text-sm font-semibold">
                  <ShieldAlert className="w-4 h-4" />
                  {t('audit.verify_fail')}
                </div>
                <div className="mt-1 text-[11px] font-mono text-rose-200/70">{t('audit.verify_fail_hint')}</div>
              </div>
            )
          )}
        </div>
      </div>

      <section className="max-w-7xl mx-auto rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] backdrop-blur-md p-4 sm:p-5 mb-4 space-y-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <span className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t('audit.filters')}</span>
          {hasFilters && (
            <Button variant="unstyled"
              type="button"
              onClick={clearFilters}
              className="text-[11px] font-mono text-cyan-400/80 hover:text-cyan-300"
            >
              {t('audit.clear_filters')}
            </Button>
          )}
        </div>

        <div className="flex flex-wrap gap-2">
          {ACTION_PILLS.map((pill) => {
            const active = actionFilter === pill.key
            return (
              <Button variant="unstyled"
                key={pill.key || 'all'}
                type="button"
                onClick={() => { setActionFilter(pill.key); setOffset(0) }}
                className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-all ${
                  active
                    ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/40 shadow-[0_0_20px_rgba(34,211,238,0.12)]'
                    : 'bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] border-[var(--border-default)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                }`}
              >
                {t(pill.labelKey)}
              </Button>
            )
          })}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-[1fr_1fr_1fr_auto] gap-3">
          <label className="relative block">
            <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--text-disabled)] pointer-events-none" />
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => { setDateFrom(e.target.value); setOffset(0) }}
              className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-cyan-500/40"
              aria-label={t('audit.date_from')}
            />
          </label>
          <label className="relative block">
            <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--text-disabled)] pointer-events-none" />
            <input
              type="date"
              value={dateTo}
              onChange={(e) => { setDateTo(e.target.value); setOffset(0) }}
              className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-cyan-500/40"
              aria-label={t('audit.date_to')}
            />
          </label>
          <label className="relative block">
            <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--text-disabled)] pointer-events-none" />
            <input
              type="search"
              aria-label={t('audit.actor_placeholder')}
              placeholder={t('audit.actor_placeholder')}
              value={actor}
              onChange={(e) => { setActor(e.target.value); setOffset(0) }}
              className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2.5 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
            />
          </label>
          <div className="flex gap-2">
            {[
              { days: 1, label: t('audit.range_24h') },
              { days: 7, label: t('audit.range_7d') },
              { days: 30, label: t('audit.range_30d') },
            ].map((r) => (
              <Button variant="unstyled"
                key={r.days}
                type="button"
                onClick={() => setQuickRange(r.days)}
                className="px-3 py-2.5 rounded-xl text-xs font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] whitespace-nowrap"
              >
                {r.label}
              </Button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2 text-[11px] font-mono text-[var(--text-muted)] pt-1 border-t border-[var(--border-subtle)]">
          <Search className="h-3.5 w-3.5" />
          <span>
            {t('audit.summary', {
              shown: filteredEntries.length,
              total,
              page: currentPage,
              pages: totalPages,
            })}
          </span>
        </div>
      </section>

      <section className="max-w-7xl mx-auto space-y-3">
        {error && (
          <div className="text-sm text-rose-300 font-mono">{error}</div>
        )}
        <DataTable
          columns={columns}
          data={filteredEntries}
          loading={loading}
          hidePagination
          densityToggle
          animateRows={false}
          getRowId={(e) => e.id}
          renderSubRow={renderAuditDetail}
          getRowCanExpand={(row) => Boolean(row.original.details)}
          expandLabel={t('audit.expand_payload')}
          collapseLabel={t('audit.collapse_payload')}
          emptyState={{ icon: '📋', title: t('audit.empty_title'), body: t('audit.empty_body') }}
        />

        {total > 0 && (
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 px-4 py-4 rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)]">
            <div className="flex items-center gap-3 text-[11px] font-mono text-[var(--text-muted)]">
              <span>{t('audit.rows_per_page')}</span>
              <select
                value={pageSize}
                onChange={(e) => { setPageSize(Number(e.target.value)); setOffset(0) }}
                className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1 text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40"
              >
                {PAGE_SIZES.map((n) => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
              <span className="hidden sm:inline text-[var(--text-disabled)]">·</span>
              <span>{t('audit.page_range', { start: rangeStart, end: rangeEnd, total })}</span>
            </div>

            <div className="flex items-center gap-1">
              <Button variant="unstyled"
                type="button"
                disabled={offset <= 0}
                onClick={() => setOffset(0)}
                className="p-2 rounded-lg border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] disabled:opacity-25 transition-colors"
                aria-label={t('audit.first_page')}
              >
                <ChevronsLeft className="h-4 w-4" />
              </Button>
              <Button variant="unstyled"
                type="button"
                disabled={offset <= 0}
                onClick={() => setOffset((o) => Math.max(0, o - pageSize))}
                className="p-2 rounded-lg border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] disabled:opacity-25 transition-colors"
                aria-label={t('audit.prev_page')}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>

              <div className="flex items-center gap-1 px-2">
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let page
                  if (totalPages <= 5) page = i + 1
                  else if (currentPage <= 3) page = i + 1
                  else if (currentPage >= totalPages - 2) page = totalPages - 4 + i
                  else page = currentPage - 2 + i
                  return (
                    <Button variant="unstyled"
                      key={page}
                      type="button"
                      onClick={() => setOffset((page - 1) * pageSize)}
                      className={`min-w-[2rem] h-8 rounded-lg text-xs font-mono border transition-all ${
                        page === currentPage
                          ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/40'
                          : 'border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)]'
                      }`}
                    >
                      {page}
                    </Button>
                  )
                })}
              </div>

              <Button variant="unstyled"
                type="button"
                disabled={offset + pageSize >= total}
                onClick={() => setOffset((o) => o + pageSize)}
                className="p-2 rounded-lg border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] disabled:opacity-25 transition-colors"
                aria-label={t('audit.next_page')}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
              <Button variant="unstyled"
                type="button"
                disabled={offset + pageSize >= total}
                onClick={() => setOffset((totalPages - 1) * pageSize)}
                className="p-2 rounded-lg border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] disabled:opacity-25 transition-colors"
                aria-label={t('audit.last_page')}
              >
                <ChevronsRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </section>
    </div>
  )
}
