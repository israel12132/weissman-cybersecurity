import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Calendar,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Search,
  Shield,
  User,
} from 'lucide-react'
import { apiFetch } from '../lib/apiBase'
import ShellScanActions from '../components/engine/ShellScanActions'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import { SkeletonTable } from '../components/ui/Skeleton'

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
  let color = 'border-[var(--border-strong)] text-[var(--text-secondary)] bg-white/5'
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
  const [entries, setEntries] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [actionFilter, setActionFilter] = useState('')
  const [actor, setActor] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [offset, setOffset] = useState(0)
  const [pageSize, setPageSize] = useState(50)
  const [expandedId, setExpandedId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    const qs = new URLSearchParams({ limit: String(pageSize), offset: String(offset) })
    if (actionFilter) qs.set('action', actionFilter)
    if (actor.trim()) qs.set('actor', actor.trim())
    try {
      const r = await apiFetch(`/api/audit-logs?${qs.toString()}`)
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
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

  return (
    <div
      className="min-h-[100dvh] text-slate-100 p-4 sm:p-6"
      style={{ background: 'radial-gradient(ellipse 100% 70% at 50% 0%, #0f172a 0%, #020617 60%, #000 100%)' }}
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
          <ShellScanActions
            onRefresh={load}
            onExport={() => exportCsv(filteredEntries)}
            refreshLoading={loading}
            exportDisabled={filteredEntries.length === 0}
          />
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
      </div>

      <section className="max-w-7xl mx-auto rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] backdrop-blur-md p-4 sm:p-5 mb-4 space-y-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <span className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t('audit.filters')}</span>
          {hasFilters && (
            <button
              type="button"
              onClick={clearFilters}
              className="text-[11px] font-mono text-cyan-400/80 hover:text-cyan-300"
            >
              {t('audit.clear_filters')}
            </button>
          )}
        </div>

        <div className="flex flex-wrap gap-2">
          {ACTION_PILLS.map((pill) => {
            const active = actionFilter === pill.key
            return (
              <button
                key={pill.key || 'all'}
                type="button"
                onClick={() => { setActionFilter(pill.key); setOffset(0) }}
                className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-all ${
                  active
                    ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/40 shadow-[0_0_20px_rgba(34,211,238,0.12)]'
                    : 'bg-white/5 text-[var(--text-tertiary)] border-[var(--border-default)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                }`}
              >
                {t(pill.labelKey)}
              </button>
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
              <button
                key={r.days}
                type="button"
                onClick={() => setQuickRange(r.days)}
                className="px-3 py-2.5 rounded-xl text-xs font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-white hover:border-[var(--border-strong)] whitespace-nowrap"
              >
                {r.label}
              </button>
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

      <section className="max-w-7xl mx-auto rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] backdrop-blur-md overflow-hidden">
        {error && (
          <div className="px-5 pt-4 text-sm text-rose-300 font-mono">{error}</div>
        )}
        {loading ? (
          <div className="p-5">
            <SkeletonTable rows={10} cols={5} />
          </div>
        ) : filteredEntries.length === 0 ? (
          <div className="p-8">
            <EmptyState
              icon="📋"
              title={t('audit.empty_title')}
              body={t('audit.empty_body')}
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] border-b border-[var(--border-default)] bg-white/[0.02]">
                  <th className="py-3 px-4 w-10" />
                  <th className="py-3 px-4 w-44">{t('audit.col_when')}</th>
                  <th className="py-3 px-4 w-40">{t('audit.col_action')}</th>
                  <th className="py-3 px-4 w-52">{t('audit.col_actor')}</th>
                  <th className="py-3 px-4">{t('audit.col_target')}</th>
                  <th className="py-3 px-4 w-32">{t('audit.col_ip')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredEntries.map((e) => {
                  const open = expandedId === e.id
                  const { text, json } = parseDetails(e.details)
                  return (
                    <React.Fragment key={e.id}>
                      <tr
                        className={`align-top cursor-pointer transition-colors ${open ? 'bg-cyan-500/[0.04]' : 'hover:bg-white/[0.02]'}`}
                        onClick={() => setExpandedId(open ? null : e.id)}
                      >
                        <td className="py-3 px-4 text-[var(--text-muted)]">
                          <ChevronDown className={`h-4 w-4 transition-transform ${open ? 'rotate-180 text-cyan-400' : ''}`} />
                        </td>
                        <td className="py-3 px-4 font-mono text-[var(--text-tertiary)] whitespace-nowrap">
                          {fmtTime(e.created_at, i18n.language)}
                        </td>
                        <td className="py-3 px-4">
                          <ActionBadge action={e.action} />
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-cyan-500/10 text-[10px] text-cyan-300">
                              {(e.actor_email || '?')[0]?.toUpperCase()}
                            </span>
                            <span className="text-cyan-300/90 truncate max-w-[14rem]" title={e.actor_email}>
                              {e.actor_email || `user#${e.user_id || '—'}`}
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-4 text-[var(--text-tertiary)] font-mono truncate max-w-[20rem]" title={extractTarget(e)}>
                          {extractTarget(e)}
                        </td>
                        <td className="py-3 px-4 font-mono text-[var(--text-muted)]">{e.client_ip || '—'}</td>
                      </tr>
                      {open && (
                        <tr className="bg-[var(--table-surface)]">
                          <td colSpan={6} className="px-4 pb-4 pt-0">
                            <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-3)] p-4">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
                                {t('audit.detail_payload')}
                              </div>
                              <pre className="text-[11px] font-mono text-emerald-200/90 whitespace-pre-wrap break-words max-h-64 overflow-auto leading-relaxed">
                                {json ? JSON.stringify(json, null, 2) : (text || '—')}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {total > 0 && (
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 px-4 py-4 border-t border-[var(--border-default)] bg-white/[0.02]">
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
              <button
                type="button"
                disabled={offset <= 0}
                onClick={() => setOffset(0)}
                className="p-2 rounded-lg border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-white disabled:opacity-25 transition-colors"
                aria-label={t('audit.first_page')}
              >
                <ChevronsLeft className="h-4 w-4" />
              </button>
              <button
                type="button"
                disabled={offset <= 0}
                onClick={() => setOffset((o) => Math.max(0, o - pageSize))}
                className="p-2 rounded-lg border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-white disabled:opacity-25 transition-colors"
                aria-label={t('audit.prev_page')}
              >
                <ChevronLeft className="h-4 w-4" />
              </button>

              <div className="flex items-center gap-1 px-2">
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let page
                  if (totalPages <= 5) page = i + 1
                  else if (currentPage <= 3) page = i + 1
                  else if (currentPage >= totalPages - 2) page = totalPages - 4 + i
                  else page = currentPage - 2 + i
                  return (
                    <button
                      key={page}
                      type="button"
                      onClick={() => setOffset((page - 1) * pageSize)}
                      className={`min-w-[2rem] h-8 rounded-lg text-xs font-mono border transition-all ${
                        page === currentPage
                          ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/40'
                          : 'border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-white hover:border-[var(--border-strong)]'
                      }`}
                    >
                      {page}
                    </button>
                  )
                })}
              </div>

              <button
                type="button"
                disabled={offset + pageSize >= total}
                onClick={() => setOffset((o) => o + pageSize)}
                className="p-2 rounded-lg border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-white disabled:opacity-25 transition-colors"
                aria-label={t('audit.next_page')}
              >
                <ChevronRight className="h-4 w-4" />
              </button>
              <button
                type="button"
                disabled={offset + pageSize >= total}
                onClick={() => setOffset((totalPages - 1) * pageSize)}
                className="p-2 rounded-lg border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-white disabled:opacity-25 transition-colors"
                aria-label={t('audit.last_page')}
              >
                <ChevronsRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}
      </section>
    </div>
  )
}
