import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Plus,
  Play,
  Save,
  Trash2,
  ChevronUp,
  ChevronDown,
  GripVertical,
  Zap,
  Clock,
  History,
  FileJson,
  AlertCircle,
  CheckCircle2,
  Loader2,
  Search,
  Download,
} from 'lucide-react'
import { apiFetch } from '../lib/apiBase'
import { formatApiErrorFromBody, formatApiErrorResponse } from '../lib/apiError'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { downloadBytes } from '../lib/pdfExport'
import ShellScanActions from '../components/engine/ShellScanActions'
import { confirmDialog } from '../utils/confirmDialog'
import Button from '../components/ui/Button'
import PlaybookGraph from '../components/PlaybookGraph'
import { downloadCsv } from '../lib/exportFindingsCsv'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLORS = {
  critical: { bg: 'bg-rose-500/15', ring: 'ring-rose-500/40', text: 'text-rose-200' },
  high:     { bg: 'bg-orange-500/15', ring: 'ring-orange-500/40', text: 'text-orange-200' },
  medium:   { bg: 'bg-amber-500/15', ring: 'ring-amber-500/40', text: 'text-amber-200' },
  low:      { bg: 'bg-sky-500/15', ring: 'ring-sky-500/40', text: 'text-sky-200' },
  info:     { bg: 'bg-[var(--border-strong)]/15', ring: 'ring-[var(--border-strong)]/40', text: 'text-[var(--text-secondary)]' },
}

const ACTION_KINDS = [
  { kind: 'set_status',   labelKey: 'playbooks.action.set_status',   params: { status: 'IN_PROGRESS' } },
  { kind: 'slack_notify', labelKey: 'playbooks.action.slack_notify', params: { url: '', template: '{{severity}}: {{title}} on {{target}}' } },
  { kind: 'webhook',      labelKey: 'playbooks.action.webhook',      params: { url: '', template: '{{title}}' } },
  { kind: 'open_pr',      labelKey: 'playbooks.action.open_pr',      params: { title: 'Auto-fix: {{title}}' } },
  { kind: 'isolate_host', labelKey: 'playbooks.action.isolate_host', params: { target: '{{target}}', duration_seconds: 900 } },
  { kind: 'page_oncall',  labelKey: 'playbooks.action.page_oncall',  params: { team: 'sec-oncall', severity: '{{severity}}' } },
  { kind: 'http_post',    labelKey: 'playbooks.action.http_post',    params: { url: '', body: { } } },
]

function exportPlaybooksCsv(list) {
  // Reuse the shared exporter so cells are neutralized against spreadsheet formula
  // injection (a name/description starting with = + - @ would otherwise execute in Excel/Sheets).
  const header = ['id', 'name', 'description', 'enabled', 'failure_count', 'actions_count']
  const rows = list.map((pb) => [
    pb.id,
    pb.name,
    pb.description || '',
    pb.enabled ? 'yes' : 'no',
    pb.failure_count ?? 0,
    Array.isArray(pb.actions) ? pb.actions.length : 0,
  ])
  downloadCsv(rows, header, 'playbooks')
}

function buildExamplePlaybook(t) {
  return {
  name: t('playbooks.example_name'),
  description: t('playbooks.example_description'),
  enabled: true,
  trigger: {
    severity: ['critical'],
    kev: true,
    exposed: true,
    cooldown_seconds: 3600,
  },
  actions: [
    { kind: 'set_status',   params: { status: 'IN_PROGRESS' } },
    { kind: 'isolate_host', params: { target: '{{target}}', duration_seconds: 1800 } },
    { kind: 'page_oncall',  params: { team: 'sec-oncall', severity: 'critical' } },
    { kind: 'slack_notify', params: { template: 'KEV CRITICAL on {{target}}: {{title}} (cvss={{cvss}} epss={{epss}})' } },
  ],
  }
}

const STATUS_META = {
  success:       { color: '#22c55e', label: 'success' },
  partial:       { color: '#f59e0b', label: 'partial' },
  failed:        { color: '#ef4444', label: 'failed' },
  dry_run:       { color: '#22d3ee', label: 'dry_run' },
  skipped_dedup: { color: '#94a3b8', label: 'skipped' },
}

function StatusPill({ status }) {
  const meta = STATUS_META[status] || { color: '#64748b', label: status || '—' }
  return (
    <span
      className="inline-flex items-center rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider"
      style={{ background: `${meta.color}18`, color: meta.color, border: `1px solid ${meta.color}44` }}
    >
      {meta.label}
    </span>
  )
}

function JsonEditor({ value, onChange, error, label, invalidLabel }) {
  const lines = (value || '').split('\n')
  const lineCount = Math.max(lines.length, 1)

  return (
    <div className="overflow-hidden rounded-xl ring-1 ring-white/[0.08] bg-[#0c0c0e]">
      <div className="flex items-center justify-between border-b border-white/[0.06] px-3 py-2">
        <span className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
          <FileJson className="h-3.5 w-3.5" />
          {label}
        </span>
        {error && (
          <span className="flex items-center gap-1 text-[10px] text-rose-400">
            <AlertCircle className="h-3 w-3" />
            {invalidLabel}
          </span>
        )}
      </div>
      <div className={`json-editor ${error ? 'json-editor--error' : ''}`}>
        <div className="json-gutter">
          {Array.from({ length: lineCount }, (_, i) => (
            <span key={i}>{i + 1}</span>
          ))}
        </div>
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          spellCheck={false}
          className="json-textarea custom-scroll"
          rows={Math.min(20, Math.max(6, lineCount))}
        />
      </div>
    </div>
  )
}

function ToggleChip({ active, onClick, children, accent = 'cyan' }) {
  const activeCls = accent === 'amber'
    ? 'bg-amber-500/15 ring-amber-400/35 text-amber-200'
    : 'bg-cyan-500/15 ring-cyan-400/35 text-cyan-200'
  return (
    <Button variant="unstyled"
      type="button"
      onClick={onClick}
      className={`rounded-full px-3 py-1.5 text-[11px] font-medium ring-1 transition-all ${
        active
          ? activeCls
          : 'bg-[var(--row-hover-bg)] ring-white/[0.08] text-[var(--text-muted)] hover:bg-[var(--row-hover-bg)] hover:text-[var(--text-secondary)]'
      }`}
    >
      {children}
    </Button>
  )
}

function ActionCard({ action, index, total, label, onMoveUp, onMoveDown, onRemove, onParamsChange, invalidLabel, moveUpLabel, moveDownLabel, removeLabel }) {
  const [paramsText, setParamsText] = useState(JSON.stringify(action.params || {}, null, 2))
  const [jsonError, setJsonError] = useState(false)

  useEffect(() => {
    setParamsText(JSON.stringify(action.params || {}, null, 2))
    setJsonError(false)
  }, [action.kind, action.params])

  const handleBlur = () => {
    try {
      const parsed = JSON.parse(paramsText || '{}')
      setJsonError(false)
      onParamsChange(parsed)
    } catch (_) {
      setJsonError(true)
    }
  }

  return (
    <motion.li
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className="group relative rounded-xl bg-[var(--bg-1)]/60 ring-1 ring-white/[0.08] transition-shadow hover:ring-white/[0.12] hover:shadow-lg hover:shadow-black/20"
    >
      <div className="flex items-stretch">
        <div className="flex w-8 shrink-0 cursor-grab flex-col items-center justify-center border-e border-white/[0.06] text-[var(--text-disabled)] transition-colors group-hover:text-[var(--text-muted)]">
          <GripVertical className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1 p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="flex h-6 w-6 items-center justify-center rounded-md bg-violet-500/15 text-[11px] font-bold text-violet-300 ring-1 ring-violet-500/30">
                {index + 1}
              </span>
              <span className="text-[13px] font-medium text-[var(--text-primary)]">{label || action.kind}</span>
              <span className="rounded bg-[var(--row-hover-bg)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-muted)]">{action.kind}</span>
            </div>
            <div className="flex items-center gap-0.5 opacity-60 transition-opacity group-hover:opacity-100">
              <Button variant="unstyled" type="button" onClick={onMoveUp} disabled={index === 0} className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--row-hover-bg)] hover:text-[var(--text-secondary)] disabled:opacity-20" aria-label={moveUpLabel}>
                <ChevronUp className="h-4 w-4" />
              </Button>
              <Button variant="unstyled" type="button" onClick={onMoveDown} disabled={index >= total - 1} className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--row-hover-bg)] hover:text-[var(--text-secondary)] disabled:opacity-20" aria-label={moveDownLabel}>
                <ChevronDown className="h-4 w-4" />
              </Button>
              <Button variant="unstyled" type="button" onClick={onRemove} className="rounded p-1 text-rose-400/70 hover:bg-rose-500/10 hover:text-rose-300" aria-label={removeLabel}>
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <div className={`rounded-lg ring-1 ${jsonError ? 'ring-rose-500/40' : 'ring-white/[0.06]'} bg-[var(--bg-2)]`}>
            <textarea
              value={paramsText}
              onChange={(e) => { setParamsText(e.target.value); setJsonError(false) }}
              onBlur={handleBlur}
              rows={Math.min(8, Math.max(3, paramsText.split('\n').length))}
              className="block w-full resize-none bg-transparent p-2.5 font-mono text-[11px] leading-relaxed text-emerald-300/90 focus:outline-none"
              spellCheck={false}
            />
          </div>
          {jsonError && (
            <p className="mt-1 flex items-center gap-1 text-[10px] text-rose-400">
              <AlertCircle className="h-3 w-3" />
              {invalidLabel}
            </p>
          )}
        </div>
      </div>
    </motion.li>
  )
}

export default function PlaybookBuilder() {
  const { t } = useTranslation()
  const [list, setList] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [draft, setDraft] = useState(null)
  const [saving, setSaving] = useState(false)
  const [statusMsg, setStatusMsg] = useState(null)
  const [runs, setRuns] = useState([])
  const [fireResult, setFireResult] = useState(null)
  const [jsonSource, setJsonSource] = useState('')
  const [jsonError, setJsonError] = useState(false)
  const [librarySearch, setLibrarySearch] = useState('')

  const refresh = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const r = await apiFetch('/api/playbooks')
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setList([])
        setLoadError(formatApiErrorFromBody(d, r.status))
        return
      }
      setList(Array.isArray(d?.playbooks) ? d.playbooks : [])
    } catch (e) {
      setList([])
      setLoadError(e?.message || t('ask_weissman.network_error'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { refresh() }, [refresh])

  useEffect(() => {
    if (!selected) { setRuns([]); return }
    let abort = false
    apiFetch(`/api/playbooks/${selected.id}/runs?limit=20`)
      .then((r) => r.json())
      .then((d) => { if (!abort) setRuns(d?.runs || []) })
      .catch(() => { if (!abort) setRuns([]) })
    return () => { abort = true }
  }, [selected])

  useEffect(() => {
    if (!draft) {
      setJsonSource('')
      setJsonError(false)
      return
    }
    setJsonSource(JSON.stringify({ trigger: draft.trigger, actions: draft.actions }, null, 2))
    setJsonError(false)
  }, [draft?.trigger, draft?.actions])

  const startNew = () => {
    setSelected(null)
    setDraft({
      name: '',
      description: '',
      enabled: false,
      trigger: { severity: [], cooldown_seconds: 3600 },
      actions: [],
    })
    setStatusMsg(null)
    setFireResult(null)
  }

  const startEdit = (pb) => {
    setSelected(pb)
    setDraft({
      name: pb.name,
      description: pb.description || '',
      enabled: !!pb.enabled,
      trigger: pb.trigger || {},
      actions: pb.actions || [],
    })
    setStatusMsg(null)
    setFireResult(null)
  }

  const insertExample = () => {
    setSelected(null)
    setDraft(JSON.parse(JSON.stringify(buildExamplePlaybook(t))))
    setStatusMsg({ kind: 'info', text: t('playbooks.loaded_example') })
    setFireResult(null)
  }

  const save = async () => {
    if (!draft?.name?.trim()) { setStatusMsg({ kind: 'err', text: t('playbooks.name_required') }); return }
    setSaving(true)
    setStatusMsg(null)
    const body = JSON.stringify({
      name: draft.name.trim(),
      description: draft.description || '',
      enabled: !!draft.enabled,
      trigger: draft.trigger || {},
      actions: draft.actions || [],
    })
    try {
      const url = selected ? `/api/playbooks/${selected.id}` : '/api/playbooks'
      const method = selected ? 'PATCH' : 'POST'
      const r = await apiFetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body,
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setStatusMsg({ kind: 'err', text: d?.detail || `HTTP ${r.status}` })
      } else {
        setStatusMsg({ kind: 'ok', text: selected ? t('playbooks.save_changes') : `${t('playbooks.create_playbook')} (${d.id})` })
        await refresh()
        if (!selected && d.id) {
          const r2 = await apiFetch('/api/playbooks').then((x) => x.json()).catch(() => ({}))
          const fresh = (r2?.playbooks || []).find((p) => p.id === d.id)
          if (fresh) startEdit(fresh)
        }
      }
    } catch (e) {
      setStatusMsg({ kind: 'err', text: e?.message || t('ask_weissman.network_error') })
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    if (!selected) return
    if (!(await confirmDialog(t('playbooks.delete_confirm', { name: selected.name })))) return
    try {
      const r = await apiFetch(`/api/playbooks/${selected.id}`, { method: 'DELETE' })
      if (r.ok) {
        setSelected(null); setDraft(null)
        await refresh()
      } else {
        setStatusMsg({ kind: 'err', text: await formatApiErrorResponse(r) })
      }
    } catch (e) {
      setStatusMsg({ kind: 'err', text: e?.message || t('ask_weissman.network_error') })
    }
  }

  const dryRun = async () => {
    if (!draft) return
    setStatusMsg(null)
    setFireResult({ loading: true })
    const sampleEvent = {
      kind: 'finding_persisted',
      tenant_id: 0,
      client_id: 1,
      finding_id: 999_999,
      cluster_id: null,
      title: 'Sample event for dry-run',
      severity: (draft.trigger?.severity?.[0]) || 'critical',
      source: (draft.trigger?.engines?.[0]) || 'asm',
      target: 'https://example.com/probe',
      status: 'OPEN',
      cvss: 9.8,
      epss: draft.trigger?.epss_min ?? 0.85,
      kev: !!draft.trigger?.kev,
      kev_known_ransomware: !!draft.trigger?.kev,
      cve: 'CVE-2024-12345',
      signature_hash: 'preview',
      internet_exposed: !!draft.trigger?.exposed,
    }
    try {
      const r = await apiFetch('/api/playbooks/fire', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event: sampleEvent, dry_run: true }),
      })
      const d = await r.json()
      setFireResult({ loading: false, ok: r.ok, ...d })
    } catch (e) {
      setFireResult({ loading: false, ok: false, detail: e?.message || t('ask_weissman.network_error') })
    }
  }

  const updateTrigger = (patch) =>
    setDraft((d) => ({ ...d, trigger: { ...(d.trigger || {}), ...patch } }))

  const toggleSev = (s) =>
    updateTrigger({
      severity: (draft.trigger?.severity || []).includes(s)
        ? draft.trigger.severity.filter((x) => x !== s)
        : [...(draft.trigger?.severity || []), s],
    })

  const addAction = (kind) => {
    const template = ACTION_KINDS.find((a) => a.kind === kind) || ACTION_KINDS[0]
    setDraft((d) => ({
      ...d,
      actions: [...(d.actions || []), JSON.parse(JSON.stringify({ kind: template.kind, params: template.params }))],
    }))
  }

  const moveAction = (i, dir) => {
    setDraft((d) => {
      const arr = [...(d.actions || [])]
      const j = i + dir
      if (j < 0 || j >= arr.length) return d
      ;[arr[i], arr[j]] = [arr[j], arr[i]]
      return { ...d, actions: arr }
    })
  }

  const removeAction = (i) =>
    setDraft((d) => ({ ...d, actions: (d.actions || []).filter((_, k) => k !== i) }))

  const updateActionParams = (i, json) => {
    setDraft((d) => {
      const arr = [...(d.actions || [])]
      arr[i] = { ...arr[i], params: json }
      return { ...d, actions: arr }
    })
  }

  const handleJsonSourceChange = (text) => {
    setJsonSource(text)
    try {
      const parsed = JSON.parse(text)
      setJsonError(false)
      setDraft((d) => ({
        ...d,
        trigger: parsed.trigger ?? d.trigger,
        actions: parsed.actions ?? d.actions,
      }))
    } catch (_) {
      setJsonError(true)
    }
  }

  const filterSummary = useMemo(() => {
    if (!list.length) return null
    const enabled = list.filter((p) => p.enabled).length
    const fails = list.reduce((a, b) => a + (b.failure_count || 0), 0)
    return t('playbooks.summary', { count: list.length, enabled, failures: fails })
  }, [list, t])

  const filteredList = useMemo(() => {
    const q = librarySearch.trim().toLowerCase()
    if (!q) return list
    return list.filter((pb) => {
      const hay = `${pb.name || ''} ${pb.description || ''} ${pb.id || ''}`.toLowerCase()
      return hay.includes(q)
    })
  }, [list, librarySearch])

  const exportPlaybookJson = () => {
    if (!draft) return
    const payload = {
      name: draft.name,
      description: draft.description || '',
      enabled: !!draft.enabled,
      trigger: draft.trigger || {},
      actions: draft.actions || [],
    }
    const bytes = new TextEncoder().encode(JSON.stringify(payload, null, 2))
    const slug = (draft.name || selected?.name || 'playbook').replace(/[^a-z0-9]+/gi, '-').toLowerCase()
    downloadBytes(bytes, `${slug || 'playbook'}.json`, 'application/json')
  }

  const actionLabel = (kind) => {
    const entry = ACTION_KINDS.find((a) => a.kind === kind)
    return entry?.labelKey ? t(entry.labelKey) : kind
  }

  return (
    <div id="main-content" tabIndex={-1} className="playbook-builder-root min-h-[100dvh] bg-[var(--bg-0)] text-[var(--text-secondary)] outline-none">
      {/* Header */}
      <header className="border-b border-white/[0.06] bg-[#09090b]/80 px-5 py-5 backdrop-blur-xl lg:px-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500/20 to-cyan-500/15 ring-1 ring-violet-400/25">
                <Zap className="h-5 w-5 text-violet-300" strokeWidth={1.5} />
              </div>
              <div>
                <h1 className="text-xl font-semibold tracking-tight">{t('playbooks.title')}</h1>
                <p className="mt-0.5 max-w-xl text-[12px] text-[var(--text-muted)]">{t('playbooks.subtitle')}</p>
              </div>
            </div>
            {filterSummary && (
              <p className="mt-2 ps-[52px] text-[11px] text-[var(--text-disabled)]">{filterSummary}</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <ShellScanActions
              onRefresh={refresh}
              onExport={() => exportPlaybooksCsv(list)}
              refreshLoading={loading}
              exportDisabled={!list.length}
            />
            <Link to="/" className="px-3 py-2 text-[12px] text-[var(--text-muted)] transition-colors hover:text-[var(--text-secondary)]">
              ← {t('nav.cockpit')}
            </Link>
            <Button variant="unstyled"
              type="button"
              onClick={insertExample}
              className="rounded-lg px-3 py-2 text-[12px] text-[var(--text-tertiary)] ring-1 ring-white/[0.1] transition-all hover:bg-[var(--row-hover-bg)] hover:text-[var(--text-primary)]"
            >
              {t('playbooks.insert_example')}
            </Button>
            <Button variant="unstyled"
              type="button"
              onClick={startNew}
              className="inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-violet-600/80 to-cyan-600/70 px-4 py-2 text-[12px] font-medium text-white shadow-lg shadow-violet-500/10 transition-all hover:from-violet-500/90 hover:to-cyan-500/80"
            >
              <Plus className="h-4 w-4" />
              {t('playbooks.new_playbook')}
            </Button>
          </div>
        </div>
      </header>

      <div className="px-5 lg:px-8 pb-4">
        <EvidenceNotice>{t('playbooks.evidence_notice')}</EvidenceNotice>
      </div>

      {/* Three-panel layout */}
      <div className="grid min-h-[calc(100dvh-88px)] grid-cols-1 xl:grid-cols-[280px_1fr_300px]">
        {/* Left — Library */}
        <aside className="border-b border-white/[0.06] bg-[#0a0a0c]/60 xl:border-b-0 xl:border-e">
          <div className="sticky top-0 p-4">
            <h2 className="mb-3 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-[var(--text-muted)]">
              <FileJson className="h-3.5 w-3.5" />
              {t('playbooks.library')}
            </h2>
            <div className="relative mb-3">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-[var(--text-disabled)] pointer-events-none" />
              <input
                type="search"
                value={librarySearch}
                onChange={(e) => setLibrarySearch(e.target.value)}
                aria-label={t('playbooks.library_search')}
                placeholder={t('playbooks.library_search')}
                className="w-full rounded-lg bg-[var(--bg-2)] pl-8 pr-3 py-2 text-[11px] text-[var(--text-secondary)] ring-1 ring-white/[0.08] placeholder:text-[var(--text-disabled)] focus:outline-none focus:ring-cyan-400/30"
              />
            </div>
            {loadError && (
              <p className="rounded-lg bg-rose-500/10 px-3 py-2 text-[11px] text-rose-300 ring-1 ring-rose-500/25">{loadError}</p>
            )}
            {loading ? (
              <div className="flex items-center gap-2 py-8 text-[12px] text-[var(--text-muted)]">
                <Loader2 className="h-4 w-4 animate-spin" />
                {t('common.loading')}
              </div>
            ) : list.length === 0 ? (
              <p className="py-6 text-[12px] leading-relaxed text-[var(--text-muted)]">{t('playbooks.no_playbooks')}</p>
            ) : filteredList.length === 0 ? (
              <p className="py-6 text-[12px] leading-relaxed text-[var(--text-muted)]">{t('playbooks.no_library_match')}</p>
            ) : (
              <ul className="space-y-1 custom-scroll max-h-[calc(100dvh-180px)] overflow-y-auto">
                {filteredList.map((pb) => {
                  const isActive = selected?.id === pb.id
                  return (
                    <li key={pb.id}>
                      <Button variant="unstyled"
                        type="button"
                        onClick={() => startEdit(pb)}
                        className={`block w-full rounded-xl px-3 py-3 text-left transition-all ${
                          isActive
                            ? 'bg-gradient-to-r from-violet-500/15 to-cyan-500/10 ring-1 ring-violet-400/30 shadow-lg shadow-violet-500/5'
                            : 'hover:bg-[var(--row-hover-bg)] ring-1 ring-transparent hover:ring-white/[0.06]'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <span className="truncate text-[13px] font-medium text-[var(--text-primary)]">{pb.name}</span>
                          <span className={`shrink-0 rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${
                            pb.enabled
                              ? 'bg-emerald-500/12 text-emerald-300 ring-1 ring-emerald-500/30'
                              : 'bg-[var(--row-hover-bg)] text-[var(--text-muted)] ring-1 ring-white/[0.08]'
                          }`}>
                            {pb.enabled ? t('common.on') : t('common.off')}
                          </span>
                        </div>
                        <div className="mt-1.5 flex items-center gap-2 text-[10px] text-[var(--text-muted)]">
                          <span>{t('playbooks.runs_count', { count: pb.run_count || 0 })}</span>
                          <StatusPill status={pb.last_run_status} />
                        </div>
                      </Button>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        </aside>

        {/* Center — Editor */}
        <main className="overflow-y-auto custom-scroll p-5 lg:p-6">
          {!draft ? (
            <div className="flex h-full min-h-[320px] flex-col items-center justify-center text-center">
              <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--row-hover-bg)] ring-1 ring-white/[0.08]">
                <Zap className="h-7 w-7 text-[var(--text-disabled)]" />
              </div>
              <p className="max-w-sm text-[14px] text-[var(--text-muted)]">{t('playbooks.pick_playbook')}</p>
            </div>
          ) : (
            <div className="mx-auto max-w-3xl space-y-6">
              {/* Meta */}
              <div className="space-y-3">
                <input
                  type="text"
                  value={draft.name}
                  onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                  placeholder={t('playbooks.name_placeholder')}
                  className="w-full rounded-xl bg-[var(--bg-1)]/60 px-4 py-3 text-[16px] font-semibold text-[var(--text-primary)] ring-1 ring-white/[0.08] placeholder:text-[var(--text-disabled)] focus:outline-none focus:ring-violet-400/35"
                />
                <textarea
                  value={draft.description}
                  onChange={(e) => setDraft((d) => ({ ...d, description: e.target.value }))}
                  placeholder={t('playbooks.description_placeholder')}
                  rows={2}
                  className="w-full resize-none rounded-xl bg-[var(--bg-1)]/40 px-4 py-3 text-[13px] text-[var(--text-secondary)] ring-1 ring-white/[0.06] placeholder:text-[var(--text-disabled)] focus:outline-none focus:ring-violet-400/25"
                />
                <label className="inline-flex cursor-pointer items-center gap-2 rounded-full bg-[var(--row-hover-bg)] px-3 py-1.5 ring-1 ring-white/[0.08]">
                  <input
                    type="checkbox"
                    checked={!!draft.enabled}
                    onChange={(e) => setDraft((d) => ({ ...d, enabled: e.target.checked }))}
                    className="rounded border-[var(--border-strong)] bg-transparent text-violet-500 focus:ring-violet-500/30"
                  />
                  <span className="text-[12px] font-medium text-[var(--text-secondary)]">{t('playbooks.enabled_label')}</span>
                </label>
              </div>

              {/* Trigger builder */}
              <section className="rounded-2xl bg-[var(--bg-1)]/40 p-5 ring-1 ring-white/[0.07]">
                <h3 className="mb-4 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-violet-300/80">
                  <Zap className="h-3.5 w-3.5" />
                  {t('playbooks.when_conditions')}
                </h3>
                <div className="space-y-4">
                  <div>
                    <p className="mb-2 text-[11px] text-[var(--text-muted)]">{t('playbooks.severity_any')}</p>
                    <div className="flex flex-wrap gap-2">
                      {SEVERITIES.map((s) => {
                        const active = (draft.trigger?.severity || []).includes(s)
                        const colors = SEV_COLORS[s]
                        return (
                          <Button variant="unstyled"
                            type="button"
                            key={s}
                            onClick={() => toggleSev(s)}
                            className={`rounded-full px-3 py-1 text-[10px] font-semibold uppercase tracking-wider ring-1 transition-all ${
                              active
                                ? `${colors.bg} ${colors.ring} ${colors.text}`
                                : 'bg-[var(--row-hover-bg)] ring-white/[0.08] text-[var(--text-muted)] hover:text-[var(--text-tertiary)]'
                            }`}
                          >
                            {t(`playbooks.severity.${s}`)}
                          </Button>
                        )
                      })}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <ToggleChip
                      active={!!draft.trigger?.kev}
                      onClick={() => updateTrigger({ kev: draft.trigger?.kev ? undefined : true })}
                      accent="amber"
                    >
                      {t('playbooks.require_kev')}
                    </ToggleChip>
                    <ToggleChip
                      active={!!draft.trigger?.exposed}
                      onClick={() => updateTrigger({ exposed: draft.trigger?.exposed ? undefined : true })}
                    >
                      {t('playbooks.require_exposed')}
                    </ToggleChip>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <label className="block">
                      <span className="text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">{t('playbooks.epss_min')}</span>
                      <input
                        type="number"
                        min="0" max="1" step="0.05"
                        value={draft.trigger?.epss_min ?? ''}
                        onChange={(e) => updateTrigger({
                          epss_min: e.target.value === '' ? undefined : Number(e.target.value),
                        })}
                        className="mt-1 block w-full rounded-lg bg-[var(--bg-2)] px-3 py-2 text-[13px] text-[var(--text-primary)] ring-1 ring-white/[0.08] focus:outline-none focus:ring-cyan-400/30"
                      />
                    </label>
                    <label className="block">
                      <span className="text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">{t('playbooks.cooldown')}</span>
                      <input
                        type="number"
                        min="0" step="60"
                        value={draft.trigger?.cooldown_seconds ?? ''}
                        onChange={(e) => updateTrigger({
                          cooldown_seconds: e.target.value === '' ? undefined : Number(e.target.value),
                        })}
                        className="mt-1 block w-full rounded-lg bg-[var(--bg-2)] px-3 py-2 text-[13px] text-[var(--text-primary)] ring-1 ring-white/[0.08] focus:outline-none focus:ring-cyan-400/30"
                      />
                    </label>
                  </div>
                </div>
              </section>

              {/* Actions */}
              <section className="rounded-2xl bg-[var(--bg-1)]/40 p-5 ring-1 ring-white/[0.07]">
                <h3 className="mb-4 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-cyan-300/80">
                  <Play className="h-3.5 w-3.5" />
                  {t('playbooks.do_actions')}
                </h3>
                <div className="mb-4 flex flex-wrap gap-1.5">
                  {ACTION_KINDS.map((a) => (
                    <Button variant="unstyled"
                      type="button"
                      key={a.kind}
                      onClick={() => addAction(a.kind)}
                      className="rounded-lg bg-[var(--row-hover-bg)] px-2.5 py-1 text-[10px] font-medium text-[var(--text-tertiary)] ring-1 ring-white/[0.08] transition-all hover:bg-cyan-500/10 hover:text-cyan-200 hover:ring-cyan-400/25"
                    >
                      + {t(a.labelKey)}
                    </Button>
                  ))}
                </div>
                {(draft.actions || []).length > 0 && (
                  <div className="mb-4">
                    <PlaybookGraph
                      trigger={draft.trigger}
                      actions={draft.actions}
                      onDryRun={dryRun}
                    />
                  </div>
                )}
                {(draft.actions || []).length === 0 ? (
                  <p className="py-8 text-center text-[12px] text-[var(--text-muted)]">{t('playbooks.no_actions')}</p>
                ) : (
                  <ul className="space-y-2">
                    {(draft.actions || []).map((a, i) => (
                      <ActionCard
                        key={`${a.kind}-${i}`}
                        action={a}
                        index={i}
                        total={draft.actions.length}
                        label={actionLabel(a.kind)}
                        onMoveUp={() => moveAction(i, -1)}
                        onMoveDown={() => moveAction(i, +1)}
                        onRemove={() => removeAction(i)}
                        onParamsChange={(json) => updateActionParams(i, json)}
                        invalidLabel={t('playbooks.json_invalid')}
                        moveUpLabel={t('a11y.move_up')}
                        moveDownLabel={t('a11y.move_down')}
                        removeLabel={t('a11y.remove_action')}
                      />
                    ))}
                  </ul>
                )}
              </section>

              {/* JSON source */}
              <JsonEditor
                value={jsonSource}
                onChange={handleJsonSourceChange}
                error={jsonError}
                label={t('playbooks.json_source')}
                invalidLabel={t('playbooks.json_invalid')}
              />

              {/* Toolbar */}
              <div className="flex flex-wrap items-center gap-2 border-t border-white/[0.06] pt-4">
                <Button variant="unstyled"
                  type="button"
                  onClick={save}
                  disabled={saving}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600/80 px-4 py-2 text-[12px] font-medium text-white transition-all hover:bg-emerald-500/90 disabled:opacity-50"
                >
                  {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                  {saving ? t('playbooks.saving') : selected ? t('playbooks.save_changes') : t('playbooks.create_playbook')}
                </Button>
                <Button variant="unstyled"
                  type="button"
                  onClick={dryRun}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600/20 px-4 py-2 text-[12px] font-medium text-cyan-200 ring-1 ring-cyan-400/30 transition-all hover:bg-cyan-500/25"
                >
                  <Play className="h-4 w-4" />
                  {t('playbooks.dry_run')}
                </Button>
                <Button variant="unstyled"
                  type="button"
                  onClick={exportPlaybookJson}
                  disabled={!draft}
                  className="inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-[12px] font-medium text-emerald-200 ring-1 ring-emerald-500/30 transition-all hover:bg-emerald-500/10 disabled:opacity-40"
                >
                  <Download className="h-4 w-4" />
                  {t('playbooks.export_json_playbook')}
                </Button>
                {selected && (
                  <Button variant="unstyled"
                    type="button"
                    onClick={remove}
                    className="ms-auto inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] text-rose-300 ring-1 ring-rose-500/25 transition-all hover:bg-rose-500/10"
                  >
                    <Trash2 className="h-4 w-4" />
                    {t('common.delete')}
                  </Button>
                )}
                {statusMsg && (
                  <span className={`flex items-center gap-1 text-[11px] ${
                    statusMsg.kind === 'err' ? 'text-rose-300' : statusMsg.kind === 'ok' ? 'text-emerald-300' : 'text-cyan-300'
                  }`}>
                    {statusMsg.kind === 'ok' && <CheckCircle2 className="h-3.5 w-3.5" />}
                    {statusMsg.kind === 'err' && <AlertCircle className="h-3.5 w-3.5" />}
                    {statusMsg.text}
                  </span>
                )}
              </div>

              {/* Dry-run result */}
              <AnimatePresence>
                {fireResult && (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="overflow-hidden rounded-2xl ring-1 ring-cyan-400/25 bg-gradient-to-br from-cyan-500/[0.08] to-violet-500/[0.05]"
                  >
                    <div className="flex items-center justify-between border-b border-cyan-400/15 px-4 py-3">
                      <span className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-cyan-300">
                        <Play className="h-3.5 w-3.5" />
                        {t('playbooks.dry_run_result')}
                      </span>
                      {fireResult.loading ? (
                        <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
                      ) : (
                        <StatusPill status={fireResult.ok ? 'dry_run' : 'failed'} />
                      )}
                    </div>
                    <div className="p-4">
                      {fireResult.loading ? (
                        <p className="text-[13px] text-[var(--text-tertiary)]">{t('playbooks.firing')}</p>
                      ) : (
                        <pre className="max-h-64 overflow-auto custom-scroll rounded-lg bg-[var(--bg-2)] p-4 font-mono text-[11px] leading-relaxed text-[var(--text-secondary)] ring-1 ring-white/[0.06]">
                          {JSON.stringify(fireResult.results ?? fireResult, null, 2)}
                        </pre>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}
        </main>

        {/* Right — History timeline */}
        <aside className="border-t border-white/[0.06] bg-[#0a0a0c]/60 xl:border-t-0 xl:border-s">
          <div className="sticky top-0 p-4">
            <h2 className="mb-4 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-[var(--text-muted)]">
              <History className="h-3.5 w-3.5" />
              {t('playbooks.run_history')}
            </h2>
            {!selected ? (
              <p className="text-[12px] text-[var(--text-muted)]">{t('playbooks.select_for_runs')}</p>
            ) : runs.length === 0 ? (
              <p className="text-[12px] text-[var(--text-muted)]">{t('playbooks.no_runs')}</p>
            ) : (
              <ol className="relative space-y-0 custom-scroll max-h-[calc(100dvh-140px)] overflow-y-auto ps-1">
                {runs.map((r, idx) => (
                  <li key={r.id} className="relative pb-5 ps-6">
                    {idx < runs.length - 1 && (
                      <span className="absolute start-[9px] top-5 bottom-0 w-px bg-gradient-to-b from-white/15 to-transparent" />
                    )}
                    <span className="absolute start-0 top-1.5 flex h-[18px] w-[18px] items-center justify-center rounded-full bg-[var(--bg-3)] ring-2 ring-[#0a0a0c]">
                      <Clock className="h-2.5 w-2.5 text-[var(--text-muted)]" />
                    </span>
                    <div className="rounded-xl bg-[var(--bg-1)]/50 p-3 ring-1 ring-white/[0.06] transition-colors hover:ring-white/[0.1]">
                      <div className="flex items-center justify-between gap-2">
                        <time className="text-[10px] font-medium text-[var(--text-muted)]">
                          {r.triggered_at ? new Date(r.triggered_at).toLocaleString() : '—'}
                        </time>
                        <StatusPill status={r.status} />
                      </div>
                      <p className="mt-1.5 truncate text-[12px] font-medium text-[var(--text-primary)]">
                        {r.trigger_event?.title || '—'}
                      </p>
                      <p className="mt-1 text-[10px] text-[var(--text-muted)]">
                        {t('playbooks.actions_ok', {
                          ok: r.actions_succeeded ?? 0,
                          total: r.actions_total ?? 0,
                          failed: r.actions_failed ?? 0,
                        })}
                      </p>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </aside>
      </div>

      <style>{`
        .playbook-builder-root {
          background:
            radial-gradient(ellipse 70% 45% at 0% 0%, rgba(139, 92, 246, 0.07), transparent),
            radial-gradient(ellipse 60% 40% at 100% 0%, rgba(34, 211, 238, 0.05), transparent),
            linear-gradient(180deg, #0a0a0c 0%, #09090b 50%, #030712 100%);
        }
        .json-editor {
          display: grid;
          grid-template-columns: auto 1fr;
          min-height: 120px;
        }
        .json-editor--error .json-gutter {
          border-right-color: rgba(239, 68, 68, 0.3);
        }
        .json-gutter {
          display: flex;
          flex-direction: column;
          padding: 12px 0;
          background: rgba(0,0,0,0.35);
          border-right: 1px solid rgba(255,255,255,0.06);
          user-select: none;
        }
        .json-gutter span {
          display: block;
          padding: 0 12px;
          font-family: ui-monospace, monospace;
          font-size: 11px;
          line-height: 1.6;
          text-align: right;
          color: rgba(255,255,255,0.18);
          min-width: 2rem;
        }
        .json-textarea {
          width: 100%;
          padding: 12px 16px;
          margin: 0;
          border: none;
          background: transparent;
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          font-size: 11px;
          line-height: 1.6;
          color: #a7f3d0;
          resize: vertical;
          min-height: 120px;
        }
        .json-textarea:focus {
          outline: none;
        }
      `}</style>
    </div>
  )
}
