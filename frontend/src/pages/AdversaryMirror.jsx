/**
 * Adversary Gap Mirror — CISO war room for legal clearnet intel + IAB-interesting exposure.
 * Live GET /api/findings only. Scan via POST /api/command-center/scan (adversary_gap_mirror).
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Crosshair, Radio, Search, ShieldAlert, Swords } from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import DataTable from '../components/ui/DataTable'
import FindingDrawer from '../components/ui/FindingDrawer'
import { SkeletonTable, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import Button from '../components/ui/Button'
import { useClient } from '../context/ClientContext'
import { firstClientTarget } from '../lib/clientTarget'
import { useLaunchEngineScan } from '../hooks/useLaunchEngineScan'
import { useToast } from '../components/ui/Toaster'
import { useJobPoll } from '../lib/useJobPoll'
import { useInsideEngineC2, useC2AbortSignal } from '../engineC2/EngineC2Boundary'

const columnHelper = createColumnHelper()
const ENGINE = 'adversary_gap_mirror'
const SOURCES = new Set([
  'adversary_gap_mirror',
  'leak_hunter',
  'darkweb_intel',
  'dark_web_monitor',
  'typosquatting_monitor',
])
const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const NS = 'pages.adversaryMirror'

function severityBadgeClass(sev) {
  const s = (sev || 'info').toLowerCase()
  const map = {
    critical: 'text-rose-300 bg-rose-500/10 border-rose-500/40',
    high: 'text-orange-300 bg-orange-500/10 border-orange-500/40',
    medium: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/40',
    low: 'text-blue-300 bg-blue-500/10 border-blue-500/40',
    info: 'text-[var(--text-secondary)] bg-[var(--bg-4)]/10 border-[var(--border-strong)]/40',
  }
  return `inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border ${map[s] || map.info}`
}

function parseFindings(data) {
  const arr = Array.isArray(data) ? data : Array.isArray(data?.findings) ? data.findings : []
  return arr
    .filter((f) => SOURCES.has((f.source || f.engine || f.type || '').toLowerCase()))
    .sort(
      (a, b) =>
        (SEVERITY_ORDER[(b.severity || '').toLowerCase()] || 0)
        - (SEVERITY_ORDER[(a.severity || '').toLowerCase()] || 0),
    )
}

async function downloadRaw(path, filename) {
  const res = await apiFetch(path, { raw: true })
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const j = await res.json()
      msg = j.error || j.detail || j.message || msg
    } catch {
      /* keep status text */
    }
    throw new Error(msg)
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export default function AdversaryMirror() {
  const { t } = useTranslation()
  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      hideEvidence
      badge={t(`${NS}.badge`)}
      badgeColor="#e11d48"
      icon={<Crosshair />}
    >
      <AdversaryMirrorBody />
    </PageShell>
  )
}

function AdversaryMirrorBody() {
  const { t } = useTranslation()
  const { toast } = useToast()
  useInsideEngineC2()
  const { signal, killed } = useC2AbortSignal()
  const { clients, selectedClientId, setSelectedClientId } = useClient()
  const selected = clients.find((c) => String(c.id) === String(selectedClientId)) || null
  const target = firstClientTarget(selected)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [selectedFinding, setSelected] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [pendingJobId, setPendingJobId] = useState(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const path = selectedClientId
        ? `/api/clients/${selectedClientId}/findings`
        : '/api/findings?limit=2000'
      const d = await apiFetch(path)
      setFindings(parseFindings(d))
      setLastRefresh(new Date())
    } catch (e) {
      setError(e.message || t(`${NS}.load_error`, { error: '' }))
      setFindings([])
    } finally {
      setLoading(false)
    }
  }, [t, selectedClientId])

  useEffect(() => { load() }, [load])
  useVisiblePolling(load, 60000, { paused: !autoRefresh })
  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: (job) => {
      setPendingJobId(null)
      setScanning(false)
      load()
      const st = String(job?.status || '').toLowerCase()
      if (st === 'completed') toast.success(t(`${NS}.scan_complete`))
      else toast.error(t(`${NS}.scan_job_failed`, { status: st || 'failed' }))
    },
  })

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return findings
    return findings.filter((f) => {
      const hay = `${f.title || ''} ${f.description || ''} ${f.target || ''} ${f.source || f.engine || ''}`.toLowerCase()
      return hay.includes(q)
    })
  }, [findings, search])

  const stats = useMemo(() => {
    const by = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    let ransom = 0
    let iab = 0
    for (const f of findings) {
      const s = (f.severity || 'info').toLowerCase()
      if (by[s] !== undefined) by[s] += 1
      if (s === 'info' || s === 'advisory') continue
      const blob = `${f.title || ''} ${f.description || ''}`.toLowerCase()
      if (blob.includes('ransomware') || blob.includes('leak-site')) ransom += 1
      if (blob.includes('iab') || blob.includes('rdp') || blob.includes('vpn') || blob.includes('product token')) iab += 1
    }
    return { ...by, total: by.critical + by.high + by.medium + by.low, ransom, iab }
  }, [findings])

  const { exportCsv } = useFindingsWorkbench(filtered, { csvPrefix: 'adversary-gap-mirror' })
  const launchScan = useLaunchEngineScan(selectedClientId)

  const runEngine = async (engineId) => {
    if (killed) {
      toast.error(t(`${NS}.killed`))
      return
    }
    if (!selectedClientId || !target) {
      toast.error(t(`${NS}.need_client`))
      return
    }
    setScanning(true)
    try {
      const { ok, data } = await launchScan({
        engineId,
        clientId: selectedClientId,
        target,
        signal,
      })
      if (!ok) {
        throw new Error(data?.error || data?.detail || data?.message || t(`${NS}.scan_failed`))
      }
      toast.success(t(`${NS}.scan_queued`))
      const jobId = data?.job_id ?? data?.jobId ?? data?.id
      if (jobId) setPendingJobId(String(jobId))
      else {
        setScanning(false)
        setTimeout(load, 2500)
      }
    } catch (e) {
      toast.error(e.message || t(`${NS}.scan_failed`))
      setScanning(false)
    }
  }

  const runMirror = () => runEngine(ENGINE)

  const exportXlsx = async () => {
    if (!selectedClientId) return
    try {
      await downloadRaw(
        `/api/clients/${selectedClientId}/adversary-mirror/xlsx`,
        `weissman-adversary-mirror-${selectedClientId}.xlsx`,
      )
    } catch (e) {
      toast.error(e.message || t(`${NS}.export_failed`))
    }
  }

  const exportPdf = async () => {
    if (!selectedClientId) return
    try {
      await downloadRaw(
        `/api/clients/${selectedClientId}/adversary-mirror/pdf`,
        `weissman-adversary-mirror-${selectedClientId}.pdf`,
      )
    } catch (e) {
      toast.error(e.message || t(`${NS}.export_failed`))
    }
  }

  const columns = useMemo(
    () => [
      columnHelper.accessor((f) => (f.severity || 'info').toLowerCase(), {
        id: 'severity',
        header: t(`${NS}.col_severity`),
        cell: (ctx) => <span className={severityBadgeClass(ctx.getValue())}>{String(ctx.getValue()).toUpperCase()}</span>,
      }),
      columnHelper.accessor((f) => f.title || '', {
        id: 'title',
        header: t(`${NS}.col_title`),
        cell: (ctx) => (
          <span className="text-[var(--text-primary)] max-w-md truncate block" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((f) => f.source || f.engine || '', {
        id: 'source',
        header: t(`${NS}.col_source`),
      }),
      columnHelper.accessor((f) => f.target || '', {
        id: 'target',
        header: t(`${NS}.col_target`),
      }),
    ],
    [t],
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="unstyled"
            type="button"
            onClick={() => setAutoRefresh((v) => !v)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono ${
              autoRefresh
                ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10'
                : 'border-[var(--border-default)] text-[var(--text-tertiary)]'
            }`}
          >
            <Radio className={`w-3 h-3 inline mr-1 ${autoRefresh ? 'animate-pulse' : ''}`} />
            {autoRefresh ? t(`${NS}.auto_on`) : t(`${NS}.auto_off`)}
          </Button>
          <Button
            variant="unstyled"
            type="button"
            onClick={runMirror}
            disabled={scanning || !target || killed}
            className="px-3 py-1.5 rounded-lg border border-rose-500/40 text-xs font-mono text-rose-200 hover:bg-rose-500/10 disabled:opacity-40"
          >
            <Swords className="w-3.5 h-3.5 inline mr-1" />
            {scanning ? t(`${NS}.scanning`) : t(`${NS}.run_mirror`)}
          </Button>
          <Button
            variant="unstyled"
            type="button"
            onClick={exportPdf}
            disabled={!selectedClientId}
            className="px-3 py-1.5 rounded-lg border border-cyan-500/35 text-xs font-mono text-cyan-300"
          >
            {t(`${NS}.export_pdf`)}
          </Button>
          <Button
            variant="unstyled"
            type="button"
            onClick={exportXlsx}
            disabled={!selectedClientId}
            className="px-3 py-1.5 rounded-lg border border-emerald-500/35 text-xs font-mono text-emerald-300"
          >
            {t(`${NS}.export_xlsx`)}
          </Button>
          <ShellScanActions
            onRefresh={load}
            onExport={() => filtered.length && exportCsv()}
            refreshLoading={loading}
            exportDisabled={filtered.length === 0}
          />
      </div>
      <div className="rounded-xl border border-rose-500/25 bg-gradient-to-r from-rose-950/40 to-violet-950/30 px-4 py-3 flex items-start gap-3">
          <ShieldAlert className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
          <p className="text-xs text-rose-100/80 leading-relaxed">{t(`${NS}.evidence_notice`)}</p>
        </div>

        <div className="flex flex-wrap gap-3 items-center">
          <select
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs font-mono"
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value || null)}
          >
            <option value="">{t(`${NS}.select_client`)}</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>{c.name || c.id}</option>
            ))}
          </select>
          <span className="text-[10px] font-mono text-[var(--text-muted)]">
            {target || t(`${NS}.no_target`)}
          </span>
          {lastRefresh && (
            <span className="text-[10px] font-mono text-[var(--text-disabled)]">
              {t(`${NS}.last_updated`, { time: lastRefresh.toLocaleTimeString() })}
            </span>
          )}
        </div>

        {error && <p className="text-xs text-rose-300">{error}</p>}

        {loading && findings.length === 0 ? (
          <SkeletonWidgetGrid count={5} />
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <Kpi label={t(`${NS}.total`)} value={stats.total} />
              <Kpi label={t(`${NS}.critical`)} value={stats.critical} accent="text-rose-300" pulse={stats.critical > 0} />
              <Kpi label={t(`${NS}.high`)} value={stats.high} accent="text-orange-300" />
              <Kpi label={t(`${NS}.ransom`)} value={stats.ransom} accent="text-fuchsia-300" />
              <Kpi label={t(`${NS}.iab`)} value={stats.iab} accent="text-amber-300" />
            </div>

            <div className="grid md:grid-cols-3 gap-3">
              <NextCard title={t(`${NS}.next_leak`)} to="/dark-web" />
              <NextCard title={t(`${NS}.next_paths`)} to="/attack-paths" />
              <NextCard title={t(`${NS}.next_heal`)} to="/remediation" />
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="unstyled"
                type="button"
                onClick={() => runEngine('leak_hunter')}
                disabled={scanning || !target || killed}
                className="px-3 py-1.5 rounded-lg border border-[var(--border-default)] text-xs font-mono"
              >
                {t(`${NS}.run_leak`)}
              </Button>
              <Button
                variant="unstyled"
                type="button"
                onClick={() => runEngine('password_spray')}
                disabled={scanning || !target || killed}
                className="px-3 py-1.5 rounded-lg border border-[var(--border-default)] text-xs font-mono"
              >
                {t(`${NS}.run_spray`)}
              </Button>
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[var(--text-muted)]" />
              <input
                className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg pl-9 pr-3 py-2 text-sm"
                placeholder={t(`${NS}.search_placeholder`)}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            {filtered.length === 0 ? (
              <EmptyState
                title={t(`${NS}.empty_title`)}
                body={t(`${NS}.empty_body`)}
              />
            ) : (
              <DataTable
                columns={columns}
                data={filtered}
                onRowClick={(row) => setSelected(row.original || row)}
              />
            )}
            {loading && findings.length > 0 && <SkeletonTable rows={3} />}
          </>
        )}

      <p className="text-[10px] font-mono text-[var(--text-muted)]">
        <Link to="/dark-web" className="text-cyan-400 hover:underline">{t(`${NS}.open_dark_web`)}</Link>
        {' · '}
        <Link to="/engines" className="text-cyan-400 hover:underline">{t(`${NS}.open_engines`)}</Link>
      </p>
      <FindingDrawer finding={selectedFinding} onClose={() => setSelected(null)} />
    </div>
  )
}

function Kpi({ label, value, accent, pulse }) {
  return (
    <div
      className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4"
      style={pulse ? { boxShadow: '0 0 24px rgba(244,63,94,0.25)' } : undefined}
    >
      <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{label}</div>
      <div className={`text-2xl font-mono mt-1 ${accent || 'text-[var(--text-primary)]'}`}>{value}</div>
    </div>
  )
}

function NextCard({ title, to }) {
  return (
    <Link
      to={to}
      className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 hover:border-rose-500/40 transition-colors"
    >
      <div className="text-xs font-medium text-[var(--text-primary)]">{title}</div>
    </Link>
  )
}
