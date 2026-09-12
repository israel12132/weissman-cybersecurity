/**
 * Cortex proven-finding bridge — live scan→finding map and XSIAM coverage gaps.
 * GET /api/findings/scan-cortex-bridge never invents XDR hits.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Radio, Search } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import ShellScanActions from '../components/engine/ShellScanActions'
import Button from '../components/ui/Button'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { launchEngineScan } from '../lib/launchEngineScan'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { SEV_COLOR } from '../lib/severity'
import { useClient } from '../context/ClientContext'

const NS = 'pages.cortexProvenBridge'
const ENGINE = 'cortex_proven_finding_bridge'

export default function CortexProvenBridge() {
  const { t } = useTranslation()
  const { selectedClientId } = useClient()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const [flushing, setFlushing] = useState(false)
  const [comparing, setComparing] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [flushMsg, setFlushMsg] = useState('')
  const [scanMsg, setScanMsg] = useState('')

  const qs = useMemo(() => {
    const p = new URLSearchParams()
    if (selectedClientId) p.set('client_id', String(selectedClientId))
    p.set('limit', '300')
    return p.toString()
  }, [selectedClientId])

  const load = useCallback(async (compareXdr = false, { quiet } = {}) => {
    if (!quiet) setLoading(true)
    setError('')
    try {
      const extra = compareXdr ? '&compare_xdr=true' : ''
      const d = await apiFetch(`/api/findings/scan-cortex-bridge?${qs}${extra}`)
      if (d?.ok === false) throw new Error(d.detail || t(`${NS}.load_failed`))
      setData(d)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
      if (!quiet) setData(null)
    } finally {
      setLoading(false)
    }
  }, [qs, t])

  useEffect(() => { load(false) }, [load])

  const items = Array.isArray(data?.items) ? data.items : []
  const counts = data?.counts || {}

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return items.filter((f) => {
      if (filter === 'proven' && !f.eligible) return false
      if (filter === 'blind' && !(f.xdr_had_matching_alert === false && f.eligible)) return false
      if (filter === 'pushed' && f.cortex_status !== 'pushed') return false
      if (!q) return true
      return `${f.title} ${f.source} ${f.engine_id} ${f.target} ${f.gate} ${f.cve || ''} ${f.proof_kind || ''}`
        .toLowerCase()
        .includes(q)
    })
  }, [items, searchQuery, filter])

  const exportCsv = useCallback(() => {
    downloadCsv(
      filtered.map((f) => [
        f.id,
        f.finding_id,
        f.engine_id,
        f.title,
        f.severity,
        f.proof_kind,
        f.eligible,
        f.cortex_status,
        f.xdr_had_matching_alert,
        f.report_run_id,
        f.target,
      ]),
      ['id', 'finding_id', 'engine', 'title', 'severity', 'proof_kind', 'eligible', 'cortex_status', 'xdr_had', 'report_run_id', 'target'],
      'weissman-cortex-bridge',
    )
  }, [filtered])

  const flushProven = async () => {
    setFlushing(true)
    setFlushMsg('')
    try {
      const d = await apiFetch('/api/findings/scan-cortex-bridge/flush', {
        method: 'POST',
        body: { dry_run: false, client_id: selectedClientId || undefined },
      })
      if (d?.ok === false) throw new Error(d.detail || t(`${NS}.flush_failed`))
      setFlushMsg(t(`${NS}.flush_ok`, { n: d.pushed ?? 0 }))
      await load(false, { quiet: true })
    } catch (e) {
      setFlushMsg(e.message || t(`${NS}.flush_failed`))
    } finally {
      setFlushing(false)
    }
  }

  const compareLive = async () => {
    setComparing(true)
    try {
      await load(true, { quiet: true })
    } finally {
      setComparing(false)
    }
  }

  const runCoverage = async () => {
    if (!selectedClientId) {
      setScanMsg(t(`${NS}.need_client`))
      return
    }
    setScanning(true)
    setScanMsg('')
    try {
      const r = await launchEngineScan({
        engineId: ENGINE,
        clientId: selectedClientId,
        target: '',
      })
      if (!r.ok) {
        throw new Error(r.data?.detail || r.data?.error || t(`${NS}.scan_failed`))
      }
      setScanMsg(t(`${NS}.scan_queued`, { id: r.data?.job_id || r.data?.id || 'queued' }))
    } catch (e) {
      setScanMsg(e.message || t(`${NS}.scan_failed`))
    } finally {
      setScanning(false)
    }
  }

  const showSkeleton = loading && !data

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      icon={<Radio />}
      actions={(
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="unstyled"
            type="button"
            onClick={runCoverage}
            disabled={scanning}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/35 text-[11px] font-mono text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-40"
          >
            {t(`${NS}.run_coverage`)}
          </Button>
          <Button
            variant="unstyled"
            type="button"
            onClick={compareLive}
            disabled={loading || comparing}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-orange-500/35 text-[11px] font-mono text-orange-200 hover:bg-orange-500/10 disabled:opacity-40"
          >
            {t(`${NS}.compare_xdr`)}
          </Button>
          <Button
            variant="unstyled"
            type="button"
            onClick={flushProven}
            disabled={flushing || !counts.proven_eligible}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-orange-500/35 bg-orange-500/10 text-[11px] font-mono text-orange-100 hover:bg-orange-500/20 disabled:opacity-40"
          >
            {t(`${NS}.flush`)}
          </Button>
          <ShellScanActions
            onRefresh={() => load(false)}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={!filtered.length}
          />
        </div>
      )}
    >
      <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      {flushMsg && (
        <p role="status" className="text-[11px] font-mono text-orange-200/90">{flushMsg}</p>
      )}
      {scanMsg && (
        <p className="text-[11px] font-mono text-cyan-200/90">{scanMsg}</p>
      )}
      {showSkeleton ? <SkeletonWidgetGrid count={4} /> : error && !data ? (
        <EmptyState title={t(`${NS}.load_failed`)} body={error} />
      ) : (
        <div className="space-y-4">
          {error && (
            <p role="alert" className="text-[11px] font-mono text-rose-300">{error}</p>
          )}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <ExecutiveWidget label={t(`${NS}.kpi_mapped`)} value={counts.mapped ?? 0} hint={t(`${NS}.kpi_mapped_hint`)} />
            <ExecutiveWidget label={t(`${NS}.kpi_proven`)} value={counts.proven_eligible ?? 0} hint={t(`${NS}.kpi_proven_hint`)} accent="#f97316" />
            <ExecutiveWidget label={t(`${NS}.kpi_pushed`)} value={counts.already_pushed ?? 0} hint={t(`${NS}.kpi_pushed_hint`)} />
            <ExecutiveWidget label={t(`${NS}.kpi_blind`)} value={counts.xdr_blind_spots ?? 0} hint={t(`${NS}.kpi_blind_hint`)} accent="#f43f5e" />
            <ExecutiveWidget label={t(`${NS}.kpi_covered`)} value={counts.xdr_already_had ?? 0} hint={t(`${NS}.kpi_covered_hint`)} accent="#34d399" />
            <ExecutiveWidget
              label={t(`${NS}.kpi_cortex`)}
              value={data?.cortex_configured ? t(`${NS}.configured`) : t(`${NS}.missing`)}
              hint={data?.cortex_mode || ENGINE}
              accent={data?.cortex_configured ? '#34d399' : '#f43f5e'}
            />
          </div>
          {!data?.cortex_configured && (
            <p className="text-[12px] font-mono text-orange-200/90">
              {data?.note}{' '}
              <Link to="/settings/integrations" className="underline text-orange-100">
                {t(`${NS}.open_integrations`)}
              </Link>
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            {['all', 'proven', 'blind', 'pushed'].map((id) => (
              <Button
                key={id}
                variant="unstyled"
                type="button"
                onClick={() => setFilter(id)}
                className={`px-2.5 py-1 rounded-md text-[10px] font-mono border ${
                  filter === id
                    ? 'border-orange-400/60 text-orange-100 bg-orange-500/15'
                    : 'border-white/10 text-white/50 hover:border-white/25'
                }`}
              >
                {t(`${NS}.filter_${id}`)}
              </Button>
            ))}
          </div>
          <div className="relative max-w-sm">
            <Search className="w-3.5 h-3.5 text-white/30 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              aria-label={t(`${NS}.search_placeholder`)}
              className="w-full pl-8 pr-3 py-2 rounded-lg text-sm bg-black/40 border border-white/10 text-white"
            />
          </div>
          {!filtered.length ? (
            <EmptyState title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
          ) : (
            <ul className="space-y-2">
              {filtered.map((f) => {
                const s = (f.severity || 'info').toLowerCase()
                const c = SEV_COLOR[s] || SEV_COLOR.info
                const blind = f.xdr_had_matching_alert === false && f.eligible
                const q = encodeURIComponent(f.finding_id || f.title || '')
                return (
                  <li
                    key={f.id || f.finding_id}
                    className="rounded-lg border border-white/10 p-3"
                    style={blind ? { borderColor: 'rgba(244,63,94,0.45)' } : undefined}
                  >
                    <div className="flex gap-2 items-center flex-wrap">
                      <span className="text-[10px] font-mono uppercase" style={{ color: c }}>{s}</span>
                      <span className="text-xs text-white/50 font-mono">{f.engine_id || f.source}</span>
                      {f.proof_kind && (
                        <span className="text-[10px] font-mono text-cyan-200/80">{f.proof_kind}</span>
                      )}
                      {f.eligible ? (
                        <span className="text-[10px] font-mono uppercase text-orange-200">{t(`${NS}.eligible`)}</span>
                      ) : (
                        <span className="text-[10px] font-mono uppercase text-white/40">{t(`${NS}.ineligible`)}</span>
                      )}
                      {blind && (
                        <span className="text-[10px] font-mono uppercase text-rose-300">{t(`${NS}.blind_spot`)}</span>
                      )}
                      {f.xdr_had_matching_alert === true && (
                        <span className="text-[10px] font-mono uppercase text-emerald-300">{t(`${NS}.xdr_had`)}</span>
                      )}
                    </div>
                    <div className="text-sm text-white mt-1">{f.title}</div>
                    <div className="text-[10px] font-mono text-white/40 mt-1">
                      {f.target || '—'} · run {f.report_run_id ?? '—'} · {f.cortex_status}
                      {' · '}
                      <Link to={`/findings?q=${q}`} className="underline text-orange-200/80">
                        {t(`${NS}.open_finding`)}
                      </Link>
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </div>
      )}
    </PageShell>
  )
}
