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
  const [flushing, setFlushing] = useState(false)
  const [comparing, setComparing] = useState(false)
  const [flushMsg, setFlushMsg] = useState('')

  const qs = useMemo(() => {
    const p = new URLSearchParams()
    if (selectedClientId) p.set('client_id', String(selectedClientId))
    p.set('limit', '300')
    return p.toString()
  }, [selectedClientId])

  const load = useCallback(async (compareXdr = false) => {
    setLoading(true)
    setError('')
    try {
      const extra = compareXdr ? '&compare_xdr=true' : ''
      const d = await apiFetch(`/api/findings/scan-cortex-bridge?${qs}${extra}`)
      if (d?.ok === false) throw new Error(d.detail || t(`${NS}.load_failed`))
      setData(d)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [qs, t])

  useEffect(() => { load(false) }, [load])

  const items = Array.isArray(data?.items) ? data.items : []
  const counts = data?.counts || {}

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return items
    return items.filter((f) =>
      `${f.title} ${f.source} ${f.engine_id} ${f.target} ${f.gate} ${f.cve || ''} ${f.proof_kind || ''}`
        .toLowerCase()
        .includes(q),
    )
  }, [items, searchQuery])

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
      await load(false)
    } catch (e) {
      setFlushMsg(e.message || t(`${NS}.flush_failed`))
    } finally {
      setFlushing(false)
    }
  }

  const compareLive = async () => {
    setComparing(true)
    try {
      await load(true)
    } finally {
      setComparing(false)
    }
  }

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
            disabled={loading || flushing || !counts.proven_eligible}
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
      {loading ? <SkeletonWidgetGrid count={4} /> : error ? (
        <EmptyState title={t(`${NS}.load_failed`)} body={error} />
      ) : (
        <div className="space-y-4">
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
          {flushMsg && (
            <p role="status" className="text-[11px] font-mono text-orange-200/90">{flushMsg}</p>
          )}
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
