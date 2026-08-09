import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import { useClientTargetPrefill } from '../hooks/useHubLocalScanParams'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { apiFetch } from '../utils/apiFetch'
import Button from '../components/ui/Button'

const PROBE_IDS = ['log4shell', 'blind_ssrf', 'blind_xss', 'xxe_oob', 'cmd_dns', 'host_ssrf']

const PROBE_META = {
  log4shell: { mitre: 'T1190' },
  blind_ssrf: { mitre: 'T1090' },
  blind_xss: { mitre: 'T1059.007' },
  xxe_oob: { mitre: 'T1190' },
  cmd_dns: { mitre: 'T1059' },
  host_ssrf: { mitre: 'T1090' },
}

function ProbeCard({ probeId, active, onRun, disabled }) {
  const { t } = useTranslation()
  const meta = PROBE_META[probeId] || { mitre: '—' }
  return (
    <div className={`rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border p-5 space-y-3 transition-all ${
      active ? 'border-cyan-500/40 shadow-[0_0_20px_rgba(34,211,238,0.1)]' : 'border-[var(--border-default)] hover:border-[var(--border-strong)]'
    }`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-sm font-semibold text-white">{t(`pages.oastDashboard.probes.${probeId}.label`)}</h3>
            {active && (
              <span className="relative flex w-2 h-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
              </span>
            )}
          </div>
          <span className="text-[9px] font-mono text-[var(--text-disabled)] bg-[var(--row-hover-bg)] px-1.5 py-0.5 rounded border border-[var(--border-default)]">
            {meta.mitre}
          </span>
        </div>
        <Button variant="unstyled"
          type="button"
          onClick={() => onRun(probeId)}
          disabled={disabled}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border border-cyan-500/30 text-cyan-300/70 hover:bg-cyan-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {active ? t('pages.oastDashboard.running') : t('pages.oastDashboard.probe_btn')}
        </Button>
      </div>
      <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">{t(`pages.oastDashboard.probes.${probeId}.description`)}</p>
    </div>
  )
}

export default function OastDashboard() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [callbacks, setCallbacks] = useState([])
  const [activeProbes, setActiveProbes] = useState(new Set())
  const [toast, setToast] = useState(null)
  const [callbacksInitialLoading, setCallbacksInitialLoading] = useState(true)
  const [refreshLoading, setRefreshLoading] = useState(false)

  const [mintTarget, setMintTarget] = useState('')
  const [mintProbeType, setMintProbeType] = useState('log4shell')
  const [mintLabel, setMintLabel] = useState('')
  const [mintLoading, setMintLoading] = useState(false)
  const [mintedTokens, setMintedTokens] = useState([])

  useEffect(() => {
    apiFetch('/api/clients')
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
      .catch(() => {})
  }, [])

  useClientTargetPrefill(selectedClientId, clients, setMintTarget)

  const reloadCallbacks = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setRefreshLoading(true)
    try {
      const d = await apiFetch('/api/oast/callbacks')
      const list = Array.isArray(d?.callbacks)
        ? d.callbacks
        : (Array.isArray(d) ? d : [])
      setCallbacks(list.slice(0, 50))
    } catch { /* best-effort; non-fatal */ }
    finally {
      if (!silent) setRefreshLoading(false)
      setCallbacksInitialLoading(false)
    }
  }, [])

  useEffect(() => {
    reloadCallbacks({ silent: true })
  }, [reloadCallbacks])
  // Hidden-tab-aware: pause the 5s OAST callback poll while the tab is backgrounded.
  useVisiblePolling(() => reloadCallbacks({ silent: true }), 5000)

  const listFindings = useMemo(() => callbacks.map((cb, i) => {
    const confirmed = cb.probe_confirmed ?? cb.confirmed ?? false
    return {
      id: cb.id ?? i,
      severity: confirmed ? 'critical' : 'info',
      title: `${cb.probe_type ?? 'unknown'} — ${cb.source_ip ?? '—'}`,
      description: cb.payload ?? '',
      type: cb.probe_type,
    }
  }), [callbacks])

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'oast-callbacks',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description}`,
  })

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((prev) => (prev?.id === id ? null : prev)), 5000)
  }, [])

  const handleProbe = useCallback(async (probeId) => {
    if (!selectedClientId) {
      showToast('error', t('pages.oastDashboard.select_client_first'))
      return
    }
    setActiveProbes((prev) => new Set([...prev, probeId]))
    try {
      const { ok, data: d } = await postScan({
        engine: 'oast_oob',
        client_id: Number(selectedClientId),
        probe_type: probeId,
      })
      if (!ok) {
        showToast('error', d.detail || t('pages.oastDashboard.probe_failed'))
        return
      }
      showToast('info', t('pages.oastDashboard.probe_queued', { jobId: d.job_id ?? '' }))
    } catch (e) {
      showToast('error', e?.message ?? t('pages.oastDashboard.network_error'))
    } finally {
      setTimeout(() => {
        setActiveProbes((prev) => { const s = new Set(prev); s.delete(probeId); return s })
      }, 10000)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClientId, showToast, t])

  const handleMintToken = useCallback(async () => {
    if (!mintTarget) return
    setMintLoading(true)
    try {
      const data = await apiFetch('/api/oast/probe', {
        method: 'POST',
        body: {
          target_url: mintTarget,
          probe_type: mintProbeType,
          label: mintLabel || undefined,
          client_id: selectedClientId ? Number(selectedClientId) : undefined,
        },
      })
      setMintedTokens((prev) => [data, ...prev])
      setMintTarget('')
      setMintLabel('')
      showToast('info', t('pages.oastDashboard.mint_success', { domain: data.callback_domain }))
    } catch (e) {
      showToast('error', t('pages.oastDashboard.mint_failed', { message: e.message }))
    } finally {
      setMintLoading(false)
    }
  }, [mintTarget, mintProbeType, mintLabel, selectedClientId, showToast, t])

  const handlePollToken = useCallback(async (token) => {
    try {
      const data = await apiFetch(`/api/oast/verify/${token}`)
      setMintedTokens((prev) => prev.map((tok) => (tok.token === token ? { ...tok, ...data } : tok)))
    } catch (e) {
      showToast('error', t('pages.oastDashboard.poll_failed', { message: e.message }))
    }
  }, [showToast, t])

  const probeLabel = (id) => {
    if (id === 'generic') return t('pages.oastDashboard.probe_generic')
    return t(`pages.oastDashboard.probes.${id}.label`, { defaultValue: id })
  }

  return (
    <PageShell
      title={t('pages.oastDashboard.title')}
      badge={t('pages.oastDashboard.badge')}
      badgeColor="#22d3ee"
      subtitle={t('pages.oastDashboard.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={() => reloadCallbacks()}
          onExport={exportCsv}
          refreshLoading={refreshLoading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="mb-6 rounded-xl border border-cyan-500/20 bg-cyan-950/20 px-4 py-3 text-[11px] font-mono text-cyan-200/80 leading-relaxed">
        {t('pages.oastDashboard.verification_banner')}
      </div>

      <div className="flex items-center gap-2 mb-8">
        <span className="text-[11px] font-mono text-[var(--text-muted)]">{t('pages.oastDashboard.client')}</span>
        <select
          value={selectedClientId ?? ''}
          onChange={(e) => setSelectedClientId(e.target.value || null)}
          className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40"
        >
          <option value="">{t('pages.oastDashboard.select_client')}</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-cyan-500/30 text-cyan-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="space-y-4">
          <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">{t('pages.oastDashboard.oob_probes')}</h3>
          <div className="space-y-4">
            {PROBE_IDS.map((probeId) => (
              <ProbeCard
                key={probeId}
                probeId={probeId}
                active={activeProbes.has(probeId)}
                onRun={handleProbe}
                disabled={!selectedClientId}
              />
            ))}
          </div>
        </div>

        <div className="space-y-4">
          <WeissmanFindingsPanel
            findings={listFindings}
            filteredFindings={filteredFindings}
            counts={counts}
            total={total}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            loading={callbacksInitialLoading && !listFindings.length}
            accent="#22d3ee"
          />
        </div>
      </div>

      <div className="mt-12 space-y-4">
        <div>
          <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">{t('pages.oastDashboard.structured_tokens')}</h3>
          <p className="text-[11px] text-[var(--text-disabled)] mt-1">{t('pages.oastDashboard.structured_body')}</p>
        </div>

        <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4">
          <h4 className="text-[11px] font-mono text-[var(--text-muted)] uppercase">{t('pages.oastDashboard.mint_new')}</h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input
              type="text"
              placeholder={t('pages.oastDashboard.target_placeholder')}
              value={mintTarget}
              onChange={(e) => setMintTarget(e.target.value)}
              className="rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-3 py-2 text-[12px] text-[var(--text-secondary)] placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
            />
            <select
              value={mintProbeType}
              onChange={(e) => setMintProbeType(e.target.value)}
              className="rounded-xl bg-[var(--scrim)] border border-[var(--border-default)] px-3 py-2 text-[12px] text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40"
            >
              {PROBE_IDS.map((id) => <option key={id} value={id}>{probeLabel(id)}</option>)}
              <option value="generic">{t('pages.oastDashboard.probe_generic')}</option>
            </select>
            <input
              type="text"
              placeholder={t('pages.oastDashboard.label_optional')}
              value={mintLabel}
              onChange={(e) => setMintLabel(e.target.value)}
              className="rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-3 py-2 text-[12px] text-[var(--text-secondary)] placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
            />
            <Button variant="unstyled"
              type="button"
              disabled={!mintTarget || mintLoading}
              onClick={handleMintToken}
              className="rounded-xl border border-cyan-500/30 text-cyan-300/70 text-[12px] font-mono uppercase px-4 py-2 hover:bg-cyan-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {mintLoading ? t('pages.oastDashboard.minting') : t('pages.oastDashboard.mint_token')}
            </Button>
          </div>
        </div>

        {mintedTokens.length > 0 && (
          <div className="space-y-3">
            {mintedTokens.map((tok) => (
              <motion.div
                key={tok.token}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-4 space-y-2"
              >
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="space-y-0.5 min-w-0">
                    <p className="text-[11px] font-mono text-cyan-400/80 break-all">{tok.token}</p>
                    <p className="text-[10px] text-[var(--text-disabled)]">{probeLabel(tok.probe_type)} · {tok.target_url}</p>
                    {tok.label && <p className="text-[10px] text-[var(--text-disabled)] italic">{tok.label}</p>}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                      tok.oob_confirmed
                        ? 'border-green-500/30 text-green-400 bg-green-900/10'
                        : 'border-[var(--border-default)] text-[var(--text-disabled)]'
                    }`}>
                      {tok.oob_confirmed
                        ? t('pages.oastDashboard.hit_confirmed')
                        : t('pages.oastDashboard.hits_count', { count: tok.hit_count ?? 0 })}
                    </span>
                    <Button variant="unstyled"
                      type="button"
                      onClick={() => handlePollToken(tok.token)}
                      className="text-[10px] font-mono border border-[var(--border-default)] text-[var(--text-disabled)] hover:text-[var(--text-tertiary)] hover:border-[var(--border-strong)] px-2 py-0.5 rounded transition-all"
                    >
                      {t('pages.oastDashboard.poll')}
                    </Button>
                  </div>
                </div>
                <p className="text-[10px] font-mono text-[var(--text-disabled)]">
                  {t('pages.oastDashboard.callback_label')}{' '}
                  <code className="text-cyan-400/50">{tok.callback_domain ?? '—'}</code>
                </p>
                {tok.first_hit_at && (
                  <p className="text-[10px] text-green-400/70">
                    {t('pages.oastDashboard.first_hit', { time: new Date(tok.first_hit_at).toLocaleString() })}
                  </p>
                )}
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </PageShell>
  )
}
