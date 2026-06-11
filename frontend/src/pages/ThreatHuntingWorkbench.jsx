/**
 * Threat Hunting Workbench
 *
 * World-class threat hunting: hunt campaigns, IOC management,
 * hypothesis-driven hunting with YARA-like queries, hunt results.
 * Route: /threat-hunting
 */
import React, { useState, useMemo, useCallback, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import { apiFetch } from '../lib/apiBase'

// ─── Data ─────────────────────────────────────────────────────────────────────

const HUNT_STATUS_META = {
  active:    { labelKey: 'pages.threatHuntingWorkbench.status_active',    color: '#22d3ee' },
  completed: { labelKey: 'pages.threatHuntingWorkbench.status_completed', color: '#4ade80' },
  paused:    { labelKey: 'pages.threatHuntingWorkbench.status_paused',    color: '#f59e0b' },
  queued:    { labelKey: 'pages.threatHuntingWorkbench.status_queued',    color: '#8b5cf6' },
}

function normalizeCampaign(raw, t) {
  return {
    id: raw.id ?? '',
    title: raw.title ?? t('pages.threatHuntingWorkbench.untitled_hunt'),
    hypothesis: raw.hypothesis ?? '',
    status: raw.status ?? 'queued',
    analyst: raw.analyst ?? t('pages.threatHuntingWorkbench.unassigned'),
    started: raw.started ?? '—',
    mitre: Array.isArray(raw.mitre) ? raw.mitre : [],
    hitsFound: Number(raw.hitsFound) || 0,
    dataSources: Array.isArray(raw.dataSources) ? raw.dataSources : [],
    priority: raw.priority ?? 'medium',
    color: raw.color ?? '#22d3ee',
  }
}

function normalizeIoc(raw, index) {
  const tags = Array.isArray(raw.tags) ? raw.tags : (raw.source ? [raw.source] : [])
  return {
    id: raw.id ?? `ioc-${index}`,
    type: raw.type ?? 'domain',
    value: raw.value ?? raw.indicator ?? '',
    source: raw.source ?? 'Findings',
    severity: String(raw.severity ?? 'medium').toLowerCase(),
    tags,
    added: raw.added ?? (raw.last_seen ? String(raw.last_seen).slice(0, 10) : '—'),
  }
}

function normalizeQuery(raw, index, t) {
  return {
    id: raw.id ?? `q-${index}`,
    name: raw.name ?? t('pages.threatHuntingWorkbench.untitled_query'),
    datasource: raw.datasource ?? raw.dataSources?.[0] ?? 'Findings',
    language: raw.language ?? 'KQL',
    query: raw.query ?? '',
    mitre: raw.mitre ?? '—',
    hits: Number(raw.hits ?? raw.hitsFound) || 0,
  }
}

const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22d3ee', info: '#6b7280' }
const IOC_TYPE_ICON = { ip: '🌐', domain: '🔗', hash: '#️⃣', email: '✉️', url: '🔍' }

// ─── Sub-components ───────────────────────────────────────────────────────────

function MetricCard({ label, value, sub, color, icon }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl bg-black/40 backdrop-blur border border-white/8 p-4 flex flex-col gap-1"
    >
      <div className="flex items-center gap-2">
        {icon && <span className="text-lg">{icon}</span>}
        <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: `${color}99` }}>{label}</span>
      </div>
      <div className="text-3xl font-bold font-mono" style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] text-white/30 font-mono">{sub}</div>}
    </motion.div>
  )
}

function CampaignCard({ campaign, selected, onSelect, t }) {
  const sm = HUNT_STATUS_META[campaign.status] ?? { labelKey: null, color: '#6b7280' }
  const sc = SEV_COLOR[campaign.priority] ?? '#6b7280'
  const statusLabel = sm.labelKey ? t(sm.labelKey) : campaign.status.toUpperCase()
  return (
    <motion.button
      type="button"
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      onClick={() => onSelect(campaign.id === selected ? null : campaign.id)}
      className="w-full text-left rounded-xl border p-4 transition-all hover:scale-[1.003]"
      style={{
        borderColor: selected === campaign.id ? `${campaign.color}50` : 'rgba(255,255,255,0.07)',
        background: selected === campaign.id ? `${campaign.color}08` : 'rgba(0,0,0,0.3)',
      }}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-[10px] font-mono text-white/30">{campaign.id}</span>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: sm.color, borderColor: `${sm.color}40`, background: `${sm.color}10` }}
            >
              {statusLabel}
            </span>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: sc, borderColor: `${sc}40`, background: `${sc}10` }}
            >
              {campaign.priority}
            </span>
          </div>
          <p className="text-xs font-semibold text-white/85 leading-snug">{campaign.title}</p>
        </div>
        <div className="text-right shrink-0">
          <div className="text-xl font-bold font-mono" style={{ color: campaign.hitsFound > 0 ? '#ef4444' : '#4ade80' }}>
            {campaign.hitsFound}
          </div>
          <div className="text-[9px] font-mono text-white/25">{t('pages.threatHuntingWorkbench.hits')}</div>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {campaign.mitre.map((m) => (
          <span key={m} className="text-[9px] font-mono px-1.5 py-0.5 bg-white/5 border border-white/10 rounded text-white/30">{m}</span>
        ))}
      </div>
    </motion.button>
  )
}

function CampaignDetail({ campaign, t }) {
  if (!campaign) return null
  const sm = HUNT_STATUS_META[campaign.status] ?? { labelKey: null, color: '#6b7280' }
  const statusLabel = sm.labelKey ? t(sm.labelKey) : campaign.status.toUpperCase()
  return (
    <motion.div
      key={campaign.id}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl bg-black/40 backdrop-blur border border-white/10 p-6 space-y-4"
    >
      <div>
        <div className="flex items-center gap-2 flex-wrap mb-1">
          <span className="text-[10px] font-mono text-white/30">{campaign.id}</span>
          <span
            className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
            style={{ color: sm.color, borderColor: `${sm.color}40`, background: `${sm.color}10` }}
          >
            {statusLabel}
          </span>
        </div>
        <h3 className="text-sm font-bold text-white mb-2">{campaign.title}</h3>
        <p className="text-xs text-white/50 leading-relaxed italic">"{campaign.hypothesis}"</p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {[
          { label: t('pages.threatHuntingWorkbench.analyst'), value: campaign.analyst },
          { label: t('pages.threatHuntingWorkbench.started'), value: campaign.started },
          { label: t('pages.threatHuntingWorkbench.hits_found'), value: campaign.hitsFound > 0 ? `🔴 ${campaign.hitsFound}` : '✅ 0' },
          { label: t('pages.threatHuntingWorkbench.data_sources'), value: campaign.dataSources.join(', ') },
        ].map(({ label, value }) => (
          <div key={label} className="rounded-lg bg-black/30 border border-white/8 p-3">
            <div className="text-[9px] font-mono uppercase tracking-widest text-white/25 mb-0.5">{label}</div>
            <div className="text-xs font-semibold text-white/70">{value}</div>
          </div>
        ))}
      </div>
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-white/25 mb-2">{t('pages.threatHuntingWorkbench.mitre_techniques')}</div>
        <div className="flex flex-wrap gap-1.5">
          {campaign.mitre.map((m) => (
            <span
              key={m}
              className="px-2 py-1 rounded text-[10px] font-mono border"
              style={{ background: 'rgba(34,211,238,0.05)', border: '1px solid rgba(34,211,238,0.2)', color: 'rgba(34,211,238,0.7)' }}
            >
              {m}
            </span>
          ))}
        </div>
      </div>
    </motion.div>
  )
}

function QueryCard({ query, t }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <motion.div
      layout
      className="rounded-xl bg-black/40 backdrop-blur border border-white/10 overflow-hidden"
    >
      <button
        type="button"
        onClick={() => setExpanded((p) => !p)}
        className="w-full text-left p-4 flex items-start justify-between gap-3 hover:bg-white/3 transition-colors"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border text-cyan-400 border-cyan-500/30 bg-cyan-950/20 uppercase tracking-widest">
              {query.language}
            </span>
            <span className="text-[9px] font-mono text-white/30 bg-white/5 border border-white/10 px-1.5 py-0.5 rounded">{query.mitre}</span>
          </div>
          <p className="text-xs font-semibold text-white/80">{query.name}</p>
          <div className="text-[10px] font-mono text-white/30 mt-0.5">{query.datasource}</div>
        </div>
        <div className="text-right shrink-0">
          <div className="text-lg font-bold font-mono" style={{ color: query.hits > 0 ? '#ef4444' : '#4ade80' }}>{query.hits}</div>
          <div className="text-[9px] font-mono text-white/25">{t('pages.threatHuntingWorkbench.hits')}</div>
        </div>
      </button>
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4">
              <pre className="bg-black/60 border border-white/10 rounded-lg p-3 text-[10px] font-mono text-green-400/80 overflow-x-auto leading-relaxed whitespace-pre-wrap">
                {query.query}
              </pre>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

function IocTable({ iocs, t }) {
  if (!iocs.length) {
    return (
      <EmptyState
        icon="search"
        title={t('pages.threatHuntingWorkbench.ioc_empty_title')}
        body={t('pages.threatHuntingWorkbench.ioc_empty_body')}
        cta={{ label: t('pages.threatHuntingWorkbench.ioc_view_findings'), to: '/findings' }}
      />
    )
  }
  return (
    <div className="rounded-2xl bg-black/40 backdrop-blur border border-white/10 overflow-hidden">
      <div className="grid grid-cols-[auto_1fr_auto_auto_auto] gap-x-4 px-4 py-2 border-b border-white/8 text-[9px] font-mono uppercase tracking-widest text-white/25">
        <span>{t('pages.threatHuntingWorkbench.col_type')}</span>
        <span>{t('pages.threatHuntingWorkbench.col_indicator')}</span>
        <span>{t('pages.threatHuntingWorkbench.col_source')}</span>
        <span>{t('pages.threatHuntingWorkbench.col_severity')}</span>
        <span>{t('pages.threatHuntingWorkbench.col_added')}</span>
      </div>
      {iocs.map((ioc, i) => {
        const sc = SEV_COLOR[ioc.severity] ?? '#6b7280'
        return (
          <motion.div
            key={ioc.id}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: i * 0.03 }}
            className="grid grid-cols-[auto_1fr_auto_auto_auto] gap-x-4 px-4 py-2.5 border-b border-white/5 hover:bg-white/2 transition-colors items-center"
          >
            <span className="text-sm">{IOC_TYPE_ICON[ioc.type] ?? '?'}</span>
            <div className="min-w-0">
              <code className="text-[11px] font-mono text-white/75 block truncate">{ioc.value}</code>
              <div className="flex gap-1 mt-0.5 flex-wrap">
                {ioc.tags.map((tag) => (
                  <span key={tag} className="text-[8px] font-mono bg-white/5 border border-white/10 px-1 py-0.5 rounded text-white/30">{tag}</span>
                ))}
              </div>
            </div>
            <span className="text-[10px] font-mono text-white/30 whitespace-nowrap">{ioc.source}</span>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest whitespace-nowrap"
              style={{ color: sc, borderColor: `${sc}40`, background: `${sc}10` }}
            >
              {ioc.severity}
            </span>
            <span className="text-[10px] font-mono text-white/25 whitespace-nowrap">{ioc.added}</span>
          </motion.div>
        )
      })}
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ThreatHuntingWorkbench() {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState('campaigns')
  const [campaigns, setCampaigns] = useState([])
  const [iocs, setIocs] = useState([])
  const [queries, setQueries] = useState([])
  const [campaignsLoading, setCampaignsLoading] = useState(true)
  const [campaignsError, setCampaignsError] = useState(null)
  const [selectedCampaign, setSelectedCampaign] = useState(null)

  const loadHuntData = useCallback(async () => {
    try {
      const r = await apiFetch('/api/soc/hunts')
      if (!r.ok) {
        setCampaigns([])
        setIocs([])
        setQueries([])
        setCampaignsError(t('pages.threatHuntingWorkbench.load_error', { status: r.status }))
        return
      }
      const data = await r.json().catch(() => ({}))
      const list = (Array.isArray(data.campaigns) ? data.campaigns : []).map((raw) => normalizeCampaign(raw, t))
      const iocList = (Array.isArray(data.iocs) ? data.iocs : []).map(normalizeIoc)
      const queryList = (Array.isArray(data.queries) ? data.queries : []).map((raw, i) => normalizeQuery(raw, i, t))
      setCampaigns(list)
      setIocs(iocList)
      setQueries(queryList)
      setCampaignsError(null)
      setSelectedCampaign((prev) => {
        if (prev && list.some((c) => c.id === prev)) return prev
        return list[0]?.id ?? null
      })
    } catch (e) {
      setCampaigns([])
      setIocs([])
      setQueries([])
      setCampaignsError(e.message || String(e))
    } finally {
      setCampaignsLoading(false)
    }
  }, [t])

  useEffect(() => {
    loadHuntData()
  }, [loadHuntData])

  const selectedCampaignObj = useMemo(
    () => campaigns.find((c) => c.id === selectedCampaign),
    [campaigns, selectedCampaign],
  )

  const metrics = useMemo(() => {
    const active = campaigns.filter((c) => c.status === 'active').length
    const totalHits = campaigns.reduce((s, c) => s + c.hitsFound, 0)
    const totalIOCs = iocs.length
    const critIOCs = iocs.filter((i) => i.severity === 'critical').length
    return { active, totalHits, totalIOCs, critIOCs }
  }, [campaigns, iocs])

  const tabs = [
    { id: 'campaigns', label: t('pages.threatHuntingWorkbench.tab_campaigns'), count: campaigns.length },
    { id: 'queries',   label: t('pages.threatHuntingWorkbench.tab_queries'),   count: queries.length },
    { id: 'iocs',      label: t('pages.threatHuntingWorkbench.tab_iocs'),    count: iocs.length },
  ]

  return (
    <PageShell
      title={t('pages.threatHuntingWorkbench.title')}
      subtitle={t('pages.threatHuntingWorkbench.subtitle')}
      badge={t('pages.threatHuntingWorkbench.badge')}
      badgeColor="#8b5cf6"
    >
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        <MetricCard label={t('pages.threatHuntingWorkbench.metric_active_hunts')} value={metrics.active} sub={t('pages.threatHuntingWorkbench.metric_active_hunts_sub')} color="#22d3ee" icon="🎯" />
        <MetricCard label={t('pages.threatHuntingWorkbench.metric_total_hits')} value={metrics.totalHits} sub={t('pages.threatHuntingWorkbench.metric_total_hits_sub')} color="#ef4444" icon="🔴" />
        <MetricCard label={t('pages.threatHuntingWorkbench.metric_iocs_tracked')} value={metrics.totalIOCs} sub={t('pages.threatHuntingWorkbench.metric_iocs_tracked_sub')} color="#8b5cf6" icon="🧲" />
        <MetricCard label={t('pages.threatHuntingWorkbench.metric_critical_iocs')} value={metrics.critIOCs} sub={t('pages.threatHuntingWorkbench.metric_critical_iocs_sub')} color="#f97316" icon="⚡" />
      </div>

      <div className="flex gap-2 mb-6 flex-wrap">
        {tabs.map((tab) => (
          <button
            key={tab.id} type="button" onClick={() => setActiveTab(tab.id)}
            className="px-4 py-2 rounded-xl text-xs font-mono border transition-all"
            style={{
              color: activeTab === tab.id ? '#8b5cf6' : 'rgba(255,255,255,0.35)',
              borderColor: activeTab === tab.id ? 'rgba(139,92,246,0.4)' : 'rgba(255,255,255,0.1)',
              background: activeTab === tab.id ? 'rgba(139,92,246,0.1)' : 'transparent',
            }}
          >
            {tab.label}
            <span className="ml-2 text-[9px] opacity-60">({tab.count})</span>
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        {activeTab === 'campaigns' && (
          <motion.div key="campaigns" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">{t('pages.threatHuntingWorkbench.campaigns_heading')}</h2>
            {campaignsLoading ? (
              <p className="text-sm text-white/40 font-mono">{t('pages.threatHuntingWorkbench.loading_campaigns')}</p>
            ) : campaigns.length === 0 ? (
              <div className="rounded-xl border border-white/10 bg-black/30 p-8 text-center">
                <p className="text-sm text-white/40 font-mono">{t('pages.threatHuntingWorkbench.no_campaigns')}</p>
                {campaignsError ? (
                  <p className="text-[11px] text-rose-400/70 font-mono mt-2">{campaignsError}</p>
                ) : (
                  <p className="text-[11px] text-white/25 font-mono mt-2">
                    {t('pages.threatHuntingWorkbench.no_campaigns_hint')}
                  </p>
                )}
              </div>
            ) : (
              <div className="grid lg:grid-cols-[360px_1fr] gap-6">
                <div className="space-y-2">
                  {campaigns.map((c) => (
                    <CampaignCard key={c.id} campaign={c} selected={selectedCampaign} onSelect={setSelectedCampaign} t={t} />
                  ))}
                </div>
                <AnimatePresence mode="wait">
                  {selectedCampaignObj && <CampaignDetail key={selectedCampaignObj.id} campaign={selectedCampaignObj} t={t} />}
                </AnimatePresence>
              </div>
            )}
          </motion.div>
        )}

        {activeTab === 'queries' && (
          <motion.div key="queries" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-3">
            <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">{t('pages.threatHuntingWorkbench.detection_queries_heading')}</h2>
            {queries.length === 0 ? (
              <EmptyState
                icon="search"
                title={t('pages.threatHuntingWorkbench.no_queries_title')}
                body={t('pages.threatHuntingWorkbench.no_queries_body')}
              />
            ) : (
              queries.map((q) => (
                <QueryCard key={q.id} query={q} t={t} />
              ))
            )}
          </motion.div>
        )}

        {activeTab === 'iocs' && (
          <motion.div key="iocs" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">{t('pages.threatHuntingWorkbench.ioc_heading')}</h2>
            <IocTable iocs={iocs} t={t} />
          </motion.div>
        )}
      </AnimatePresence>
    </PageShell>
  )
}
