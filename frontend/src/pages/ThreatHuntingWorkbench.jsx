/**
 * Threat Hunting Workbench
 *
 * World-class threat hunting: hunt campaigns, IOC management,
 * hypothesis-driven hunting with YARA-like queries, hunt results.
 * Route: /threat-hunting
 */
import React, { useState, useMemo, useCallback, useEffect } from 'react'
<<<<<<< HEAD
import { useTranslation } from 'react-i18next'
=======
>>>>>>> origin/main
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

// ─── Constants ────────────────────────────────────────────────────────────────

const HUNT_STATUS_META = {
  active:    { label: 'ACTIVE',    color: '#22d3ee' },
  completed: { label: 'COMPLETED', color: '#4ade80' },
  paused:    { label: 'PAUSED',    color: '#f59e0b' },
  queued:    { label: 'QUEUED',    color: '#8b5cf6' },
}

<<<<<<< HEAD
function normalizeCampaign(raw) {
  return {
    id: raw.id ?? '',
    title: raw.title ?? 'Untitled hunt',
    hypothesis: raw.hypothesis ?? '',
    status: raw.status ?? 'queued',
    analyst: raw.analyst ?? 'Unassigned',
    started: raw.started ?? '—',
    mitre: Array.isArray(raw.mitre) ? raw.mitre : [],
    hitsFound: Number(raw.hitsFound) || 0,
    dataSources: Array.isArray(raw.dataSources) ? raw.dataSources : [],
    priority: raw.priority ?? 'medium',
    color: raw.color ?? '#22d3ee',
  }
}
=======
// Fallback campaigns when API is unavailable
const FALLBACK_CAMPAIGNS = [
  {
    id: 'hunt-007',
    title: 'Living-off-the-land Binaries (LOLBins) Abuse',
    hypothesis: 'Attackers are using signed Windows binaries (certutil, mshta, wscript) to download and execute payloads, evading AV.',
    status: 'active',
    analyst: 'T. Reyes',
    started: '2026-04-19',
    mitre: ['T1218', 'T1059.005', 'T1140'],
    hitsFound: 14,
    dataSources: ['EDR', 'Windows Event Logs', 'Sysmon'],
    priority: 'high',
    color: '#22d3ee',
  },
  {
    id: 'hunt-006',
    title: 'Kerberoasting & AS-REP Roasting Detection',
    hypothesis: 'Privilege escalation via service account SPN enumeration and offline hash cracking (Kerberoasting) is active in AD environment.',
    status: 'completed',
    analyst: 'M. Kaplan',
    started: '2026-04-15',
    mitre: ['T1558.003', 'T1558.004'],
    hitsFound: 3,
    dataSources: ['AD Security Logs', 'SIEM', 'Zeek'],
    priority: 'critical',
    color: '#4ade80',
  },
  {
    id: 'hunt-005',
    title: 'DNS Tunneling for C2 Communication',
    hypothesis: 'Threat actors are using DNS TXT/A record queries to exfiltrate data and receive C2 commands, bypassing network controls.',
    status: 'active',
    analyst: 'S. Park',
    started: '2026-04-18',
    mitre: ['T1071.004', 'T1041'],
    hitsFound: 7,
    dataSources: ['DNS Logs', 'NetFlow', 'Zeek'],
    priority: 'high',
    color: '#22d3ee',
  },
  {
    id: 'hunt-004',
    title: 'Scheduled Task Persistence via SYSTEM Context',
    hypothesis: 'Malware is creating scheduled tasks running as SYSTEM to maintain persistence after reboot.',
    status: 'paused',
    analyst: 'A. Cohen',
    started: '2026-04-10',
    mitre: ['T1053.005', 'T1547'],
    hitsFound: 0,
    dataSources: ['Windows Event Logs', 'EDR'],
    priority: 'medium',
    color: '#f59e0b',
  },
  {
    id: 'hunt-003',
    title: 'Cloud Metadata Service Abuse (SSRF → IMDS)',
    hypothesis: 'SSRF vulnerabilities in cloud workloads are being used to access AWS/GCP IMDS, leaking IAM credentials.',
    status: 'queued',
    analyst: 'Unassigned',
    started: '—',
    mitre: ['T1552.005', 'T1190'],
    hitsFound: 0,
    dataSources: ['CloudTrail', 'VPC Flow Logs', 'WAF'],
    priority: 'high',
    color: '#8b5cf6',
  },
]
>>>>>>> origin/main

const IOC_LIST = [
  { id: 'ioc-1',  type: 'ip',     value: '185.220.101.45',                  source: 'Threat Intel Feed', severity: 'critical', tags: ['tor-exit', 'c2'], added: '2026-04-20' },
  { id: 'ioc-2',  type: 'domain', value: 'update-service[.]xyz',            source: 'Hunt-007',          severity: 'high',     tags: ['c2', 'lolbin'],   added: '2026-04-19' },
  { id: 'ioc-3',  type: 'hash',   value: '7a9c2f5b3d8e1f4c9b6a0d3e2c8f1a5b', source: 'EDR Alert',        severity: 'critical', tags: ['ransomware'],     added: '2026-04-19' },
  { id: 'ioc-4',  type: 'email',  value: 'noreply@update-service[.]xyz',    source: 'Phishing Report',   severity: 'medium',   tags: ['phishing'],       added: '2026-04-18' },
  { id: 'ioc-5',  type: 'url',    value: 'https://cdn-fast[.]cc/stage2.ps1', source: 'Hunt-005',         severity: 'high',     tags: ['c2', 'powershell'], added: '2026-04-18' },
  { id: 'ioc-6',  type: 'ip',     value: '91.108.4.199',                    source: 'Threat Intel Feed', severity: 'high',     tags: ['scanning'],       added: '2026-04-17' },
  { id: 'ioc-7',  type: 'hash',   value: 'e3b0c44298fc1c149afbf4c8996fb924', source: 'Hunt-006',         severity: 'medium',   tags: ['kerberoasting'],  added: '2026-04-16' },
  { id: 'ioc-8',  type: 'domain', value: 'evil-cert-check[.]com',           source: 'Hunt-007',         severity: 'high',     tags: ['lolbin', 'certutil'], added: '2026-04-16' },
]

const HUNT_QUERIES = [
  {
    id: 'q-1',
    name: 'LOLBin Download via certutil',
    datasource: 'Windows Event Logs (Sysmon)',
    language: 'KQL',
    query: `DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("urlcache", "verifyctl", "-decode")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName`,
    mitre: 'T1218.003',
    hits: 9,
  },
  {
    id: 'q-2',
    name: 'DNS Query Entropy Spike',
    datasource: 'Zeek / DNS Logs',
    language: 'SPL',
    query: `index=zeek sourcetype=dns
| eval domain_len=len(query)
| where domain_len > 60 AND query_type="TXT"
| stats count by src_ip, query
| where count > 50
| sort -count`,
    mitre: 'T1071.004',
    hits: 4,
  },
  {
    id: 'q-3',
    name: 'Kerberoasting — TGS Request Spike',
    datasource: 'Windows Security Logs',
    language: 'KQL',
    query: `SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| summarize count() by AccountName, IpAddress, bin(TimeGenerated, 5m)
| where count_ > 5`,
    mitre: 'T1558.003',
    hits: 3,
  },
]

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

function CampaignCard({ campaign, selected, onSelect }) {
  const sm = HUNT_STATUS_META[campaign.status] ?? { label: campaign.status.toUpperCase(), color: '#6b7280' }
  const sc = SEV_COLOR[campaign.priority] ?? '#6b7280'
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
              {sm.label}
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
          <div className="text-[9px] font-mono text-white/25">hits</div>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {campaign.mitre.map((t) => (
          <span key={t} className="text-[9px] font-mono px-1.5 py-0.5 bg-white/5 border border-white/10 rounded text-white/30">{t}</span>
        ))}
      </div>
    </motion.button>
  )
}

function CampaignDetail({ campaign }) {
  if (!campaign) return null
  const sm = HUNT_STATUS_META[campaign.status] ?? { label: campaign.status.toUpperCase(), color: '#6b7280' }
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
            {sm.label}
          </span>
        </div>
        <h3 className="text-sm font-bold text-white mb-2">{campaign.title}</h3>
        <p className="text-xs text-white/50 leading-relaxed italic">"{campaign.hypothesis}"</p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {[
          { label: 'Analyst',      value: campaign.analyst },
          { label: 'Started',      value: campaign.started },
          { label: 'Hits Found',   value: campaign.hitsFound > 0 ? `🔴 ${campaign.hitsFound}` : '✅ 0' },
          { label: 'Data Sources', value: campaign.dataSources.join(', ') },
        ].map(({ label, value }) => (
          <div key={label} className="rounded-lg bg-black/30 border border-white/8 p-3">
            <div className="text-[9px] font-mono uppercase tracking-widest text-white/25 mb-0.5">{label}</div>
            <div className="text-xs font-semibold text-white/70">{value}</div>
          </div>
        ))}
      </div>
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-white/25 mb-2">MITRE ATT&amp;CK Techniques</div>
        <div className="flex flex-wrap gap-1.5">
          {campaign.mitre.map((t) => (
            <span
              key={t}
              className="px-2 py-1 rounded text-[10px] font-mono border"
              style={{ background: 'rgba(34,211,238,0.05)', border: '1px solid rgba(34,211,238,0.2)', color: 'rgba(34,211,238,0.7)' }}
            >
              {t}
            </span>
          ))}
        </div>
      </div>
    </motion.div>
  )
}

function QueryCard({ query }) {
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
          <div className="text-[9px] font-mono text-white/25">hits</div>
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

function IocTable({ iocs }) {
  return (
    <div className="rounded-2xl bg-black/40 backdrop-blur border border-white/10 overflow-hidden">
      <div className="grid grid-cols-[auto_1fr_auto_auto_auto] gap-x-4 px-4 py-2 border-b border-white/8 text-[9px] font-mono uppercase tracking-widest text-white/25">
        <span>Type</span>
        <span>Indicator</span>
        <span>Source</span>
        <span>Severity</span>
        <span>Added</span>
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
                {ioc.tags.map((t) => (
                  <span key={t} className="text-[8px] font-mono bg-white/5 border border-white/10 px-1 py-0.5 rounded text-white/30">{t}</span>
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
<<<<<<< HEAD
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState('campaigns') // 'campaigns' | 'queries' | 'iocs'
  const [campaigns, setCampaigns] = useState([])
  const [campaignsLoading, setCampaignsLoading] = useState(true)
  const [campaignsError, setCampaignsError] = useState(null)
  const [selectedCampaign, setSelectedCampaign] = useState(null)

  const loadCampaigns = useCallback(async () => {
    try {
      const r = await apiFetch('/api/soc/hunts')
      if (!r.ok) {
        setCampaigns([])
        setCampaignsError(`Couldn't load hunts (HTTP ${r.status})`)
        return
      }
      const data = await r.json().catch(() => ({}))
      const list = (Array.isArray(data.campaigns) ? data.campaigns : []).map(normalizeCampaign)
      setCampaigns(list)
      setCampaignsError(null)
      setSelectedCampaign((prev) => {
        if (prev && list.some((c) => c.id === prev)) return prev
        return list[0]?.id ?? null
      })
    } catch (e) {
      setCampaigns([])
      setCampaignsError(e.message || String(e))
    } finally {
      setCampaignsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadCampaigns()
  }, [loadCampaigns])

  const selectedCampaignObj = useMemo(
    () => campaigns.find((c) => c.id === selectedCampaign),
    [campaigns, selectedCampaign],
  )

  const metrics = useMemo(() => {
    const active = campaigns.filter((c) => c.status === 'active').length
    const totalHits = campaigns.reduce((s, c) => s + c.hitsFound, 0)
    const totalIOCs = IOC_LIST.length
    const critIOCs = IOC_LIST.filter((i) => i.severity === 'critical').length
    return { active, totalHits, totalIOCs, critIOCs }
  }, [campaigns])
=======
  const [campaigns, setCampaigns] = useState([])
  const [iocs, setIocs] = useState([])
  const [queries, setQueries] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('campaigns') // 'campaigns' | 'queries' | 'iocs'
  const [selectedCampaign, setSelectedCampaign] = useState(null)

  // Load data from API
  useEffect(() => {
    const loadData = async () => {
      setLoading(true)
      setError(null)

      try {
        // Fetch hunt campaigns
        const campaignsRes = await apiFetch('/api/threat-hunting/campaigns')
        if (campaignsRes.ok) {
          const campaignsData = await campaignsRes.json()
          const campaignsArray = Array.isArray(campaignsData) ? campaignsData : campaignsData.campaigns || []
          setCampaigns(campaignsArray)
          if (campaignsArray.length > 0) {
            setSelectedCampaign(campaignsArray[0].id)
          }
        } else if (campaignsRes.status === 404) {
          // API not implemented, use fallback
          setCampaigns(FALLBACK_CAMPAIGNS)
          setSelectedCampaign(FALLBACK_CAMPAIGNS[0].id)
        } else {
          throw new Error(`Failed to load campaigns (HTTP ${campaignsRes.status})`)
        }

        // Fetch IOCs
        const iocsRes = await apiFetch('/api/threat-hunting/iocs')
        if (iocsRes.ok) {
          const iocsData = await iocsRes.json()
          setIocs(Array.isArray(iocsData) ? iocsData : iocsData.iocs || [])
        } else if (iocsRes.status === 404) {
          setIocs(IOC_LIST)
        } else {
          throw new Error(`Failed to load IOCs (HTTP ${iocsRes.status})`)
        }

        // Fetch hunt queries
        const queriesRes = await apiFetch('/api/threat-hunting/queries')
        if (queriesRes.ok) {
          const queriesData = await queriesRes.json()
          setQueries(Array.isArray(queriesData) ? queriesData : queriesData.queries || [])
        } else if (queriesRes.status === 404) {
          setQueries(HUNT_QUERIES)
        } else {
          throw new Error(`Failed to load queries (HTTP ${queriesRes.status})`)
        }
      } catch (err) {
        setError(err?.message || 'Failed to load threat hunting data')
        // Use fallback data on error
        setCampaigns(FALLBACK_CAMPAIGNS)
        setSelectedCampaign(FALLBACK_CAMPAIGNS[0].id)
        setIocs(IOC_LIST)
        setQueries(HUNT_QUERIES)
      } finally {
        setLoading(false)
      }
    }

    loadData()
  }, [])
>>>>>>> origin/main

  const selectedCampaignObj = useMemo(() => campaigns.find((c) => c.id === selectedCampaign), [selectedCampaign, campaigns])

  const metrics = useMemo(() => {
    const active = campaigns.filter((c) => c.status === 'active').length
    const totalHits = campaigns.reduce((s, c) => s + c.hitsFound, 0)
    const totalIOCs = iocs.length
    const critIOCs = iocs.filter((i) => i.severity === 'critical').length
    return { active, totalHits, totalIOCs, critIOCs }
  }, [campaigns, iocs])

  const tabs = [
    { id: 'campaigns', label: '🎯 Hunt Campaigns', count: campaigns.length },
<<<<<<< HEAD
    { id: 'queries',   label: '🔎 Hunt Queries',   count: HUNT_QUERIES.length },
    { id: 'iocs',      label: '🧲 IOC Library',    count: IOC_LIST.length },
=======
    { id: 'queries',   label: '🔎 Hunt Queries',   count: queries.length },
    { id: 'iocs',      label: '🧲 IOC Library',    count: iocs.length },
>>>>>>> origin/main
  ]

  return (
    <PageShell
      title={t('pages.threatHuntingWorkbench.title')}
      subtitle={t('pages.threatHuntingWorkbench.subtitle')}
      badge="HUNT"
      badgeColor="#8b5cf6"
    >
      {/* ── Error Banner ── */}
      {error && (
        <div className="mb-6 rounded-xl border border-amber-500/30 bg-amber-950/20 px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="text-amber-400 text-sm">⚠️</span>
            <span className="text-xs font-mono text-amber-300/80">{error}</span>
            <span className="text-[10px] text-amber-300/50 ml-auto">Using demo data</span>
          </div>
        </div>
      )}

      {/* ── Loading State ── */}
      {loading && (
        <div className="flex items-center justify-center py-20">
          <div className="text-center space-y-3">
            <div className="w-8 h-8 border-2 border-purple-500/40 border-t-purple-500 rounded-full animate-spin mx-auto" />
            <p className="text-sm font-mono text-white/40">Loading threat hunting data...</p>
          </div>
        </div>
      )}

      {/* ── Metrics ──────────────────────────────────────────────────────── */}
      {!loading && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
          <MetricCard label="Active Hunts"    value={metrics.active}    sub="Currently executing"      color="#22d3ee" icon="🎯" />
          <MetricCard label="Total Hits"      value={metrics.totalHits} sub="Across all campaigns"     color="#ef4444" icon="🔴" />
          <MetricCard label="IOCs Tracked"    value={metrics.totalIOCs} sub="Active indicators"        color="#8b5cf6" icon="🧲" />
          <MetricCard label="Critical IOCs"   value={metrics.critIOCs}  sub="Immediate action needed"  color="#f97316" icon="⚡" />
        </div>
      )}

      {/* ── Tabs ─────────────────────────────────────────────────────────── */}
      {!loading && (
        <div className="flex gap-2 mb-6 flex-wrap">
          {tabs.map((t) => (
            <button
              key={t.id} type="button" onClick={() => setActiveTab(t.id)}
              className="px-4 py-2 rounded-xl text-xs font-mono border transition-all"
              style={{
                color: activeTab === t.id ? '#8b5cf6' : 'rgba(255,255,255,0.35)',
                borderColor: activeTab === t.id ? 'rgba(139,92,246,0.4)' : 'rgba(255,255,255,0.1)',
                background: activeTab === t.id ? 'rgba(139,92,246,0.1)' : 'transparent',
              }}
            >
              {t.label}
              <span className="ml-2 text-[9px] opacity-60">({t.count})</span>
            </button>
          ))}
        </div>
      )}

      {/* ── Content ──────────────────────────────────────────────────────── */}
<<<<<<< HEAD
      <AnimatePresence mode="wait">
        {activeTab === 'campaigns' && (
          <motion.div key="campaigns" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">Hunt Campaigns</h2>
            {campaignsLoading ? (
              <p className="text-sm text-white/40 font-mono">{t('pages.threatHuntingWorkbench.loading_campaigns')}</p>
            ) : campaigns.length === 0 ? (
              <div className="rounded-xl border border-white/10 bg-black/30 p-8 text-center">
                <p className="text-sm text-white/40 font-mono">{t('pages.threatHuntingWorkbench.no_campaigns')}</p>
                {campaignsError ? (
                  <p className="text-[11px] text-rose-400/70 font-mono mt-2">{campaignsError}</p>
                ) : (
                  <p className="text-[11px] text-white/25 font-mono mt-2">
                    Campaigns appear when correlated finding clusters are detected from scan data.
                  </p>
                )}
              </div>
            ) : (
              <div className="grid lg:grid-cols-[360px_1fr] gap-6">
                <div className="space-y-2">
                  {campaigns.map((c) => (
                    <CampaignCard key={c.id} campaign={c} selected={selectedCampaign} onSelect={setSelectedCampaign} />
                  ))}
                </div>
                <AnimatePresence mode="wait">
                  {selectedCampaignObj && <CampaignDetail key={selectedCampaignObj.id} campaign={selectedCampaignObj} />}
                </AnimatePresence>
              </div>
            )}
          </motion.div>
        )}
=======
      {!loading && (
        <AnimatePresence mode="wait">
          {activeTab === 'campaigns' && (
            <motion.div key="campaigns" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              {campaigns.length === 0 ? (
                <div className="rounded-2xl border border-white/10 bg-black/20 p-12 text-center">
                  <p className="text-sm text-white/40">No hunt campaigns found</p>
                </div>
              ) : (
                <div className="grid lg:grid-cols-[360px_1fr] gap-6">
                  <div className="space-y-2">
                    <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">Hunt Campaigns</h2>
                    {campaigns.map((c) => (
                      <CampaignCard key={c.id} campaign={c} selected={selectedCampaign} onSelect={setSelectedCampaign} />
                    ))}
                  </div>
                  <AnimatePresence mode="wait">
                    {selectedCampaignObj && <CampaignDetail key={selectedCampaignObj.id} campaign={selectedCampaignObj} />}
                  </AnimatePresence>
                </div>
              )}
            </motion.div>
          )}
>>>>>>> origin/main

          {activeTab === 'queries' && (
            <motion.div key="queries" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-3">
              <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">Detection Queries</h2>
              {queries.length === 0 ? (
                <div className="rounded-2xl border border-white/10 bg-black/20 p-12 text-center">
                  <p className="text-sm text-white/40">No detection queries found</p>
                </div>
              ) : (
                queries.map((q) => (
                  <QueryCard key={q.id} query={q} />
                ))
              )}
            </motion.div>
          )}

          {activeTab === 'iocs' && (
            <motion.div key="iocs" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">Indicators of Compromise</h2>
              {iocs.length === 0 ? (
                <div className="rounded-2xl border border-white/10 bg-black/20 p-12 text-center">
                  <p className="text-sm text-white/40">No IOCs found</p>
                </div>
              ) : (
                <IocTable iocs={iocs} />
              )}
            </motion.div>
          )}
        </AnimatePresence>
      )}
    </PageShell>
  )
}
