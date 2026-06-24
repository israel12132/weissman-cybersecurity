/**
 * AI Analysis Engine — live patterns from `/api/soc/ai-patterns` with
 * `/api/findings/clusters` and `/api/findings` fallbacks. No fabricated intel.
 */
import React, { useState, useMemo, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import { RefreshCw, Search, Download } from 'lucide-react'
import { apiFetch } from '../lib/apiBase'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonBar, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import CopyButton from '../components/ui/CopyButton'

const CATEGORY_ICONS = {
  cloud_attacks: { color: '#06b6d4', icon: '☁️' },
  supply_chain: { color: '#f97316', icon: '⛓️' },
  identity: { color: '#a78bfa', icon: '🆔' },
  cloud_native: { color: '#34d399', icon: '🐳' },
  web_app: { color: '#f59e0b', icon: '🌐' },
  other: { color: '#94a3b8', icon: '🔍' },
}

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#6b7280',
}

const CATEGORY_RULES = [
  { id: 'cloud_attacks', re: /cloud|aws|azure|gcp|iam|ec2|s3|imds/i },
  { id: 'supply_chain', re: /supply|sbom|dependency|npm|pypi|maven|ci\/?cd/i },
  { id: 'identity', re: /auth|oauth|kerberos|ldap|identity|jwt|saml|ad\b|password/i },
  { id: 'cloud_native', re: /k8s|kubernetes|docker|container|kube|pod/i },
  { id: 'web_app', re: /xss|sqli|ssrf|idor|bola|web|api|http|injection/i },
]

function clusterHaystack(c) {
  return [
    c.title, c.cwe, c.vuln_signature, c.target,
    ...(c.engines || []), ...(c.sources || []), ...(c.cves || []),
  ].join(' ')
}

function deriveCategory(text) {
  const hay = (text || '').toLowerCase()
  const rule = CATEGORY_RULES.find((r) => r.re.test(hay))
  return rule?.id || 'other'
}

function clusterConfidence(c) {
  let score = 0.45
  if (c.max_epss != null) score += Number(c.max_epss) * 0.3
  if (c.max_cvss != null) score += (Number(c.max_cvss) / 10) * 0.2
  if (c.kev_listed) score += 0.15
  if (c.member_count > 1) score += Math.min(0.15, c.member_count * 0.03)
  return Math.min(0.99, score)
}

function findingConfidence(f) {
  let score = 0.4
  if (f.epss_score != null) score += Number(f.epss_score) * 0.3
  if (f.cvss_score) score += (Number(f.cvss_score) / 10) * 0.2
  if (f.kev_listed) score += 0.15
  if (f.seen_count > 1) score += Math.min(0.1, f.seen_count * 0.02)
  if (f.confidence_multiplier) score *= Math.min(1.2, Number(f.confidence_multiplier))
  return Math.min(0.99, score)
}

function clusterToPattern(cluster, members = []) {
  const severity = (cluster.max_severity || 'medium').toLowerCase()
  const mitre = [...new Set(members.map((m) => m.mitre_attack).filter(Boolean))]
  const remediation = members.find((m) => m.remediation)?.remediation || ''
  const descriptions = members.map((m) => m.description).filter(Boolean)
  const indicators = [
    ...(cluster.cves || []),
    cluster.cwe && `CWE: ${cluster.cwe}`,
    cluster.vuln_signature,
    cluster.kev_listed && 'KEV',
    cluster.member_count > 1 && String(cluster.member_count),
  ].filter(Boolean)

  const description = descriptions[0]
    || [cluster.title, cluster.target, cluster.cwe].filter(Boolean).join(' · ')

  return {
    id: `CL-${cluster.id}`,
    clusterId: cluster.id,
    name: cluster.title || cluster.vuln_signature || `Cluster ${cluster.id}`,
    category: deriveCategory(clusterHaystack(cluster)),
    confidence: clusterConfidence(cluster),
    affectedSystems: [...new Set([cluster.target, ...(cluster.engines || []), ...(cluster.sources || [])].filter(Boolean))],
    mitreTechniques: mitre,
    severity,
    description,
    indicators,
    remediation,
    status: cluster.status,
    memberCount: cluster.member_count,
    kevListed: cluster.kev_listed,
    maxEpss: cluster.max_epss,
    maxCvss: cluster.max_cvss,
    lastSeen: cluster.last_seen_at,
    firstSeen: cluster.first_seen_at,
    _raw: cluster,
  }
}

function findingToPattern(f) {
  const severity = (f.severity || 'medium').toLowerCase()
  return {
    id: f.id || `F-${f.raw_id}`,
    clusterId: f.cluster_id,
    name: f.title || 'Finding',
    category: deriveCategory([f.title, f.description, f.source, f.target, f.mitre_attack].join(' ')),
    confidence: findingConfidence(f),
    affectedSystems: [f.target, f.source].filter(Boolean),
    mitreTechniques: f.mitre_attack ? [f.mitre_attack] : [],
    severity,
    description: f.description || f.title,
    indicators: [f.cve || f.cve_id, f.signature_hash, f.kev_listed && 'KEV'].filter(Boolean),
    remediation: f.remediation || '',
    status: f.status,
    memberCount: f.seen_count || 1,
    kevListed: f.kev_listed,
    maxEpss: f.epss_score,
    maxCvss: f.cvss_score,
    lastSeen: f.discovered_at,
    firstSeen: f.discovered_at,
    _raw: f,
  }
}

function socPatternToPattern(p) {
  const severity = (p.severity || 'medium').toLowerCase()
  const source = p.source || ''
  return {
    id: `CL-${p.id}`,
    clusterId: p.id,
    name: p.name || `Pattern ${p.id}`,
    category: deriveCategory(`${p.name || ''} ${source}`),
    confidence: Number(p.confidence) || 0.5,
    affectedSystems: source ? [source] : [],
    mitreTechniques: Array.isArray(p.techniques) ? p.techniques.filter(Boolean) : [],
    severity,
    description: p.name,
    indicators: [p.occurrences > 1 && String(p.occurrences), source].filter(Boolean),
    remediation: '',
    status: 'open',
    memberCount: p.occurrences || 1,
    kevListed: false,
    maxEpss: null,
    maxCvss: null,
    lastSeen: null,
    firstSeen: null,
    _raw: p,
  }
}

function buildCorrelations(patterns) {
  const corrs = []
  for (const p of patterns) {
    const engines = p._raw?.engines || []
    if (engines.length >= 2) {
      corrs.push({
        id: `corr-engines-${p.id}`,
        type: 'multi_engine',
        patternIds: [p.id],
        confidence: Math.min(0.95, p.confidence + 0.08),
        meta: { name: p.name, engines: engines.join(', '), target: p._raw?.target || '—', count: p.memberCount },
        riskMultiplier: Number((1 + Math.min(0.5, (p.memberCount - 1) * 0.08)).toFixed(2)),
        detectedAt: p.lastSeen || null,
      })
    }
  }
  const byTarget = new Map()
  for (const p of patterns) {
    const target = p._raw?.target || p.affectedSystems[0]
    if (!target) continue
    const list = byTarget.get(target) || []
    list.push(p)
    byTarget.set(target, list)
  }
  for (const [target, group] of byTarget) {
    if (group.length < 2) continue
    const avgConf = group.reduce((a, p) => a + p.confidence, 0) / group.length
    const latest = group.map((p) => p.lastSeen).filter(Boolean).sort().pop()
    corrs.push({
      id: `corr-target-${target.replace(/[^a-z0-9]+/gi, '-').slice(0, 40)}`,
      type: 'co_located',
      patternIds: group.map((p) => p.id),
      confidence: Math.min(0.95, avgConf + 0.05),
      meta: { target, count: group.length },
      riskMultiplier: Number((1 + group.length * 0.12).toFixed(2)),
      detectedAt: latest || null,
    })
  }
  return corrs.sort((a, b) => b.confidence - a.confidence).slice(0, 25)
}

async function loadIntelPatterns() {
  const socRes = await apiFetch('/api/soc/ai-patterns')
  if (socRes.ok) {
    const socData = await socRes.json()
    const socPatterns = Array.isArray(socData?.patterns) ? socData.patterns : []
    if (socPatterns.length > 0) {
      return { patterns: socPatterns.map(socPatternToPattern), source: 'soc', total: socPatterns.length }
    }
  }
  const membersByCluster = new Map()
  let findings = []
  let findingsTotal = 0
  let findingsOk = false
  const findingsRes = await apiFetch('/api/findings?limit=2000')
  if (findingsRes.ok) {
    findingsOk = true
    const fd = await findingsRes.json()
    findings = Array.isArray(fd) ? fd : Array.isArray(fd?.findings) ? fd.findings : []
    findingsTotal = fd?.total ?? findings.length
    for (const f of findings) {
      if (!f.cluster_id) continue
      const list = membersByCluster.get(f.cluster_id) || []
      list.push(f)
      membersByCluster.set(f.cluster_id, list)
    }
  }
  const clustersRes = await apiFetch('/api/findings/clusters?limit=500')
  if (clustersRes.ok) {
    const cd = await clustersRes.json()
    const clusters = Array.isArray(cd?.clusters) ? cd.clusters : []
    if (clusters.length > 0) {
      return {
        patterns: clusters.map((c) => clusterToPattern(c, membersByCluster.get(c.id) || [])),
        source: 'clusters',
        total: cd.total ?? clusters.length,
      }
    }
  }
  if (findingsOk) {
    return { patterns: findings.map(findingToPattern), source: 'findings', total: findingsTotal }
  }
  throw new Error(`HTTP ${clustersRes.status}`)
}

function exportPatternsCsv(patterns) {
  const header = ['id', 'name', 'category', 'severity', 'confidence', 'member_count', 'kev', 'last_seen']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...patterns.map((p) =>
      [p.id, p.name, p.category, p.severity, Math.round(p.confidence * 100), p.memberCount, p.kevListed, p.lastSeen].map(esc).join(','),
    ),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `weissman-ai-patterns-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function AIAnalysisEngine() {
  const { t, i18n } = useTranslation()
  const [patterns, setPatterns] = useState([])
  const [correlations, setCorrelations] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [dataSource, setDataSource] = useState(null)
  const [selectedPattern, setSelectedPattern] = useState(null)
  const [filterCategory, setFilterCategory] = useState('all')
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [search, setSearch] = useState('')
  const [activeTab, setActiveTab] = useState('patterns')
  const [lastUpdated, setLastUpdated] = useState(null)

  const categoryLabel = useCallback((id) => {
    const key = {
      cloud_attacks: 'category_cloud',
      supply_chain: 'category_supply',
      identity: 'category_identity',
      cloud_native: 'category_cloud_native',
      web_app: 'category_web',
      other: 'category_other',
    }[id] || 'category_other'
    return t(`pages.aiAnalysisEngine.${key}`)
  }, [t])

  const severityLabel = useCallback((sev) => {
    const s = (sev || 'medium').toLowerCase()
    return t(`pages.aiAnalysisEngine.severity_${s}`, { defaultValue: s.toUpperCase() })
  }, [t])

  const evidenceNotice = useMemo(() => {
    if (dataSource === 'clusters') return t('pages.aiAnalysisEngine.evidence_clusters')
    if (dataSource === 'findings') return t('pages.aiAnalysisEngine.evidence_findings')
    return t('pages.aiAnalysisEngine.evidence_soc')
  }, [dataSource, t])

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const { patterns: loaded, source } = await loadIntelPatterns()
      setPatterns(loaded)
      setCorrelations(buildCorrelations(loaded))
      setDataSource(source)
      setLastUpdated(new Date())
      setSelectedPattern((prev) => {
        if (prev && loaded.some((p) => p.id === prev.id)) return prev
        return loaded[0] || null
      })
    } catch (e) {
      setError(e.message || t('pages.aiAnalysisEngine.load_error'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  const categories = useMemo(() => [...new Set(patterns.map((p) => p.category))].sort(), [patterns])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return patterns.filter((p) => {
      if (filterCategory !== 'all' && p.category !== filterCategory) return false
      if (filterSeverity !== 'all' && p.severity !== filterSeverity) return false
      if (!q) return true
      const hay = [p.name, p.description, p.id, ...p.affectedSystems, ...p.mitreTechniques].join(' ').toLowerCase()
      return hay.includes(q)
    })
  }, [patterns, filterCategory, filterSeverity, search])

  const avgConfidence = useMemo(() => {
    if (!patterns.length) return 0
    return Math.round((patterns.reduce((a, p) => a + p.confidence, 0) / patterns.length) * 100)
  }, [patterns])

  const criticalCount = useMemo(() => patterns.filter((p) => p.severity === 'critical').length, [patterns])

  const corrTitle = (corr) => {
    if (corr.type === 'multi_engine') {
      return t('pages.aiAnalysisEngine.corr_multi_engine_title', { name: corr.meta.name })
    }
    return t('pages.aiAnalysisEngine.corr_co_located_title', { target: corr.meta.target })
  }

  const corrDescription = (corr) => {
    if (corr.type === 'multi_engine') {
      return t('pages.aiAnalysisEngine.corr_multi_engine_body', corr.meta)
    }
    return t('pages.aiAnalysisEngine.corr_co_located_body', corr.meta)
  }

  const listFindings = useMemo(() => filtered.map((p) => ({
    id: p.id,
    severity: p.severity || 'info',
    title: p.name,
    type: p.category || 'pattern',
    description: p.description || '',
  })), [filtered])

  const { exportCsv: exportWorkbenchCsv, filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-ai-patterns',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description}`,
  })

  return (
    <PageShell
      title={t('pages.aiAnalysisEngine.title')}
      subtitle={t('pages.aiAnalysisEngine.subtitle')}
      badge="AI"
      badgeColor="#a78bfa"
      actions={(
        <ShellScanActions
          onRefresh={load}
          onExport={() => exportPatternsCsv(filtered)}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 px-4 py-3 text-[11px] font-mono text-violet-200/80 mb-4 leading-relaxed">
        {evidenceNotice}
      </div>

      {lastUpdated && (
        <p className="text-[11px] font-mono text-white/40 mb-6">
          {t('pages.aiAnalysisEngine.last_updated', { time: lastUpdated.toLocaleTimeString(i18n.language) })}
        </p>
      )}

      {error && (
        <div className="mb-6 p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm">
          {t('pages.aiAnalysisEngine.load_error_detail', { detail: error })}
        </div>
      )}

      {loading && patterns.length === 0 ? (
        <>
          <SkeletonWidgetGrid count={4} />
          <SkeletonBar className="h-96 mt-6" />
        </>
      ) : (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
            {[
              { label: t('pages.aiAnalysisEngine.kpi_patterns'), value: patterns.length, color: '#a78bfa' },
              { label: t('pages.aiAnalysisEngine.kpi_confidence'), value: `${avgConfidence}%`, color: '#10b981' },
              { label: t('pages.aiAnalysisEngine.kpi_correlations'), value: correlations.length, color: '#f97316' },
              { label: t('pages.aiAnalysisEngine.kpi_critical'), value: criticalCount, color: '#ef4444' },
            ].map((kpi) => (
              <div key={kpi.label} className="rounded-2xl border border-white/10 bg-white/5 p-4 text-center">
                <div className="text-2xl font-bold" style={{ color: kpi.color }}>{kpi.value}</div>
                <div className="text-[11px] text-white/50 mt-1">{kpi.label}</div>
              </div>
            ))}
          </div>

          <div className="flex flex-wrap gap-2 mb-6">
            {[
              { id: 'patterns', label: t('pages.aiAnalysisEngine.tab_patterns') },
              { id: 'correlations', label: t('pages.aiAnalysisEngine.tab_correlations') },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2 rounded-xl text-sm font-medium transition-all ${
                  activeTab === tab.id
                    ? 'bg-[#a78bfa]/20 text-[#a78bfa] border border-[#a78bfa]/40'
                    : 'bg-white/5 text-white/50 border border-white/10 hover:bg-white/10'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {activeTab === 'patterns' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="space-y-3">
                <div className="relative mb-3">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30" />
                  <input
                    type="search"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder={t('pages.aiAnalysisEngine.search_placeholder')}
                    className="w-full bg-black/40 border border-white/10 rounded-lg pl-10 pr-3 py-2 text-xs text-white/80 focus:outline-none focus:border-violet-500/40"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <select
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                    className="flex-1 text-xs bg-black/40 border border-white/10 rounded-lg px-2 py-1.5 text-white/60 focus:outline-none"
                  >
                    <option value="all">{t('pages.aiAnalysisEngine.filter_all_categories')}</option>
                    {categories.map((k) => (
                      <option key={k} value={k}>{categoryLabel(k)}</option>
                    ))}
                  </select>
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="flex-1 text-xs bg-black/40 border border-white/10 rounded-lg px-2 py-1.5 text-white/60 focus:outline-none"
                  >
                    <option value="all">{t('pages.aiAnalysisEngine.filter_all_severity')}</option>
                    {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
                      <option key={s} value={s}>{severityLabel(s)}</option>
                    ))}
                  </select>
                </div>

                {!loading && filtered.length === 0 && (
                  <EmptyState
                    icon="🤖"
                    title={t('pages.aiAnalysisEngine.no_patterns_title')}
                    body={t('pages.aiAnalysisEngine.no_patterns_body')}
                    action={(
                      <Link to="/engines" className="text-sm text-violet-400 hover:underline">
                        {t('pages.aiAnalysisEngine.go_engines')}
                      </Link>
                    )}
                  />
                )}

                {filtered.map((pattern) => {
                  const sm = SEVERITY_COLORS[pattern.severity] ?? SEVERITY_COLORS.medium
                  const cm = CATEGORY_ICONS[pattern.category] ?? CATEGORY_ICONS.other
                  return (
                    <motion.button
                      key={pattern.id}
                      layout
                      whileHover={{ scale: 1.01 }}
                      onClick={() => setSelectedPattern(pattern)}
                      className={`w-full text-left rounded-2xl border p-4 transition-all ${
                        selectedPattern?.id === pattern.id
                          ? 'border-[#a78bfa]/50 bg-[#a78bfa]/10'
                          : 'border-white/10 bg-white/5 hover:bg-white/10'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <span>{cm.icon}</span>
                          <span className="text-sm font-semibold text-white truncate">{pattern.name}</span>
                        </div>
                        <span
                          className="text-[10px] font-mono px-2 py-0.5 rounded border flex-shrink-0 ml-2"
                          style={{ color: sm, borderColor: `${sm}40`, backgroundColor: `${sm}10` }}
                        >
                          {severityLabel(pattern.severity)}
                        </span>
                      </div>
                      <div className="flex items-center justify-between mt-2">
                        <span className="text-[11px] text-white/40">{categoryLabel(pattern.category)}</span>
                        <div className="flex items-center gap-1">
                          <div className="w-16 bg-white/10 rounded-full h-1">
                            <div className="h-1 rounded-full bg-emerald-500" style={{ width: `${pattern.confidence * 100}%` }} />
                          </div>
                          <span className="text-[10px] font-mono text-emerald-400">{Math.round(pattern.confidence * 100)}%</span>
                        </div>
                      </div>
                    </motion.button>
                  )
                })}
              </div>

              <div className="lg:col-span-2">
                <AnimatePresence mode="wait">
                  {selectedPattern ? (
                    <motion.div
                      key={selectedPattern.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="rounded-2xl border border-white/15 bg-white/5 p-6 space-y-5"
                    >
                      {(() => {
                        const sm = SEVERITY_COLORS[selectedPattern.severity] ?? SEVERITY_COLORS.medium
                        const cm = CATEGORY_ICONS[selectedPattern.category] ?? CATEGORY_ICONS.other
                        return (
                          <>
                            <div className="flex items-start justify-between gap-4">
                              <div>
                                <div className="flex items-center gap-2 mb-1">
                                  <span className="text-xl">{cm.icon}</span>
                                  <h2 className="text-lg font-bold text-white">{selectedPattern.name}</h2>
                                </div>
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border"
                                    style={{ color: sm, borderColor: `${sm}40`, backgroundColor: `${sm}10` }}>
                                    {severityLabel(selectedPattern.severity)}
                                  </span>
                                  <span className="text-[10px] px-2 py-0.5 rounded border"
                                    style={{ color: cm.color, borderColor: `${cm.color}40`, backgroundColor: `${cm.color}10` }}>
                                    {categoryLabel(selectedPattern.category)}
                                  </span>
                                  <span className="text-[10px] font-mono text-white/40 flex items-center gap-1">
                                    {selectedPattern.id}
                                    <CopyButton value={selectedPattern.id} />
                                  </span>
                                  {selectedPattern.kevListed && (
                                    <span className="text-[10px] font-mono px-2 py-0.5 rounded border text-red-400 border-red-500/40 bg-red-500/10">
                                      KEV
                                    </span>
                                  )}
                                </div>
                              </div>
                              <div className="text-right flex-shrink-0">
                                <div className="text-2xl font-bold text-emerald-400">{Math.round(selectedPattern.confidence * 100)}%</div>
                                <div className="text-[10px] text-white/40">{t('pages.aiAnalysisEngine.confidence')}</div>
                              </div>
                            </div>

                            <p className="text-sm text-white/70 leading-relaxed">{selectedPattern.description}</p>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                              <div>
                                <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">{t('pages.aiAnalysisEngine.affected_systems')}</div>
                                <div className="flex flex-wrap gap-1">
                                  {selectedPattern.affectedSystems.length > 0 ? selectedPattern.affectedSystems.map((s) => (
                                    <span key={s} className="text-[11px] px-2 py-0.5 rounded bg-white/10 text-white/70 border border-white/10">{s}</span>
                                  )) : <span className="text-[11px] text-white/40">—</span>}
                                </div>
                              </div>
                              <div>
                                <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">{t('pages.aiAnalysisEngine.mitre_techniques')}</div>
                                <div className="flex flex-wrap gap-1">
                                  {selectedPattern.mitreTechniques.length > 0 ? selectedPattern.mitreTechniques.map((tech) => (
                                    <span key={tech} className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-200 border border-indigo-500/30">{tech}</span>
                                  )) : <span className="text-[11px] text-white/40">{t('pages.aiAnalysisEngine.mitre_not_mapped')}</span>}
                                </div>
                              </div>
                            </div>

                            <div>
                              <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">{t('pages.aiAnalysisEngine.indicators')}</div>
                              {selectedPattern.indicators.length > 0 ? (
                                <ul className="space-y-1">
                                  {selectedPattern.indicators.map((ioc, i) => (
                                    <li key={i} className="text-xs text-white/70 flex items-start gap-2">
                                      <span className="text-amber-400 mt-0.5 flex-shrink-0">◆</span>
                                      {ioc}
                                    </li>
                                  ))}
                                </ul>
                              ) : (
                                <p className="text-xs text-white/40">{t('pages.aiAnalysisEngine.no_indicators')}</p>
                              )}
                            </div>

                            {(selectedPattern.maxEpss != null || selectedPattern.maxCvss != null || selectedPattern.memberCount > 1) && (
                              <div className="grid grid-cols-3 gap-3 text-center">
                                {selectedPattern.maxEpss != null && (
                                  <div className="rounded-lg bg-white/5 border border-white/10 p-3">
                                    <div className="text-sm font-mono text-cyan-300">{(selectedPattern.maxEpss * 100).toFixed(1)}%</div>
                                    <div className="text-[10px] text-white/40">{t('pages.aiAnalysisEngine.max_epss')}</div>
                                  </div>
                                )}
                                {selectedPattern.maxCvss != null && (
                                  <div className="rounded-lg bg-white/5 border border-white/10 p-3">
                                    <div className="text-sm font-mono text-orange-300">{Number(selectedPattern.maxCvss).toFixed(1)}</div>
                                    <div className="text-[10px] text-white/40">{t('pages.aiAnalysisEngine.max_cvss')}</div>
                                  </div>
                                )}
                                <div className="rounded-lg bg-white/5 border border-white/10 p-3">
                                  <div className="text-sm font-mono text-violet-300">{selectedPattern.memberCount}</div>
                                  <div className="text-[10px] text-white/40">{t('pages.aiAnalysisEngine.correlated_signals')}</div>
                                </div>
                              </div>
                            )}

                            <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/20 p-4">
                              <div className="text-[10px] uppercase tracking-widest text-emerald-400/70 mb-2">{t('pages.aiAnalysisEngine.remediation')}</div>
                              <p className="text-xs text-white/70 leading-relaxed">
                                {selectedPattern.remediation || t('pages.aiAnalysisEngine.no_remediation')}
                              </p>
                            </div>

                            {selectedPattern.lastSeen && (
                              <div className="text-[11px] text-white/35 font-mono">
                                {t('pages.aiAnalysisEngine.last_seen', { time: selectedPattern.lastSeen.slice(0, 19).replace('T', ' ') })}
                                {selectedPattern.status && ` · ${t('pages.aiAnalysisEngine.status_label', { status: selectedPattern.status })}`}
                              </div>
                            )}
                          </>
                        )
                      })()}
                    </motion.div>
                  ) : (
                    <motion.div
                      key="empty"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="rounded-2xl border border-dashed border-white/10 bg-white/3 p-12 flex flex-col items-center justify-center text-center h-full min-h-[300px]"
                    >
                      <div className="text-4xl mb-4">🤖</div>
                      <div className="text-sm text-white/40">{t('pages.aiAnalysisEngine.select_pattern')}</div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          )}

          {activeTab === 'correlations' && (
            <div className="space-y-4">
              <p className="text-sm text-white/50 mb-4">{t('pages.aiAnalysisEngine.correlations_intro')}</p>

              {!loading && correlations.length === 0 && (
                <EmptyState
                  icon="🔗"
                  title={t('pages.aiAnalysisEngine.no_correlations_title')}
                  body={t('pages.aiAnalysisEngine.no_correlations_body')}
                />
              )}

              {correlations.map((corr) => (
                <motion.div
                  key={corr.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="rounded-2xl border border-white/10 bg-white/5 p-5"
                >
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div>
                      <h3 className="text-sm font-bold text-white mb-1">{corrTitle(corr)}</h3>
                      <div className="flex flex-wrap gap-2">
                        {corr.patternIds.map((pid) => {
                          const p = patterns.find((x) => x.id === pid)
                          return p ? (
                            <button
                              key={pid}
                              type="button"
                              onClick={() => { setActiveTab('patterns'); setSelectedPattern(p) }}
                              className="text-[10px] px-2 py-0.5 rounded bg-violet-500/20 text-violet-200 border border-violet-500/30 hover:bg-violet-500/30"
                            >
                              {p.name}
                            </button>
                          ) : null
                        })}
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <div className="text-lg font-bold text-emerald-400">{Math.round(corr.confidence * 100)}%</div>
                      <div className="text-[10px] text-white/40">{t('pages.aiAnalysisEngine.confidence')}</div>
                    </div>
                  </div>
                  <p className="text-xs text-white/60 leading-relaxed mb-3">{corrDescription(corr)}</p>
                  <div className="flex items-center justify-between text-[11px] text-white/40">
                    <span>
                      {t('pages.aiAnalysisEngine.risk_multiplier')}{' '}
                      <span className="text-orange-400 font-mono">×{corr.riskMultiplier}</span>
                    </span>
                    <span>
                      {t('pages.aiAnalysisEngine.detected')}: {corr.detectedAt?.slice(0, 10) ?? '—'}
                    </span>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </>
      )}
    </PageShell>
  )
}
