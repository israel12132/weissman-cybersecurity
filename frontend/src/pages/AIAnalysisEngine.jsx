/**
 * AI Analysis Engine
 *
 * AI-powered attack pattern recognition, false-positive reduction,
 * threat correlation, and composite risk scoring dashboard.
 * Route: /ai-analysis
 *
 * Patterns from `/api/soc/ai-patterns` with `/api/findings/clusters` fallback — no fabricated intel.
 */
<<<<<<< HEAD
import React, { useState, useMemo, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
=======
import React, { useState, useMemo, useEffect, useCallback } from 'react'
>>>>>>> origin/main
import { motion, AnimatePresence } from 'framer-motion'
import { apiFetch } from '../lib/apiBase'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

<<<<<<< HEAD
// ─── Metadata ─────────────────────────────────────────────────────────────────
=======
// ─── Fallback Data ────────────────────────────────────────────────────────────

const FALLBACK_ATTACK_PATTERNS = [
  {
    id: 'AP-001',
    name: 'Cloud-to-AD Lateral Movement',
    category: 'cloud_attacks',
    confidence: 0.78,
    affectedSystems: ['AWS', 'Azure', 'Active Directory', 'VPN'],
    mitreTechniques: ['T1078', 'T1021', 'T1484', 'T1087', 'T1003'],
    severity: 'critical',
    description: 'Attacker compromises cloud credentials, pivots via VPN/DirectConnect into on-premises AD, escalates privileges to Domain Admin.',
    indicators: ['Anomalous IAM API calls', 'Unusual VPN geo-origin', 'LDAP enumeration spike', 'DCSync event'],
    remediation: 'Enforce MFA on all cloud accounts, segment AD from cloud via firewall, deploy PAW architecture.',
  },
  {
    id: 'AP-002',
    name: 'Supply Chain → RCE Chain',
    category: 'supply_chain',
    confidence: 0.71,
    affectedSystems: ['CI/CD', 'npm', 'PyPI', 'Maven', 'Build Server'],
    mitreTechniques: ['T1195', 'T1059', 'T1543', 'T1036', 'T1041'],
    severity: 'critical',
    description: 'Malicious dependency injected into CI/CD pipeline executes arbitrary code on build servers and propagates to production.',
    indicators: ['Unexpected postinstall scripts', 'Build server outbound DNS to unknown host', 'Artifact hash mismatch'],
    remediation: 'Pin all dependencies to exact hashes, enforce SLSA level 3, use isolated build environments.',
  },
  {
    id: 'AP-003',
    name: 'SSRF → IMDS → IAM Escalation',
    category: 'cloud_attacks',
    confidence: 0.88,
    affectedSystems: ['Web Application', 'AWS EC2', 'IAM', 'S3'],
    mitreTechniques: ['T1190', 'T1552', 'T1078', 'T1537'],
    severity: 'high',
    description: 'SSRF vulnerability in web application used to reach cloud IMDS endpoint, stealing IAM credentials for privilege escalation.',
    indicators: ['HTTP request to 169.254.169.254', 'IAM role credential use from unexpected IP', 'Anomalous S3 list/get calls'],
    remediation: 'Block IMDS v1, enforce IMDSv2 with hop limit 1, add SSRF header validation, deploy WAF SSRF rule.',
  },
  {
    id: 'AP-004',
    name: 'Kerberoasting → DCSync',
    category: 'identity',
    confidence: 0.83,
    affectedSystems: ['Active Directory', 'Kerberos', 'Domain Controllers'],
    mitreTechniques: ['T1558.003', 'T1003.006', 'T1078.002', 'T1021.002'],
    severity: 'critical',
    description: 'Service account tickets extracted and cracked offline, followed by DCSync to dump all domain credentials.',
    indicators: ['TGS requests for service accounts', 'Offline brute-force log', 'Replication rights granted to non-DC', 'DRSUAPI calls'],
    remediation: 'Use 25+ char random passwords for service accounts, deploy Managed Service Accounts, monitor DCSync via SACL.',
  },
  {
    id: 'AP-005',
    name: 'Container Escape → Host Takeover',
    category: 'cloud_native',
    confidence: 0.65,
    affectedSystems: ['Docker', 'Kubernetes', 'Container Runtime', 'Host OS'],
    mitreTechniques: ['T1611', 'T1543.002', 'T1078.001', 'T1552.007'],
    severity: 'high',
    description: 'Container escape via privileged pod or runtime vulnerability grants root access to underlying Kubernetes node.',
    indicators: ['Privileged container spawn', 'Unexpected host namespace access', 'kubelet credential exposure', 'Node-level privilege escalation'],
    remediation: 'Enforce Pod Security Standards (Restricted), disable privileged containers, use gVisor/Kata for isolation.',
  },
  {
    id: 'AP-006',
    name: 'OAuth2 Token Hijack → Account Takeover',
    category: 'identity',
    confidence: 0.90,
    affectedSystems: ['OAuth2 Provider', 'OIDC', 'Web Application', 'Mobile App'],
    mitreTechniques: ['T1550.001', 'T1539', 'T1185', 'T1078'],
    severity: 'high',
    description: 'Attacker captures OAuth2 authorization code via open redirect, exchanges for tokens, and maintains persistent access.',
    indicators: ['Redirect to unexpected origin', 'Token reuse from different IP', 'Refresh token persistence anomaly'],
    remediation: 'Validate redirect URIs strictly, use PKCE for all public clients, enforce token binding.',
  },
]
>>>>>>> origin/main

const CATEGORY_META = {
  cloud_attacks:  { label: 'Cloud Attacks',   color: '#06b6d4', icon: '☁️' },
  supply_chain:   { label: 'Supply Chain',    color: '#f97316', icon: '⛓️' },
  identity:       { label: 'Identity',        color: '#a78bfa', icon: '🆔' },
  cloud_native:   { label: 'Cloud Native',    color: '#34d399', icon: '🐳' },
  web_app:        { label: 'Web App',         color: '#f59e0b', icon: '🌐' },
  other:          { label: 'Other',           color: '#94a3b8', icon: '🔍' },
}

const SEVERITY_META = {
  critical: { color: '#ef4444', label: 'CRITICAL' },
  high:     { color: '#f97316', label: 'HIGH' },
  medium:   { color: '#f59e0b', label: 'MEDIUM' },
  low:      { color: '#22d3ee', label: 'LOW' },
  info:     { color: '#6b7280', label: 'INFO' },
}

<<<<<<< HEAD
const CATEGORY_RULES = [
  { id: 'cloud_attacks',  re: /cloud|aws|azure|gcp|iam|ec2|s3|imds/i },
  { id: 'supply_chain',   re: /supply|sbom|dependency|npm|pypi|maven|ci\/?cd/i },
  { id: 'identity',       re: /auth|oauth|kerberos|ldap|identity|jwt|saml|ad\b|password/i },
  { id: 'cloud_native',   re: /k8s|kubernetes|docker|container|kube|pod/i },
  { id: 'web_app',        re: /xss|sqli|ssrf|idor|bola|web|api|http|injection/i },
]

// ─── Data transforms ──────────────────────────────────────────────────────────

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
  const mitre = [...new Set(
    members.map((m) => m.mitre_attack).filter(Boolean),
  )]
  const remediation = members.find((m) => m.remediation)?.remediation || ''
  const descriptions = members.map((m) => m.description).filter(Boolean)

  const indicators = [
    ...(cluster.cves || []),
    cluster.cwe && `CWE: ${cluster.cwe}`,
    cluster.vuln_signature,
    cluster.kev_listed && 'CISA KEV listed',
    cluster.member_count > 1 && `${cluster.member_count} correlated signals`,
  ].filter(Boolean)

  const description = descriptions[0]
    || [
      cluster.title,
      cluster.target && `Target: ${cluster.target}`,
      cluster.cwe && `CWE ${cluster.cwe}`,
      cluster.member_count > 1 && `${cluster.member_count} engines/sources corroborate this cluster.`,
    ].filter(Boolean).join(' · ')

  return {
    id: `CL-${cluster.id}`,
    clusterId: cluster.id,
    name: cluster.title || cluster.vuln_signature || `Cluster ${cluster.id}`,
    category: deriveCategory(clusterHaystack(cluster)),
    confidence: clusterConfidence(cluster),
    affectedSystems: [...new Set([
      cluster.target,
      ...(cluster.engines || []),
      ...(cluster.sources || []),
    ].filter(Boolean))],
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
  const indicators = [
    f.cve || f.cve_id,
    f.signature_hash,
    f.kev_listed && 'CISA KEV listed',
    f.seen_count > 1 && `Seen ${f.seen_count}×`,
  ].filter(Boolean)

  return {
    id: f.id || `F-${f.raw_id}`,
    clusterId: f.cluster_id,
    name: f.title || 'Finding',
    category: deriveCategory([
      f.title, f.description, f.source, f.target, f.mitre_attack,
    ].join(' ')),
    confidence: findingConfidence(f),
    affectedSystems: [f.target, f.source].filter(Boolean),
    mitreTechniques: f.mitre_attack ? [f.mitre_attack] : [],
    severity,
    description: f.description || f.title,
    indicators,
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
  const text = `${p.name || ''} ${source}`

  return {
    id: `CL-${p.id}`,
    clusterId: p.id,
    name: p.name || `Pattern ${p.id}`,
    category: deriveCategory(text),
    confidence: Number(p.confidence) || 0.5,
    affectedSystems: source ? [source] : [],
    mitreTechniques: Array.isArray(p.techniques) ? p.techniques.filter(Boolean) : [],
    severity,
    description: [
      p.occurrences > 1 && `${p.occurrences} correlated occurrences`,
      source && `Source engine: ${source}`,
    ].filter(Boolean).join(' · ') || p.name,
    indicators: [
      p.occurrences > 1 && `${p.occurrences} occurrences`,
      source && `Source: ${source}`,
    ].filter(Boolean),
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
        patternIds: [p.id],
        confidence: Math.min(0.95, p.confidence + 0.08),
        title: `Multi-engine correlation: ${p.name}`,
        description: `${p.memberCount} finding(s) from ${engines.join(', ')} converge on ${p._raw?.target || 'the same vulnerability signature'}.`,
        riskMultiplier: Number((1 + Math.min(0.5, (p.memberCount - 1) * 0.08)).toFixed(2)),
        detectedAt: p.lastSeen || new Date().toISOString(),
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
      patternIds: group.map((p) => p.id),
      confidence: Math.min(0.95, avgConf + 0.05),
      title: `Co-located exposure on ${target}`,
      description: `${group.length} distinct vulnerability clusters affect ${target}, indicating compounding attack surface.`,
      riskMultiplier: Number((1 + group.length * 0.12).toFixed(2)),
      detectedAt: latest || new Date().toISOString(),
    })
  }

  return corrs
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 25)
}

async function loadIntelPatterns() {
  const socRes = await apiFetch('/api/soc/ai-patterns')
  if (socRes.ok) {
    const socData = await socRes.json()
    const socPatterns = Array.isArray(socData?.patterns) ? socData.patterns : []
    if (socPatterns.length > 0) {
      return {
        patterns: socPatterns.map(socPatternToPattern),
        source: 'soc',
        total: socPatterns.length,
      }
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
    return {
      patterns: findings.map(findingToPattern),
      source: 'findings',
      total: findingsTotal,
    }
  }

  throw new Error(`Failed to load intel (HTTP ${clustersRes.status})`)
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function AIAnalysisEngine() {
  const { t } = useTranslation()
  const [patterns, setPatterns] = useState([])
  const [correlations, setCorrelations] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [dataSource, setDataSource] = useState(null)
=======
// ─── Fallback Correlations ───────────────────────────────────────────────────

const FALLBACK_CORRELATIONS = [
  {
    id: 'corr-001',
    patternIds: ['AP-001', 'AP-004'],
    confidence: 0.91,
    title: 'Cloud breach → AD full compromise pathway',
    description: 'Cloud-to-AD lateral movement correlates with Kerberoasting activity. Combined attack path achieves full domain takeover in under 6 hours.',
    riskMultiplier: 1.4,
    detectedAt: '2026-05-16T12:00:00Z',
  },
  {
    id: 'corr-002',
    patternIds: ['AP-002', 'AP-005'],
    confidence: 0.77,
    title: 'Supply chain compromise leads to container escape',
    description: 'Malicious CI artifact deploys privileged container enabling host takeover.',
    riskMultiplier: 1.3,
    detectedAt: '2026-05-15T08:30:00Z',
  },
  {
    id: 'corr-003',
    patternIds: ['AP-003', 'AP-006'],
    confidence: 0.82,
    title: 'SSRF + OAuth2 combined account takeover',
    description: 'SSRF used to bypass IP allowlisting for OAuth2 redirect, combined with token hijack for persistent access.',
    riskMultiplier: 1.2,
    detectedAt: '2026-05-14T16:45:00Z',
  },
]

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AIAnalysisEngine() {
  const [attackPatterns, setAttackPatterns] = useState([])
  const [correlations, setCorrelations] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
>>>>>>> origin/main
  const [selectedPattern, setSelectedPattern] = useState(null)
  const [filterCategory, setFilterCategory] = useState('all')
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [activeTab, setActiveTab] = useState('patterns')

<<<<<<< HEAD
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoading(true)
      setError(null)
      try {
        const { patterns: loaded, source } = await loadIntelPatterns()
        if (cancelled) return
        setPatterns(loaded)
        setCorrelations(buildCorrelations(loaded))
        setDataSource(source)
        setSelectedPattern((prev) => {
          if (prev && loaded.some((p) => p.id === prev.id)) return prev
          return loaded[0] || null
        })
      } catch (e) {
        if (!cancelled) setError(e.message || 'Failed to load intel data')
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const categories = useMemo(() => {
    const ids = [...new Set(patterns.map((p) => p.category))]
    return ids.sort()
  }, [patterns])

  const filtered = useMemo(() => {
    return patterns.filter((p) => {
=======
  // Load AI analysis data from API
  useEffect(() => {
    const loadData = async () => {
      setLoading(true)
      setError(null)

      try {
        // Fetch attack patterns
        const patternsRes = await apiFetch('/api/ai-analysis/patterns')
        if (patternsRes.ok) {
          const patternsData = await patternsRes.json()
          setAttackPatterns(Array.isArray(patternsData) ? patternsData : patternsData.patterns || [])
        } else if (patternsRes.status === 404) {
          // API not implemented, use fallback
          setAttackPatterns(FALLBACK_ATTACK_PATTERNS)
        } else {
          throw new Error(`Failed to load patterns (HTTP ${patternsRes.status})`)
        }

        // Fetch correlations
        const corrRes = await apiFetch('/api/ai-analysis/correlations')
        if (corrRes.ok) {
          const corrData = await corrRes.json()
          setCorrelations(Array.isArray(corrData) ? corrData : corrData.correlations || [])
        } else if (corrRes.status === 404) {
          // API not implemented, use fallback
          setCorrelations(FALLBACK_CORRELATIONS)
        } else {
          throw new Error(`Failed to load correlations (HTTP ${corrRes.status})`)
        }
      } catch (err) {
        setError(err?.message || 'Failed to load AI analysis data')
        // Use fallback data on error
        setAttackPatterns(FALLBACK_ATTACK_PATTERNS)
        setCorrelations(FALLBACK_CORRELATIONS)
      } finally {
        setLoading(false)
      }
    }

    loadData()
  }, [])

  const filtered = useMemo(() => {
    return attackPatterns.filter((p) => {
>>>>>>> origin/main
      if (filterCategory !== 'all' && p.category !== filterCategory) return false
      if (filterSeverity !== 'all' && p.severity !== filterSeverity) return false
      return true
    })
<<<<<<< HEAD
  }, [patterns, filterCategory, filterSeverity])

  const avgConfidence = useMemo(() => {
    if (!patterns.length) return 0
    return Math.round((patterns.reduce((a, p) => a + p.confidence, 0) / patterns.length) * 100)
  }, [patterns])

  const criticalCount = useMemo(
    () => patterns.filter((p) => p.severity === 'critical').length,
    [patterns],
=======
  }, [attackPatterns, filterCategory, filterSeverity])

  const avgConfidence = useMemo(() => {
    if (attackPatterns.length === 0) return 0
    return Math.round((attackPatterns.reduce((a, p) => a + p.confidence, 0) / attackPatterns.length) * 100)
  }, [attackPatterns])

  const criticalCount = useMemo(() =>
    attackPatterns.filter(p => p.severity === 'critical').length,
    [attackPatterns]
>>>>>>> origin/main
  )

  return (
    <PageShell
<<<<<<< HEAD
      title={t('pages.aiAnalysisEngine.title')}
      subtitle={t('pages.aiAnalysisEngine.subtitle')}
      badge="AI"
      badgeColor="#a78bfa"
    >
      <p className="text-xs text-white/40 font-mono mb-6">
        Live intel from <code>/api/soc/ai-patterns</code>
        {dataSource === 'clusters'
          ? ' (fallback: /api/findings/clusters)'
          : dataSource === 'findings'
            ? ' (fallback: /api/findings)'
            : ''}.
        Patterns reflect correlated finding clusters — no fabricated attack chains.
      </p>

      {error && (
        <div className="mb-6 p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm">
          Couldn&apos;t load intel data: {error}.
        </div>
      )}

      {/* ── KPI Bar ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
        {[
          { label: 'Patterns Detected', value: loading ? '…' : patterns.length, color: '#a78bfa' },
          { label: 'Avg Confidence', value: loading ? '…' : `${avgConfidence}%`, color: '#10b981' },
          { label: 'Correlations', value: loading ? '…' : correlations.length, color: '#f97316' },
          { label: 'Critical Patterns', value: loading ? '…' : criticalCount, color: '#ef4444' },
        ].map((kpi) => (
          <div key={kpi.label} className="rounded-2xl border border-white/10 bg-white/5 p-4 text-center">
            <div className="text-2xl font-bold" style={{ color: kpi.color }}>{kpi.value}</div>
            <div className="text-[11px] text-white/50 mt-1">{kpi.label}</div>
          </div>
        ))}
      </div>

      {/* ── Tabs ── */}
      <div className="flex gap-2 mb-6">
        {[
          { id: 'patterns', label: 'Attack Patterns' },
          { id: 'correlations', label: 'Correlations' },
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
          {/* ── Pattern List ── */}
          <div className="space-y-3">
            <div className="flex items-center gap-2 mb-3">
              <select
                value={filterCategory}
                onChange={(e) => setFilterCategory(e.target.value)}
                className="flex-1 text-xs bg-black/40 border border-white/10 rounded-lg px-2 py-1.5 text-white/60 focus:outline-none"
              >
                <option value="all">All Categories</option>
                {categories.map((k) => (
                  <option key={k} value={k}>{CATEGORY_META[k]?.label ?? k}</option>
                ))}
              </select>
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="flex-1 text-xs bg-black/40 border border-white/10 rounded-lg px-2 py-1.5 text-white/60 focus:outline-none"
              >
                <option value="all">All Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            {loading && (
              <div className="rounded-2xl border border-white/10 bg-white/5 p-6 text-sm text-white/45">
                Loading finding clusters…
              </div>
            )}

            {!loading && filtered.length === 0 && (
              <div className="rounded-2xl border border-dashed border-white/10 bg-white/3 p-6 text-sm text-white/45">
                No patterns match the current filters. Run engines to populate finding clusters.
              </div>
            )}

            {filtered.map((pattern) => {
              const sm = SEVERITY_META[pattern.severity] ?? SEVERITY_META.medium
              const cm = CATEGORY_META[pattern.category] ?? { color: '#22d3ee', icon: '🔍', label: pattern.category }
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
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded border flex-shrink-0 ml-2"
                      style={{ color: sm.color, borderColor: `${sm.color}40`, backgroundColor: `${sm.color}10` }}>
                      {sm.label}
                    </span>
                  </div>
                  <div className="flex items-center justify-between mt-2">
                    <span className="text-[11px] text-white/40">{cm.label}</span>
                    <div className="flex items-center gap-1">
                      <div className="w-16 bg-white/10 rounded-full h-1">
                        <div className="h-1 rounded-full" style={{ width: `${pattern.confidence * 100}%`, backgroundColor: '#10b981' }} />
                      </div>
                      <span className="text-[10px] font-mono text-[#10b981]">{Math.round(pattern.confidence * 100)}%</span>
                    </div>
                  </div>
                </motion.button>
              )
            })}
          </div>

          {/* ── Pattern Detail ── */}
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
                    const sm = SEVERITY_META[selectedPattern.severity] ?? SEVERITY_META.medium
                    const cm = CATEGORY_META[selectedPattern.category] ?? { color: '#22d3ee', icon: '🔍', label: selectedPattern.category }
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
                                style={{ color: sm.color, borderColor: `${sm.color}40`, backgroundColor: `${sm.color}10` }}>
                                {sm.label}
                              </span>
                              <span className="text-[10px] px-2 py-0.5 rounded border"
                                style={{ color: cm.color, borderColor: `${cm.color}40`, backgroundColor: `${cm.color}10` }}>
                                {cm.label}
                              </span>
                              <span className="text-[10px] font-mono text-white/40">{selectedPattern.id}</span>
                              {selectedPattern.kevListed && (
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded border text-red-400 border-red-500/40 bg-red-500/10">
                                  KEV
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="text-right flex-shrink-0">
                            <div className="text-2xl font-bold text-[#10b981]">{Math.round(selectedPattern.confidence * 100)}%</div>
                            <div className="text-[10px] text-white/40">Confidence</div>
                          </div>
                        </div>

                        <p className="text-sm text-white/70 leading-relaxed">{selectedPattern.description}</p>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                          <div>
                            <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">Affected Systems</div>
                            <div className="flex flex-wrap gap-1">
                              {selectedPattern.affectedSystems.length > 0 ? selectedPattern.affectedSystems.map((s) => (
                                <span key={s} className="text-[11px] px-2 py-0.5 rounded bg-white/10 text-white/70 border border-white/10">{s}</span>
                              )) : (
                                <span className="text-[11px] text-white/40">—</span>
                              )}
                            </div>
                          </div>
                          <div>
                            <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">MITRE Techniques</div>
                            <div className="flex flex-wrap gap-1">
                              {selectedPattern.mitreTechniques.length > 0 ? selectedPattern.mitreTechniques.map((t) => (
                                <span key={t} className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#6366f1]/20 text-[#a5b4fc] border border-[#6366f1]/30">{t}</span>
                              )) : (
                                <span className="text-[11px] text-white/40">Not mapped</span>
                              )}
                            </div>
                          </div>
                        </div>

                        <div>
                          <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">Indicators of Compromise</div>
                          {selectedPattern.indicators.length > 0 ? (
                            <ul className="space-y-1">
                              {selectedPattern.indicators.map((ioc, i) => (
                                <li key={i} className="text-xs text-white/70 flex items-start gap-2">
                                  <span className="text-[#f59e0b] mt-0.5 flex-shrink-0">◆</span>
                                  {ioc}
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="text-xs text-white/40">No indicators recorded for this cluster.</p>
                          )}
                        </div>

                        {(selectedPattern.maxEpss != null || selectedPattern.maxCvss != null || selectedPattern.memberCount > 1) && (
                          <div className="grid grid-cols-3 gap-3 text-center">
                            {selectedPattern.maxEpss != null && (
                              <div className="rounded-lg bg-white/5 border border-white/10 p-3">
                                <div className="text-sm font-mono text-cyan-300">{(selectedPattern.maxEpss * 100).toFixed(1)}%</div>
                                <div className="text-[10px] text-white/40">Max EPSS</div>
                              </div>
                            )}
                            {selectedPattern.maxCvss != null && (
                              <div className="rounded-lg bg-white/5 border border-white/10 p-3">
                                <div className="text-sm font-mono text-orange-300">{Number(selectedPattern.maxCvss).toFixed(1)}</div>
                                <div className="text-[10px] text-white/40">Max CVSS</div>
                              </div>
                            )}
                            <div className="rounded-lg bg-white/5 border border-white/10 p-3">
                              <div className="text-sm font-mono text-violet-300">{selectedPattern.memberCount}</div>
                              <div className="text-[10px] text-white/40">Correlated signals</div>
                            </div>
                          </div>
                        )}

                        <div className="rounded-xl bg-[#10b981]/10 border border-[#10b981]/20 p-4">
                          <div className="text-[10px] uppercase tracking-widest text-[#10b981]/70 mb-2">Remediation Guidance</div>
                          <p className="text-xs text-white/70 leading-relaxed">
                            {selectedPattern.remediation || 'No remediation text on file — triage in Findings Command Center.'}
                          </p>
                        </div>

                        {selectedPattern.lastSeen && (
                          <div className="text-[11px] text-white/35 font-mono">
                            Last seen: {selectedPattern.lastSeen.slice(0, 19).replace('T', ' ')}
                            {selectedPattern.status && ` · Status: ${selectedPattern.status}`}
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
                  <div className="text-sm text-white/40">
                    {loading ? 'Loading intel patterns…' : 'Select an attack pattern to view AI analysis details'}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
=======
      title="AI Analysis Engine"
      subtitle={loading ? 'Loading AI analysis...' : 'Attack Pattern Recognition · Threat Correlation · Risk Scoring'}
      badge="AI"
      badgeColor="#a78bfa"
    >
      {/* ── Error Banner ─────────────────────────────────────────────────── */}
      {error && (
        <div className="mb-6 rounded-xl border border-amber-500/30 bg-amber-950/20 px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="text-amber-400 text-sm">⚠️</span>
            <span className="text-xs font-mono text-amber-300/80">{error}</span>
            <span className="text-[10px] text-amber-300/50 ml-auto">Using demo data</span>
>>>>>>> origin/main
          </div>
        </div>
      )}

<<<<<<< HEAD
      {activeTab === 'correlations' && (
        <div className="space-y-4">
          <div className="text-sm text-white/50 mb-4">
            Correlations derived from multi-engine clusters and co-located targets in live finding data.
          </div>

          {loading && (
            <div className="rounded-2xl border border-white/10 bg-white/5 p-6 text-sm text-white/45">
              Analyzing cluster correlations…
            </div>
          )}

          {!loading && correlations.length === 0 && (
            <div className="rounded-2xl border border-dashed border-white/10 bg-white/3 p-8 text-sm text-white/45 text-center">
              No correlations yet. Multi-engine clusters or shared targets will appear here as engines report findings.
            </div>
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
                  <h3 className="text-sm font-bold text-white mb-1">{corr.title}</h3>
                  <div className="flex flex-wrap gap-2">
                    {corr.patternIds.map((pid) => {
                      const p = patterns.find((x) => x.id === pid)
                      return p ? (
                        <span key={pid} className="text-[10px] px-2 py-0.5 rounded bg-[#a78bfa]/20 text-[#c4b5fd] border border-[#a78bfa]/30">
                          {p.name}
                        </span>
                      ) : null
                    })}
                  </div>
                </div>
                <div className="text-right flex-shrink-0">
                  <div className="text-lg font-bold text-[#10b981]">{Math.round(corr.confidence * 100)}%</div>
                  <div className="text-[10px] text-white/40">Confidence</div>
                </div>
              </div>
              <p className="text-xs text-white/60 leading-relaxed mb-3">{corr.description}</p>
              <div className="flex items-center justify-between text-[11px] text-white/40">
                <span>Risk multiplier: <span className="text-[#f97316] font-mono">×{corr.riskMultiplier}</span></span>
                <span>Detected: {corr.detectedAt?.slice(0, 10) ?? '—'}</span>
              </div>
            </motion.div>
          ))}
=======
      {/* ── Loading State ────────────────────────────────────────────────── */}
      {loading && (
        <div className="flex items-center justify-center py-20">
          <div className="text-center space-y-3">
            <div className="w-8 h-8 border-2 border-violet-500/40 border-t-violet-500 rounded-full animate-spin mx-auto" />
            <p className="text-sm font-mono text-white/40">Loading AI analysis...</p>
          </div>
>>>>>>> origin/main
        </div>
      )}

      {!loading && (
        <>
          {/* ── KPI Bar ── */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
            {[
              { label: 'Patterns Detected', value: attackPatterns.length, color: '#a78bfa' },
              { label: 'Avg Confidence', value: `${avgConfidence}%`, color: '#10b981' },
              { label: 'Correlations', value: correlations.length, color: '#f97316' },
              { label: 'Critical Patterns', value: criticalCount, color: '#ef4444' },
            ].map((kpi) => (
              <div key={kpi.label} className="rounded-2xl border border-white/10 bg-white/5 p-4 text-center">
                <div className="text-2xl font-bold" style={{ color: kpi.color }}>{kpi.value}</div>
                <div className="text-[11px] text-white/50 mt-1">{kpi.label}</div>
              </div>
            ))}
          </div>

          {/* ── Tabs ── */}
          <div className="flex gap-2 mb-6">
            {[
              { id: 'patterns', label: 'Attack Patterns' },
              { id: 'correlations', label: 'Correlations' },
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
              {/* ── Pattern List ── */}
              <div className="space-y-3">
                <div className="flex items-center gap-2 mb-3">
                  <select
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                    className="flex-1 text-xs bg-black/40 border border-white/10 rounded-lg px-2 py-1.5 text-white/60 focus:outline-none"
                  >
                    <option value="all">All Categories</option>
                    {Object.entries(CATEGORY_META).map(([k, v]) => (
                      <option key={k} value={k}>{v.label}</option>
                    ))}
                  </select>
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="flex-1 text-xs bg-black/40 border border-white/10 rounded-lg px-2 py-1.5 text-white/60 focus:outline-none"
                  >
                    <option value="all">All Severity</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                  </select>
                </div>

                {filtered.length === 0 && (
                  <div className="text-center py-8 text-white/40 text-sm">
                    No patterns match your filters
                  </div>
                )}

                {filtered.map((pattern) => {
                  const sm = SEVERITY_META[pattern.severity] ?? SEVERITY_META.medium
                  const cm = CATEGORY_META[pattern.category] ?? { color: '#22d3ee', icon: '🔍', label: pattern.category }
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
                        <div className="flex items-center gap-2 min-w-0 flex-1">
                          <span>{cm.icon}</span>
                          <span className="text-sm font-semibold text-white truncate">{pattern.name}</span>
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded border flex-shrink-0 ml-2"
                          style={{ color: sm.color, borderColor: `${sm.color}40`, backgroundColor: `${sm.color}10` }}>
                          {sm.label}
                        </span>
                      </div>
                      <div className="flex items-center justify-between mt-2">
                        <span className="text-[11px] text-white/40">{cm.label}</span>
                        <div className="flex items-center gap-1">
                          <div className="w-16 bg-white/10 rounded-full h-1">
                            <div className="h-1 rounded-full" style={{ width: `${pattern.confidence * 100}%`, backgroundColor: '#10b981' }} />
                          </div>
                          <span className="text-[10px] font-mono text-[#10b981]">{Math.round(pattern.confidence * 100)}%</span>
                        </div>
                      </div>
                    </motion.button>
                  )
                })}
              </div>

              {/* ── Pattern Detail ── */}
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
                        const sm = SEVERITY_META[selectedPattern.severity] ?? SEVERITY_META.medium
                        const cm = CATEGORY_META[selectedPattern.category] ?? { color: '#22d3ee', icon: '🔍', label: selectedPattern.category }
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
                                    style={{ color: sm.color, borderColor: `${sm.color}40`, backgroundColor: `${sm.color}10` }}>
                                    {sm.label}
                                  </span>
                                  <span className="text-[10px] px-2 py-0.5 rounded border"
                                    style={{ color: cm.color, borderColor: `${cm.color}40`, backgroundColor: `${cm.color}10` }}>
                                    {cm.label}
                                  </span>
                                  <span className="text-[10px] font-mono text-white/40">{selectedPattern.id}</span>
                                </div>
                              </div>
                              <div className="text-right flex-shrink-0">
                                <div className="text-2xl font-bold text-[#10b981]">{Math.round(selectedPattern.confidence * 100)}%</div>
                                <div className="text-[10px] text-white/40">Confidence</div>
                              </div>
                            </div>

                            <p className="text-sm text-white/70 leading-relaxed">{selectedPattern.description}</p>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                              <div>
                                <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">Affected Systems</div>
                                <div className="flex flex-wrap gap-1">
                                  {selectedPattern.affectedSystems.map((s) => (
                                    <span key={s} className="text-[11px] px-2 py-0.5 rounded bg-white/10 text-white/70 border border-white/10">{s}</span>
                                  ))}
                                </div>
                              </div>
                              <div>
                                <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">MITRE Techniques</div>
                                <div className="flex flex-wrap gap-1">
                                  {selectedPattern.mitreTechniques.map((t) => (
                                    <span key={t} className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#6366f1]/20 text-[#a5b4fc] border border-[#6366f1]/30">{t}</span>
                                  ))}
                                </div>
                              </div>
                            </div>

                            <div>
                              <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">Indicators of Compromise</div>
                              <ul className="space-y-1">
                                {selectedPattern.indicators.map((ioc, i) => (
                                  <li key={i} className="text-xs text-white/70 flex items-start gap-2">
                                    <span className="text-[#f59e0b] mt-0.5 flex-shrink-0">◆</span>
                                    {ioc}
                                  </li>
                                ))}
                              </ul>
                            </div>

                            <div className="rounded-xl bg-[#10b981]/10 border border-[#10b981]/20 p-4">
                              <div className="text-[10px] uppercase tracking-widest text-[#10b981]/70 mb-2">AI Remediation Guidance</div>
                              <p className="text-xs text-white/70 leading-relaxed">{selectedPattern.remediation}</p>
                            </div>
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
                      <div className="text-sm text-white/40">Select an attack pattern to view AI analysis details</div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          )}

          {activeTab === 'correlations' && (
            <div className="space-y-4">
              <div className="text-sm text-white/50 mb-4">
                AI-detected correlations between attack patterns — multi-vector attack chains with compounding risk.
              </div>
              {correlations.length === 0 && (
                <div className="text-center py-12 text-white/40 text-sm">
                  No correlations detected
                </div>
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
                      <h3 className="text-sm font-bold text-white mb-1">{corr.title}</h3>
                      <div className="flex flex-wrap gap-2">
                        {corr.patternIds.map((pid) => {
                          const p = attackPatterns.find((x) => x.id === pid)
                          return p ? (
                            <span key={pid} className="text-[10px] px-2 py-0.5 rounded bg-[#a78bfa]/20 text-[#c4b5fd] border border-[#a78bfa]/30">
                              {p.name}
                            </span>
                          ) : null
                        })}
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <div className="text-lg font-bold text-[#10b981]">{Math.round(corr.confidence * 100)}%</div>
                      <div className="text-[10px] text-white/40">Confidence</div>
                    </div>
                  </div>
                  <p className="text-xs text-white/60 leading-relaxed mb-3">{corr.description}</p>
                  <div className="flex items-center justify-between text-[11px] text-white/40">
                    <span>Risk multiplier: <span className="text-[#f97316] font-mono">×{corr.riskMultiplier}</span></span>
                    <span>Detected: {corr.detectedAt.slice(0, 10)}</span>
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
