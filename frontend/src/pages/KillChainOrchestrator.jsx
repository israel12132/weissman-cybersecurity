/**
 * Kill Chain Orchestrator
 *
 * MITRE ATT&CK-aligned kill chain orchestration: 7-phase attack simulation,
 * engine-to-phase mapping, live risk scoring, and chain-of-execution visualization.
 * Route: /kill-chain
 *
 * Data: `/api/findings` (chains + phase findings), `/api/engines/production`
 * (mapped engines), `/api/dashboard/exec-kpis` (KPI strip). No fabricated chains.
 */
import React, { useState, useMemo, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import { apiFetch } from '../lib/apiBase'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'
import { useProductionEngines } from '../lib/useProductionEngines'

// ─── Kill Chain Phases (MITRE scaffolding — engines/findings are live) ────────

const PHASES = [
  {
    id: 'reconnaissance',
    label: 'Reconnaissance',
    icon: '🔭',
    color: '#22d3ee',
    mitre: 'TA0043',
    techniques: ['T1595', 'T1592', 'T1589', 'T1590', 'T1597', 'T1598'],
    description: 'Gather intelligence on target systems, networks, employees, and infrastructure before active exploitation.',
    riskWeight: 0.10,
  },
  {
    id: 'weaponization',
    label: 'Weaponization',
    icon: '⚗️',
    color: '#a78bfa',
    mitre: 'TA0001',
    techniques: ['T1587', 'T1588', 'T1583', 'T1584'],
    description: 'Develop or acquire tools, exploits, and payloads tailored to target vulnerabilities.',
    riskWeight: 0.15,
  },
  {
    id: 'delivery',
    label: 'Delivery',
    icon: '📦',
    color: '#f97316',
    mitre: 'TA0001',
    techniques: ['T1566', 'T1190', 'T1195', 'T1091'],
    description: 'Transmit weaponized payloads to the target environment via phishing, web exploits, or supply chain compromise.',
    riskWeight: 0.20,
  },
  {
    id: 'exploitation',
    label: 'Exploitation',
    icon: '💥',
    color: '#ef4444',
    mitre: 'TA0002',
    techniques: ['T1203', 'T1211', 'T1068', 'T1210'],
    description: 'Trigger code execution or abuse vulnerabilities to establish initial access within the target.',
    riskWeight: 0.25,
  },
  {
    id: 'installation',
    label: 'Installation',
    icon: '🔩',
    color: '#f59e0b',
    mitre: 'TA0003',
    techniques: ['T1543', 'T1547', 'T1574', 'T1505'],
    description: 'Install backdoors, web shells, or persistent agents to maintain access after initial compromise.',
    riskWeight: 0.10,
  },
  {
    id: 'c2',
    label: 'Command & Control',
    icon: '📡',
    color: '#6366f1',
    mitre: 'TA0011',
    techniques: ['T1071', 'T1090', 'T1572', 'T1008'],
    description: 'Establish covert communication channels between compromised hosts and attacker-controlled infrastructure.',
    riskWeight: 0.10,
  },
  {
    id: 'exfiltration',
    label: 'Exfiltration',
    icon: '📤',
    color: '#10b981',
    mitre: 'TA0010',
    techniques: ['T1041', 'T1048', 'T1537', 'T1020'],
    description: 'Extract sensitive data from the target environment using covert channels or cloud storage abuse.',
    riskWeight: 0.10,
  },
]

const PHASE_SEQUENCE = PHASES.map((p) => p.id)

/** Engine IDs per phase — mirrors backend `kill_chain_orchestrator.py`. */
const PHASE_ENGINE_MAP = {
  reconnaissance: [
    'osint', 'asm', 'recon', 'leak_hunter', 'discovery_engine', 'subdomain_takeover',
    'cve_scanner', 'supply_chain_scanner', 'phishing_kit_scanner', 'github_monitor',
  ],
  weaponization: [
    'payload_generator', 'exploit_db_lookup', 'zero_day_finder', 'malware_generator',
    'ransomware_simulation', 'cve_scanner', 'supply_chain_scanner', 'phishing_kit_scanner', 'keylogger_engine',
  ],
  delivery: [
    'phishing_kit_scanner', 'payload_generator', 'xss_engine', 'open_redirect', 'ssrf_engine',
    'oauth2_scanner', 'sqli_engine', 'xxe_engine', 'supply_chain_scanner', 'exploit_db_lookup',
  ],
  exploitation: [
    'sqli_engine', 'xss_engine', 'ssrf_engine', 'xxe_engine', 'rce_engine', 'lfi_rfi_engine',
    'bola_idor', 'open_redirect', 'zero_day_finder', 'exploit_db_lookup', 'oauth2_scanner',
  ],
  installation: [
    'malware_generator', 'rootkit_scanner', 'keylogger_engine', 'ransomware_simulation',
    'supply_chain_scanner', 'privilege_escalation', 'pass_the_hash', 'mimikatz_sim', 'memory_dumper',
  ],
  c2: [
    'c2_beacon_simulator', 'dns_c2_tunnel', 'https_c2_beacon', 'covert_channel_engine',
    'lateral_movement_sim', 'privilege_escalation', 'pass_the_hash', 'mimikatz_sim', 'memory_dumper',
  ],
  exfiltration: [
    'data_exfil_engine', 'covert_channel_engine', 'cloud_exfil', 'dns_c2_tunnel', 'https_c2_beacon',
    'memory_dumper', 'lateral_movement_sim', 'c2_beacon_simulator',
  ],
}

const GROUP_TO_PHASE = {
  recon: 'reconnaissance',
  social: 'delivery',
  supply_chain: 'weaponization',
  web: 'exploitation',
  apt: 'exploitation',
  malware: 'installation',
  stealth: 'c2',
  network: 'c2',
  data: 'exfiltration',
  cloud: 'exploitation',
  crypto: 'installation',
  ot: 'exploitation',
  ai: 'exploitation',
  mobile: 'delivery',
}

const VULN_TYPE_PHASE_AFFINITY = {
  sqli: 'exploitation',
  xss: 'delivery',
  ssrf: 'exploitation',
  xxe: 'exploitation',
  rce: 'exploitation',
  lfi: 'exploitation',
  rfi: 'exploitation',
  idor: 'exploitation',
  bola: 'exploitation',
  open_redirect: 'delivery',
  phishing: 'delivery',
  subdomain: 'reconnaissance',
  osint: 'reconnaissance',
  c2: 'c2',
  exfil: 'exfiltration',
  malware: 'installation',
  rootkit: 'installation',
  privesc: 'installation',
  credential: 'installation',
  lateral: 'c2',
  ransomware: 'exfiltration',
  keylogger: 'installation',
}

const SEVERITY_META = {
  critical: { color: '#ef4444', label: 'CRITICAL' },
  high: { color: '#f97316', label: 'HIGH' },
  medium: { color: '#f59e0b', label: 'MEDIUM' },
  low: { color: '#22d3ee', label: 'LOW' },
  info: { color: '#6b7280', label: 'INFO' },
}

const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

function normalizeSource(finding) {
  return (finding.source || finding.engine || '').toLowerCase().replace(/[-\s]/g, '_')
}

function resolveFindingPhase(finding) {
  const source = normalizeSource(finding)

  for (const phase of PHASE_SEQUENCE) {
    if (PHASE_ENGINE_MAP[phase]?.includes(source)) return phase
  }

  const eng = ENGINES_BY_ID[source]
  if (eng?.group && GROUP_TO_PHASE[eng.group]) return GROUP_TO_PHASE[eng.group]

  const text = `${finding.title || ''} ${finding.description || ''} ${finding.cwe || ''}`.toLowerCase()
  for (const [keyword, phase] of Object.entries(VULN_TYPE_PHASE_AFFINITY)) {
    if (text.includes(keyword)) return phase
  }

  return 'reconnaissance'
}

function scoreToRiskLevel(score) {
  if (score >= 75) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 25) return 'medium'
  return 'low'
}

function computeChainRiskScore(findings) {
  if (!findings.length) return 0

  const criticalCount = findings.filter((f) => (f.severity || '').toLowerCase() === 'critical').length
  const highCount = findings.filter((f) => (f.severity || '').toLowerCase() === 'high').length
  const mediumCount = findings.filter((f) => (f.severity || '').toLowerCase() === 'medium').length

  const cvssScores = findings
    .map((f) => Number(f.cvss_score || f.risk_score || 0))
    .filter((n) => n > 0)
  const maxCvss = cvssScores.length ? Math.max(...cvssScores) : 0
  const avgCvss = cvssScores.length ? cvssScores.reduce((a, b) => a + b, 0) / cvssScores.length : 0
  const cvssWeighted = (maxCvss * 0.6 + avgCvss * 0.4) * 10

  const coveredPhases = new Set(findings.map(resolveFindingPhase))
  if (criticalCount > 0) {
    coveredPhases.add('exploitation')
    coveredPhases.add('installation')
  }
  const killChainCoverage = coveredPhases.size / PHASE_SEQUENCE.length

  const severityComponent = Math.min(100, criticalCount * 20 + highCount * 8 + mediumCount * 3)
  const coverageComponent = killChainCoverage * 100
  const overall = Math.min(100, severityComponent * 0.45 + cvssWeighted * 0.35 + coverageComponent * 0.2)

  return Math.round(overall)
}

function maxSeverity(findings) {
  let best = 'info'
  let rank = 0
  for (const f of findings) {
    const sev = (f.severity || 'info').toLowerCase()
    const r = SEVERITY_RANK[sev] || 0
    if (r > rank) {
      rank = r
      best = sev
    }
  }
  return best
}

function buildChainsFromFindings(findings) {
  const groups = new Map()

  for (const f of findings) {
    const target = (f.target || '').trim() || f.client_id || f.client || 'Unscoped findings'
    if (!groups.has(target)) groups.set(target, [])
    groups.get(target).push(f)
  }

  return Array.from(groups.entries())
    .map(([target, groupFindings], idx) => {
      const phaseFindings = Object.fromEntries(PHASE_SEQUENCE.map((id) => [id, []]))
      const techniques = new Set()

      for (const f of groupFindings) {
        const phase = resolveFindingPhase(f)
        const label = f.title || f.description || f.id || 'Finding'
        phaseFindings[phase].push(label)
        const mitre = f.mitre_attack || f.mitre || f.technique
        if (mitre) techniques.add(mitre)
      }

      const phasesWithFindings = PHASE_SEQUENCE
        .map((id, i) => (phaseFindings[id].length > 0 ? i : -1))
        .filter((i) => i >= 0)
      const highestPhaseIdx = phasesWithFindings.length ? Math.max(...phasesWithFindings) : -1
      const activePhaseIdx = Math.min(highestPhaseIdx + 1, PHASE_SEQUENCE.length - 1)
      const completedPhases = phasesWithFindings.length ? activePhaseIdx : 0

      const riskScore = computeChainRiskScore(groupFindings)
      const severity = scoreToRiskLevel(riskScore)
      const discoveredAt = groupFindings
        .map((f) => f.discovered_at)
        .filter(Boolean)
        .sort()[0] || null

      const topTitles = groupFindings
        .slice()
        .sort((a, b) => (SEVERITY_RANK[(b.severity || '').toLowerCase()] || 0) - (SEVERITY_RANK[(a.severity || '').toLowerCase()] || 0))
        .slice(0, 3)
        .map((f) => f.title)
        .filter(Boolean)

      const summary = topTitles.length
        ? `${groupFindings.length} finding${groupFindings.length === 1 ? '' : 's'} across ${phasesWithFindings.length} kill-chain phase${phasesWithFindings.length === 1 ? '' : 's'}: ${topTitles.join('; ')}.`
        : `${groupFindings.length} finding${groupFindings.length === 1 ? '' : 's'} mapped to the kill chain for ${target}.`

      return {
        id: `chain-${target}-${idx}`,
        name: target === 'Unscoped findings' ? 'Unscoped attack chain' : `${target} attack chain`,
        severity: maxSeverity(groupFindings) === 'info' ? severity : maxSeverity(groupFindings),
        completedPhases,
        totalPhases: PHASES.length,
        riskScore,
        target,
        discoveredAt,
        techniques: Array.from(techniques),
        summary,
        phaseFindings,
        findingCount: groupFindings.length,
      }
    })
    .sort((a, b) => b.riskScore - a.riskScore || b.findingCount - a.findingCount)
}

function enginesForPhase(phaseId, productionEngines) {
  const allowed = new Set(PHASE_ENGINE_MAP[phaseId] || [])
  return productionEngines.filter((e) => allowed.has(e.id))
}

function parseFindingsResponse(data) {
  return Array.isArray(data) ? data : Array.isArray(data?.findings) ? data.findings : []
}

function normalizeApiChains(apiChains) {
  if (!Array.isArray(apiChains) || !apiChains.length) return []

  return apiChains.map((chain) => {
    const steps = Array.isArray(chain.steps) ? chain.steps : []
    const phaseFindings = Object.fromEntries(PHASE_SEQUENCE.map((id) => [id, []]))

    for (const step of steps) {
      const order = Number(step.step ?? 0)
      const phaseIdx = Math.max(0, Math.min(PHASE_SEQUENCE.length - 1, order))
      const phaseId = PHASE_SEQUENCE[phaseIdx]
      const label = [step.method, step.url].filter(Boolean).join(' · ') || 'Privilege escalation step'
      phaseFindings[phaseId].push(label)
    }

    const phasesWithFindings = PHASE_SEQUENCE
      .map((id, i) => (phaseFindings[id].length > 0 ? i : -1))
      .filter((i) => i >= 0)
    const highestPhaseIdx = phasesWithFindings.length ? Math.max(...phasesWithFindings) : -1
    const completedPhases = phasesWithFindings.length
      ? Math.min(highestPhaseIdx + 1, PHASE_SEQUENCE.length - 1)
      : 0
    const riskScore = chain.phase_progress != null
      ? Math.round(Number(chain.phase_progress))
      : Math.round((completedPhases / PHASES.length) * 100)

    const target = chain.client_id != null
      ? `Client ${chain.client_id}`
      : chain.name || 'Unknown target'
    const discoveredAt = steps.map((s) => s.at).filter(Boolean).sort()[0] || null

    return {
      id: chain.id || `chain-${target}`,
      name: chain.name || `${target} attack chain`,
      severity: (chain.severity || 'medium').toLowerCase(),
      completedPhases,
      totalPhases: PHASES.length,
      riskScore,
      target,
      discoveredAt,
      techniques: [],
      summary: steps.length
        ? `${steps.length} privilege-escalation step${steps.length === 1 ? '' : 's'} mapped across ${phasesWithFindings.length} kill-chain phase${phasesWithFindings.length === 1 ? '' : 's'}.`
        : chain.name || 'Kill chain from SOC telemetry.',
      phaseFindings,
      findingCount: steps.length,
    }
  })
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function KillChainOrchestrator() {
  const { t } = useTranslation()
  const { engines: productionEngines, productionCount, loading: enginesLoading } = useProductionEngines()
  const [findings, setFindings] = useState([])
  const [chainsFromApi, setChainsFromApi] = useState(null)
  const [execKpis, setExecKpis] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeChain, setActiveChain] = useState(null)
  const [activePhase, setActivePhase] = useState(null)
  const [filterSeverity, setFilterSeverity] = useState('all')

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoading(true)
      setError(null)
      try {
        const [chainsRes, findingsRes, kpisRes] = await Promise.all([
          apiFetch('/api/soc/kill-chains'),
          apiFetch('/api/findings?limit=2000'),
          apiFetch('/api/dashboard/exec-kpis'),
        ])
        const chainsData = chainsRes.ok ? await chainsRes.json() : null
        const apiChains = normalizeApiChains(chainsData?.chains)
        if (!findingsRes.ok && !apiChains.length) throw new Error(`Findings HTTP ${findingsRes.status}`)
        const findingsData = findingsRes.ok ? await findingsRes.json() : null
        const kpisData = kpisRes.ok ? await kpisRes.json() : null
        if (cancelled) return
        setChainsFromApi(apiChains.length ? apiChains : null)
        setFindings(parseFindingsResponse(findingsData))
        setExecKpis(kpisData)
      } catch (e) {
        if (!cancelled) setError(e.message || 'Failed to load kill-chain data')
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const chains = useMemo(
    () => chainsFromApi ?? buildChainsFromFindings(findings),
    [chainsFromApi, findings],
  )

  const phasesWithEngines = useMemo(
    () => PHASES.map((phase) => ({
      ...phase,
      engines: enginesForPhase(phase.id, productionEngines).map((e) => e.label),
    })),
    [productionEngines],
  )

  const filteredChains = useMemo(
    () => (filterSeverity === 'all' ? chains : chains.filter((c) => c.severity === filterSeverity)),
    [chains, filterSeverity],
  )

  useEffect(() => {
    if (!filteredChains.length) {
      setActiveChain(null)
      return
    }
    if (!activeChain || !filteredChains.some((c) => c.id === activeChain.id)) {
      setActiveChain(filteredChains[0])
      setActivePhase(null)
    }
  }, [filteredChains, activeChain])

  const overallRisk = useMemo(() => {
    if (!chains.length) return execKpis?.security_score != null ? 100 - execKpis.security_score : 0
    return Math.round(chains.reduce((a, c) => a + c.riskScore, 0) / chains.length)
  }, [chains, execKpis])

  const techniquesMapped = useMemo(() => {
    const fromFindings = new Set(
      findings.map((f) => f.mitre_attack || f.mitre || f.technique).filter(Boolean),
    )
    if (fromFindings.size) return fromFindings.size
    return execKpis?.mitre_top?.length ?? 0
  }, [findings, execKpis])

  const phasesCovered = useMemo(() => {
    const covered = new Set(findings.map(resolveFindingPhase))
    return covered.size
  }, [findings])

  const isLoading = loading || enginesLoading

  return (
    <PageShell
      title={t('pages.killChainOrchestrator.title')}
      subtitle={t('pages.killChainOrchestrator.subtitle')}
      badge="ATT&CK"
      badgeColor="#ef4444"
    >
      <p className="text-xs text-white/45 font-mono mb-6">
        Chains from <code>/api/soc/kill-chains</code>
        {chainsFromApi ? ' (live)' : ' — falling back to findings grouped by target'}.
        Engine mappings from <code>/api/engines/production</code>
        {productionCount > 0 ? ` (${productionCount} live)` : ''}. KPIs augmented by{' '}
        <code>/api/dashboard/exec-kpis</code> when findings are sparse.
      </p>

      {error && (
        <div className="mb-6 p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm">
          Couldn't load kill-chain data: {error}.
        </div>
      )}

      {/* ── KPI Bar ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
        {[
          { label: 'Active Chains', value: isLoading ? '…' : chains.length, color: '#22d3ee' },
          { label: 'Avg Risk Score', value: isLoading ? '…' : `${overallRisk}/100`, color: '#ef4444' },
          { label: 'Techniques Mapped', value: isLoading ? '…' : techniquesMapped, color: '#f97316' },
          { label: 'Phases Covered', value: isLoading ? '…' : `${phasesCovered}/${PHASES.length}`, color: '#10b981' },
        ].map((kpi) => (
          <div key={kpi.label} className="rounded-2xl border border-white/10 bg-white/5 p-4 text-center">
            <div className="text-2xl font-bold" style={{ color: kpi.color }}>{kpi.value}</div>
            <div className="text-[11px] text-white/50 mt-1">{kpi.label}</div>
          </div>
        ))}
      </div>

      {isLoading ? (
        <div className="rounded-2xl border border-white/10 bg-white/5 p-8 text-center text-sm text-white/45">
          Loading findings and production engines…
        </div>
      ) : chains.length === 0 ? (
        <EmptyState
          icon="radar"
          title={t('pages.killChainOrchestrator.no_findings_title')}
          body="Kill-chain views are built from live scan findings. Run engines against a target to populate reconnaissance through exfiltration phases."
          cta={{ label: 'Open Findings C2', to: '/findings' }}
          secondary={{ label: 'Browse engines', to: '/engines' }}
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* ── Left: Chain List ── */}
          <div className="space-y-3">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-semibold text-white/80">Attack Chains</h2>
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="text-xs bg-black/40 border border-white/10 rounded-lg px-2 py-1 text-white/60 focus:outline-none"
              >
                <option value="all">All Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
              </select>
            </div>

            {filteredChains.length === 0 ? (
              <EmptyState
                compact
                icon="search-x"
                title={t('pages.killChainOrchestrator.no_match_title')}
                body="Try a different severity filter or review findings in the command center."
                cta={{ label: 'View findings', to: '/findings' }}
              />
            ) : (
              filteredChains.map((chain) => {
                const sm = SEVERITY_META[chain.severity] ?? SEVERITY_META.medium
                const progress = Math.round((chain.completedPhases / chain.totalPhases) * 100)
                return (
                  <motion.button
                    key={chain.id}
                    layout
                    whileHover={{ scale: 1.01 }}
                    onClick={() => { setActiveChain(chain); setActivePhase(null) }}
                    className={`w-full text-left rounded-2xl border p-4 transition-all ${
                      activeChain?.id === chain.id
                        ? 'border-[#ef4444]/50 bg-[#ef4444]/10'
                        : 'border-white/10 bg-white/5 hover:bg-white/10'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold text-white truncate pr-2">{chain.name}</span>
                      <span
                        className="text-[10px] font-mono px-2 py-0.5 rounded border flex-shrink-0"
                        style={{ color: sm.color, borderColor: `${sm.color}40`, backgroundColor: `${sm.color}10` }}
                      >
                        {sm.label}
                      </span>
                    </div>
                    <div className="text-[11px] text-white/40 mb-3 truncate">{chain.target}</div>
                    <div className="w-full bg-white/10 rounded-full h-1.5 mb-1">
                      <div className="h-1.5 rounded-full transition-all" style={{ width: `${progress}%`, backgroundColor: sm.color }} />
                    </div>
                    <div className="flex justify-between text-[10px] text-white/40">
                      <span>{chain.completedPhases}/{chain.totalPhases} phases</span>
                      <span>
                        Risk: <span className="font-mono" style={{ color: sm.color }}>{chain.riskScore}</span>
                      </span>
                    </div>
                  </motion.button>
                )
              })
            )}
          </div>

          {/* ── Center: Phase Timeline ── */}
          <div className="lg:col-span-2 space-y-4">
            {activeChain ? (
              <>
                <div className="rounded-2xl border border-white/10 bg-white/5 p-5 mb-2">
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div>
                      <h2 className="text-base font-bold text-white">{activeChain.name}</h2>
                      <div className="text-[11px] text-white/40 mt-1">
                        Target: <span className="text-[#22d3ee]/80">{activeChain.target}</span>
                        {activeChain.discoveredAt && (
                          <>
                            {' · '}
                            Detected:{' '}
                            <span className="text-white/60">{activeChain.discoveredAt.slice(0, 10)}</span>
                          </>
                        )}
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <div className="text-2xl font-bold text-[#ef4444]">{activeChain.riskScore}</div>
                      <div className="text-[10px] text-white/40">Risk Score</div>
                    </div>
                  </div>
                  <p className="text-xs text-white/60 leading-relaxed">{activeChain.summary}</p>
                  {activeChain.techniques.length > 0 ? (
                    <div className="flex flex-wrap gap-2 mt-3">
                      {activeChain.techniques.map((t) => (
                        <Link
                          key={t}
                          to={`/findings?mitre=${encodeURIComponent(t)}`}
                          className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#6366f1]/20 border border-[#6366f1]/30 text-[#a5b4fc] hover:bg-[#6366f1]/30"
                        >
                          {t}
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[10px] text-white/35 mt-3 font-mono">
                      No MITRE technique IDs on these findings yet — engines will populate{' '}
                      <code>mitre_attack</code> as scans complete.
                    </p>
                  )}
                </div>

                {/* Phase pipeline */}
                <div className="space-y-2">
                  {phasesWithEngines.map((phase, idx) => {
                    const phaseFindingLabels = activeChain.phaseFindings[phase.id] ?? []
                    const isCompleted = idx < activeChain.completedPhases
                    const isActive = idx === activeChain.completedPhases
                    const isExpanded = activePhase === phase.id

                    return (
                      <motion.div
                        key={phase.id}
                        layout
                        className={`rounded-2xl border transition-all ${
                          isExpanded ? 'border-white/20 bg-white/8' :
                          isCompleted ? 'border-white/10 bg-white/5' :
                          isActive ? 'bg-white/5' :
                          'border-white/5 bg-black/20 opacity-50'
                        }`}
                        style={isExpanded ? { borderColor: `${phase.color}40` } : {}}
                      >
                        <button
                          type="button"
                          className="w-full flex items-center gap-3 p-4 text-left"
                          onClick={() => setActivePhase(isExpanded ? null : phase.id)}
                        >
                          <div
                            className="w-8 h-8 rounded-full flex items-center justify-center text-sm flex-shrink-0 border-2"
                            style={{
                              borderColor: isCompleted || isActive ? phase.color : 'rgba(255,255,255,0.1)',
                              backgroundColor: isCompleted ? `${phase.color}20` : 'transparent',
                            }}
                          >
                            {isCompleted ? '✓' : <span>{phase.icon}</span>}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-semibold text-white">{phase.label}</span>
                              <span className="text-[10px] font-mono text-white/30">{phase.mitre}</span>
                              {isActive && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#f59e0b]/20 text-[#f59e0b] border border-[#f59e0b]/30 animate-pulse">
                                  ACTIVE
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-white/40 truncate">{phase.description}</div>
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0">
                            {phaseFindingLabels.length > 0 && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/30">
                                {phaseFindingLabels.length} findings
                              </span>
                            )}
                            <span className="text-white/30 text-xs">{isExpanded ? '▲' : '▼'}</span>
                          </div>
                        </button>

                        <AnimatePresence>
                          {isExpanded && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: 'auto' }}
                              exit={{ opacity: 0, height: 0 }}
                              className="overflow-hidden"
                            >
                              <div className="px-4 pb-4 space-y-3">
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                  <div>
                                    <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">
                                      Production Engines
                                    </div>
                                    {phase.engines.length > 0 ? (
                                      <div className="flex flex-wrap gap-1">
                                        {phase.engines.map((e) => (
                                          <span key={e} className="text-[10px] px-2 py-0.5 rounded bg-white/10 text-white/60 border border-white/10">
                                            {e}
                                          </span>
                                        ))}
                                      </div>
                                    ) : (
                                      <p className="text-[10px] text-white/35">No production engines mapped to this phase.</p>
                                    )}
                                  </div>
                                  <div>
                                    <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">MITRE Techniques</div>
                                    <div className="flex flex-wrap gap-1">
                                      {phase.techniques.map((t) => (
                                        <span key={t} className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#6366f1]/20 text-[#a5b4fc] border border-[#6366f1]/30">
                                          {t}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                                {phaseFindingLabels.length > 0 ? (
                                  <div>
                                    <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">Findings</div>
                                    <ul className="space-y-1">
                                      {phaseFindingLabels.map((f, i) => (
                                        <li key={i} className="text-xs text-white/70 flex items-start gap-2">
                                          <span className="text-[#ef4444] mt-0.5">▸</span>
                                          {f}
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                ) : (
                                  <p className="text-[10px] text-white/35">No findings in this phase for this target.</p>
                                )}
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </motion.div>
                    )
                  })}
                </div>
              </>
            ) : (
              <EmptyState
                compact
                icon="inbox"
                title={t('pages.killChainOrchestrator.select_chain_title')}
                body="Choose a target chain from the list to inspect phase progression and mapped findings."
              />
            )}
          </div>
        </div>
      )}
    </PageShell>
  )
}
