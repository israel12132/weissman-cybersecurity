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
import { useState, useMemo, useEffect, useCallback } from 'react'
import { Link } from 'react-router'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import { apiFetch } from '../utils/apiFetch'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'
import { useProductionEngines } from '../lib/useProductionEngines'
import Button from '../components/ui/Button'

// ─── Kill Chain Phases (MITRE scaffolding — engines/findings are live) ────────

const PHASE_DEFS = [
  { id: 'reconnaissance', icon: '🔭', color: '#22d3ee', mitre: 'TA0043', techniques: ['T1595', 'T1592', 'T1589', 'T1590', 'T1597', 'T1598'], riskWeight: 0.10 },
  { id: 'weaponization', icon: '⚗️', color: '#a78bfa', mitre: 'TA0001', techniques: ['T1587', 'T1588', 'T1583', 'T1584'], riskWeight: 0.15 },
  { id: 'delivery', icon: '📦', color: '#f97316', mitre: 'TA0001', techniques: ['T1566', 'T1190', 'T1195', 'T1091'], riskWeight: 0.20 },
  { id: 'exploitation', icon: '💥', color: '#ef4444', mitre: 'TA0002', techniques: ['T1203', 'T1211', 'T1068', 'T1210'], riskWeight: 0.25 },
  { id: 'installation', icon: '🔩', color: '#f59e0b', mitre: 'TA0003', techniques: ['T1543', 'T1547', 'T1574', 'T1505'], riskWeight: 0.10 },
  { id: 'c2', icon: '📡', color: '#6366f1', mitre: 'TA0011', techniques: ['T1071', 'T1090', 'T1572', 'T1008'], riskWeight: 0.10 },
  { id: 'exfiltration', icon: '📤', color: '#10b981', mitre: 'TA0010', techniques: ['T1041', 'T1048', 'T1537', 'T1020'], riskWeight: 0.10 },
]

function buildPhases(t) {
  return PHASE_DEFS.map((phase) => ({
    ...phase,
    label: t(`pages.killChainOrchestrator.phases.${phase.id}.label`),
    description: t(`pages.killChainOrchestrator.phases.${phase.id}.description`),
  }))
}

const PHASE_SEQUENCE = PHASE_DEFS.map((p) => p.id)

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

function severityMeta(sev, t) {
  const color = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#f59e0b',
    low: '#22d3ee',
    info: '#6b7280',
  }[sev] ?? '#f59e0b'
  const labelKey = `pages.killChainOrchestrator.severity_${sev}`
  return { color, label: t(labelKey, { defaultValue: sev?.toUpperCase() }) }
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
      const completedPhases = phasesWithFindings.length
        ? Math.min(highestPhaseIdx + 1, PHASE_SEQUENCE.length)
        : 0

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
        totalPhases: PHASE_DEFS.length,
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

function buildEngineStatusFromFindings(findings) {
  const map = {}
  for (const f of findings) {
    const id = normalizeSource(f)
    if (!id) continue
    const sev = (f.severity || 'info').toLowerCase()
    const at = f.discovered_at || f.created_at || ''
    if (!map[id]) {
      map[id] = { findingCount: 0, maxSeverity: 'info', lastAt: at }
    }
    map[id].findingCount += 1
    if ((SEVERITY_RANK[sev] || 0) > (SEVERITY_RANK[map[id].maxSeverity] || 0)) {
      map[id].maxSeverity = sev
    }
    if (at && (!map[id].lastAt || at > map[id].lastAt)) {
      map[id].lastAt = at
    }
  }
  return map
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
      ? Math.min(highestPhaseIdx + 1, PHASE_SEQUENCE.length)
      : 0
    const riskScore = chain.phase_progress != null
      ? Math.round(Number(chain.phase_progress))
      : Math.round((completedPhases / PHASE_DEFS.length) * 100)

    const target = chain.client_id != null
      ? `Client ${chain.client_id}`
      : chain.name || 'Unknown target'
    const discoveredAt = steps.map((s) => s.at).filter(Boolean).sort()[0] || null

    return {
      id: chain.id || `chain-${target}`,
      name: chain.name || `${target} attack chain`,
      severity: (chain.severity || 'medium').toLowerCase(),
      completedPhases,
      totalPhases: PHASE_DEFS.length,
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

  const loadKillChainData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const FAILED = Symbol('failed')
      const [chainsData, findingsData, kpisData] = await Promise.all([
        apiFetch('/api/soc/kill-chains').catch(() => null),
        apiFetch('/api/findings?limit=2000').catch(() => FAILED),
        apiFetch('/api/dashboard/exec-kpis').catch(() => null),
      ])
      const apiChains = normalizeApiChains(chainsData?.chains)
      if (findingsData === FAILED && !apiChains.length) throw new Error(t('pages.killChainOrchestrator.load_error', { error: '' }))
      setChainsFromApi(apiChains.length ? apiChains : null)
      setFindings(parseFindingsResponse(findingsData === FAILED ? null : findingsData))
      setExecKpis(kpisData)
    } catch (e) {
      setError(e.message || t('pages.killChainOrchestrator.load_error', { error: '' }))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    loadKillChainData()
  }, [loadKillChainData])

  const chains = useMemo(
    () => chainsFromApi ?? buildChainsFromFindings(findings),
    [chainsFromApi, findings],
  )

  const engineStatusById = useMemo(
    () => buildEngineStatusFromFindings(findings),
    [findings],
  )

  const phases = useMemo(() => buildPhases(t), [t])

  const phasesWithEngines = useMemo(
    () => phases.map((phase) => ({
      ...phase,
      engines: enginesForPhase(phase.id, productionEngines),
    })),
    [phases, productionEngines],
  )

  const filteredChains = useMemo(
    () => (filterSeverity === 'all' ? chains : chains.filter((c) => c.severity === filterSeverity)),
    [chains, filterSeverity],
  )

  const chainListFindings = useMemo(() => filteredChains.map((c) => ({
    id: c.id,
    severity: c.severity || 'medium',
    title: c.name,
    type: 'kill_chain',
    description: c.summary || '',
    resource: c.target || '',
  })), [filteredChains])

  const {
    searchQuery,
    setSearchQuery,
    filteredFindings: filteredChainFindings,
  } = useFindingsWorkbench(chainListFindings, {
    csvPrefix: 'weissman-kill-chains',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleChains = useMemo(() => {
    if (!searchQuery.trim()) return filteredChains
    const ids = new Set(filteredChainFindings.map((f) => String(f.id)))
    return filteredChains.filter((c) => ids.has(String(c.id)))
  }, [filteredChains, filteredChainFindings, searchQuery])

  useEffect(() => {
    if (!visibleChains.length) {
      setActiveChain(null)
      return
    }
    if (!activeChain || !visibleChains.some((c) => c.id === activeChain.id)) {
      setActiveChain(visibleChains[0])
      setActivePhase(null)
    }
  }, [visibleChains, activeChain])

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

  const { exportCsv, filteredFindings } = useFindingsWorkbench(findings, { csvPrefix: 'weissman-kill-chain' })

  return (
    <PageShell
      title={t('pages.killChainOrchestrator.title')}
      subtitle={t('pages.killChainOrchestrator.subtitle')}
      badge="ATT&CK"
      badgeColor="#ef4444"
      actions={(
        <ShellScanActions
          onRefresh={loadKillChainData}
          onExport={exportCsv}
          refreshLoading={isLoading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <p className="text-xs text-[var(--text-muted)] font-mono mb-6">
        {t('pages.killChainOrchestrator.data_source_note', {
          live: chainsFromApi ? t('pages.killChainOrchestrator.data_source_live') : t('pages.killChainOrchestrator.data_source_fallback'),
          engines: productionCount > 0 ? t('pages.killChainOrchestrator.data_source_engines', { count: productionCount }) : '',
        })}
      </p>

      {error && (
        <div className="mb-6 p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm">
          {t('pages.killChainOrchestrator.load_error', { error })}
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
        {[
          { label: t('pages.killChainOrchestrator.kpi_active_chains'), value: isLoading ? '…' : chains.length, color: '#22d3ee' },
          { label: t('pages.killChainOrchestrator.kpi_avg_risk'), value: isLoading ? '…' : `${overallRisk}/100`, color: '#ef4444' },
          { label: t('pages.killChainOrchestrator.kpi_techniques'), value: isLoading ? '…' : techniquesMapped, color: '#f97316' },
          { label: t('pages.killChainOrchestrator.kpi_phases_covered'), value: isLoading ? '…' : `${phasesCovered}/${PHASE_DEFS.length}`, color: '#10b981' },
        ].map((kpi) => (
          <div key={kpi.label} className="rounded-2xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] p-4 text-center">
            <div className="text-2xl font-bold" style={{ color: kpi.color }}>{kpi.value}</div>
            <div className="text-[11px] text-[var(--text-tertiary)] mt-1">{kpi.label}</div>
          </div>
        ))}
      </div>

      {isLoading ? (
        <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] p-8 text-center text-sm text-[var(--text-muted)]">
          {t('pages.killChainOrchestrator.loading')}
        </div>
      ) : chains.length === 0 ? (
        <EmptyState
          icon="radar"
          title={t('pages.killChainOrchestrator.no_findings_title')}
          body={t('pages.killChainOrchestrator.no_findings_body')}
          cta={{ label: t('pages.killChainOrchestrator.cta_open_findings'), to: '/findings' }}
          secondary={{ label: t('pages.killChainOrchestrator.cta_browse_engines'), to: '/engines' }}
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* ── Left: Chain List ── */}
          <div className="space-y-3">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-semibold text-[var(--text-secondary)]">{t('pages.killChainOrchestrator.attack_chains')}</h2>
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="text-xs bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg px-2 py-1 text-[var(--text-tertiary)] focus:outline-none"
              >
                <option value="all">{t('pages.killChainOrchestrator.filter_all')}</option>
                <option value="critical">{t('pages.killChainOrchestrator.filter_critical')}</option>
                <option value="high">{t('pages.killChainOrchestrator.filter_high')}</option>
                <option value="medium">{t('pages.killChainOrchestrator.filter_medium')}</option>
              </select>
            </div>

            {filteredChains.length > 0 && (
              <WeissmanListToolbar
                searchQuery={searchQuery}
                onSearchChange={setSearchQuery}
                resultCount={visibleChains.length}
                totalCount={filteredChains.length}
              />
            )}

            {filteredChains.length === 0 ? (
              <EmptyState
                compact
                icon="search-x"
                title={t('pages.killChainOrchestrator.no_match_title')}
                body={t('pages.killChainOrchestrator.no_match_body')}
                cta={{ label: t('pages.killChainOrchestrator.cta_view_findings'), to: '/findings' }}
              />
            ) : visibleChains.length === 0 ? (
              <EmptyState
                compact
                icon="search"
                title={t('weissmanFindings.filtered_title')}
                body={t('weissmanFindings.filtered_body')}
              />
            ) : (
              visibleChains.map((chain) => {
                const sm = severityMeta(chain.severity, t)
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
                        : 'border-[var(--border-default)] bg-[var(--row-hover-bg)] hover:bg-[var(--row-hover-bg)]'
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
                    <div className="text-[11px] text-[var(--text-muted)] mb-3 truncate">{chain.target}</div>
                    <div className="w-full bg-[var(--row-hover-bg)] rounded-full h-1.5 mb-1">
                      <div className="h-1.5 rounded-full transition-all" style={{ width: `${progress}%`, backgroundColor: sm.color }} />
                    </div>
                    <div className="flex justify-between text-[10px] text-[var(--text-muted)]">
                      <span>{chain.completedPhases}/{chain.totalPhases} {t('pages.killChainOrchestrator.phases_label')}</span>
                      <span>
                        {t('pages.killChainOrchestrator.risk_label')}: <span className="font-mono" style={{ color: sm.color }}>{chain.riskScore}</span>
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
                <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] p-5 mb-2">
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div>
                      <h2 className="text-base font-bold text-white">{activeChain.name}</h2>
                      <div className="text-[11px] text-[var(--text-muted)] mt-1">
                        {t('pages.killChainOrchestrator.target_label')}: <span className="text-[#22d3ee]/80">{activeChain.target}</span>
                        {activeChain.discoveredAt && (
                          <>
                            {' · '}
                            {t('pages.killChainOrchestrator.detected_label')}:{' '}
                            <span className="text-[var(--text-tertiary)]">{activeChain.discoveredAt.slice(0, 10)}</span>
                          </>
                        )}
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <div className="text-2xl font-bold text-[#ef4444]">{activeChain.riskScore}</div>
                      <div className="text-[10px] text-[var(--text-muted)]">{t('pages.killChainOrchestrator.risk_score')}</div>
                    </div>
                  </div>
                  <p className="text-xs text-[var(--text-tertiary)] leading-relaxed">{activeChain.summary}</p>
                  {activeChain.techniques.length > 0 ? (
                    <div className="flex flex-wrap gap-2 mt-3">
                      {activeChain.techniques.map((technique) => (
                        <Link
                          key={technique}
                          to={`/findings?mitre=${encodeURIComponent(technique)}`}
                          className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#6366f1]/20 border border-[#6366f1]/30 text-[#a5b4fc] hover:bg-[#6366f1]/30"
                        >
                          {technique}
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[10px] text-[var(--text-muted)] mt-3 font-mono">
                      {t('pages.killChainOrchestrator.no_mitre_hint')}
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
                          isExpanded ? 'border-[var(--border-strong)] bg-white/8' :
                          isCompleted ? 'border-[var(--border-default)] bg-[var(--row-hover-bg)]' :
                          isActive ? 'bg-[var(--row-hover-bg)]' :
                          'border-[var(--border-subtle)] bg-[var(--bg-1)] opacity-50'
                        }`}
                        style={isExpanded ? { borderColor: `${phase.color}40` } : {}}
                      >
                        <Button variant="unstyled"
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
                              <span className="text-[10px] font-mono text-[var(--text-disabled)]">{phase.mitre}</span>
                              {isActive && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#f59e0b]/20 text-[#f59e0b] border border-[#f59e0b]/30 animate-pulse">
                                  {t('pages.killChainOrchestrator.phase_active')}
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-[var(--text-muted)] truncate">{phase.description}</div>
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0">
                            {phaseFindingLabels.length > 0 && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/30">
                                {t('pages.killChainOrchestrator.findings_count', { count: phaseFindingLabels.length })}
                              </span>
                            )}
                            <span className="text-[var(--text-disabled)] text-xs">{isExpanded ? '▲' : '▼'}</span>
                          </div>
                        </Button>

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
                                    <div className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mb-2">
                                      {t('pages.killChainOrchestrator.production_engines')}
                                    </div>
                                    {phase.engines.length > 0 ? (
                                      <div className="flex flex-wrap gap-1">
                                        {phase.engines.map((e) => {
                                          const st = engineStatusById[e.id]
                                          const sm = st ? severityMeta(st.maxSeverity, t) : null
                                          return (
                                            <Link
                                              key={e.id}
                                              to={`/engines/${e.id}`}
                                              className="inline-flex items-center gap-1.5 text-[10px] px-2 py-0.5 rounded bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] border border-[var(--border-default)] hover:border-[var(--border-strong)] hover:text-[var(--text-secondary)] transition-colors"
                                            >
                                              <span>{e.label}</span>
                                              {st?.findingCount > 0 ? (
                                                <span
                                                  className="font-mono px-1 py-px rounded border"
                                                  style={{
                                                    color: sm.color,
                                                    borderColor: `${sm.color}40`,
                                                    backgroundColor: `${sm.color}12`,
                                                  }}
                                                  title={st.lastAt ? t('pages.killChainOrchestrator.last_finding', { date: st.lastAt.slice(0, 10) }) : undefined}
                                                >
                                                  {st.findingCount} · {sm.label}
                                                </span>
                                              ) : (
                                                <span className="text-[var(--text-disabled)] font-mono">{t('pages.killChainOrchestrator.idle')}</span>
                                              )}
                                            </Link>
                                          )
                                        })}
                                      </div>
                                    ) : (
                                      <p className="text-[10px] text-[var(--text-muted)]">{t('pages.killChainOrchestrator.no_engines_phase')}</p>
                                    )}
                                  </div>
                                  <div>
                                    <div className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mb-2">{t('pages.killChainOrchestrator.mitre_techniques')}</div>
                                    <div className="flex flex-wrap gap-1">
                                      {phase.techniques.map((technique) => (
                                        <span key={technique} className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#6366f1]/20 text-[#a5b4fc] border border-[#6366f1]/30">
                                          {technique}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                                {phaseFindingLabels.length > 0 ? (
                                  <div>
                                    <div className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mb-2">{t('pages.killChainOrchestrator.findings_heading')}</div>
                                    <ul className="space-y-1">
                                      {phaseFindingLabels.map((f, i) => (
                                        <li key={i} className="text-xs text-[var(--text-secondary)] flex items-start gap-2">
                                          <span className="text-[#ef4444] mt-0.5">▸</span>
                                          {f}
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                ) : (
                                  <p className="text-[10px] text-[var(--text-muted)]">{t('pages.killChainOrchestrator.no_findings_phase')}</p>
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
                body={t('pages.killChainOrchestrator.select_chain_body')}
              />
            )}
          </div>
        </div>
      )}
    </PageShell>
  )
}
