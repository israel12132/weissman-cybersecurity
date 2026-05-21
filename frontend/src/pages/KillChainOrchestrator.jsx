/**
 * Kill Chain Orchestrator
 *
 * MITRE ATT&CK-aligned kill chain orchestration: 7-phase attack simulation,
 * engine-to-phase mapping, live risk scoring, and chain-of-execution visualization.
 * Route: /kill-chain
 */
import React, { useState, useMemo, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

// ─── Kill Chain Phases ────────────────────────────────────────────────────────

// Fallback phases when API is unavailable
const FALLBACK_PHASES = [
  {
    id: 'reconnaissance',
    label: 'Reconnaissance',
    icon: '🔭',
    color: '#22d3ee',
    mitre: 'TA0043',
    techniques: ['T1595', 'T1592', 'T1589', 'T1590', 'T1597', 'T1598'],
    description: 'Gather intelligence on target systems, networks, employees, and infrastructure before active exploitation.',
    engines: ['OSINT', 'ASM', 'Subdomain Takeover', 'Leak Hunter', 'GitHub Monitor', 'CVE Scanner'],
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
    engines: ['Zero-Day Finder', 'Exploit DB Lookup', 'Payload Generator', 'Phishing Kit Scanner'],
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
    engines: ['Phishing Kit Scanner', 'XSS Engine', 'Open Redirect', 'SSRF Engine', 'OAuth2 Scanner', 'Supply Chain Analyzer'],
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
    engines: ['Web App Scanner', 'API Fuzzer', 'BOLA/IDOR Engine', 'JWT Attack Engine', 'SQLi/XSS Engine', 'XXE Engine'],
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
    engines: ['EDR Evasion Engine', 'Anti-Forensics Engine', 'Container Registry Engine', 'K8s Container Engine'],
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
    engines: ['DNS Tunneling Engine', 'OAST/OOB Engine', 'WebSocket Attack Engine', 'mTLS/gRPC Engine'],
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
    engines: ['Data Exfil Scanner', 'Cloud Asset Discovery', 'CSPM Compliance', 'S3/Blob Enumeration'],
    riskWeight: 0.10,
  },
]

// ─── Sample Chains ────────────────────────────────────────────────────────────

// Fallback chains when API is unavailable
const FALLBACK_CHAINS = [
  {
    id: 'chain-001',
    name: 'Cloud-to-AD Lateral Movement',
    severity: 'critical',
    completedPhases: 5,
    totalPhases: 7,
    riskScore: 94,
    target: 'enterprise-corp.com',
    discoveredAt: '2026-05-16T14:22:00Z',
    techniques: ['T1078', 'T1021', 'T1484', 'T1087', 'T1003'],
    summary: 'Attacker compromises cloud credentials via phishing, pivots through VPN to on-prem AD, escalates to Domain Admin.',
    phaseFindings: {
      reconnaissance: ['Leaked AWS creds on Pastebin', 'Employee email enumeration via LinkedIn'],
      weaponization: ['Custom phishing kit targeting O365 login'],
      delivery: ['Spear-phish to 3 finance employees'],
      exploitation: ['Successful OAuth2 token hijack', 'SSRF → IMDS credential theft'],
      installation: ['Persistence via scheduled task', 'Golden ticket forged'],
      c2: [],
      exfiltration: [],
    },
  },
  {
    id: 'chain-002',
    name: 'Supply Chain → RCE Chain',
    severity: 'critical',
    completedPhases: 4,
    totalPhases: 7,
    riskScore: 88,
    target: 'ci-pipeline.internal',
    discoveredAt: '2026-05-14T09:15:00Z',
    techniques: ['T1195', 'T1059', 'T1543', 'T1036', 'T1041'],
    summary: 'Malicious npm package injected into CI/CD pipeline executes arbitrary code on build servers.',
    phaseFindings: {
      reconnaissance: ['Repo enumeration via GitHub API', 'Dependency manifest harvested'],
      weaponization: ['Typosquatted npm package "lodash-util" uploaded'],
      delivery: ['Package installed via automated dependency update bot'],
      exploitation: ['Postinstall script executed arbitrary shell commands'],
      installation: [],
      c2: [],
      exfiltration: [],
    },
  },
  {
    id: 'chain-003',
    name: 'SSRF → IMDS → IAM Escalation',
    severity: 'high',
    completedPhases: 3,
    totalPhases: 7,
    riskScore: 74,
    target: 'webapp.acmecorp.com',
    discoveredAt: '2026-05-12T16:45:00Z',
    techniques: ['T1190', 'T1552', 'T1078', 'T1537'],
    summary: 'SSRF in web application reaches AWS IMDS to steal IAM role credentials, enabling privilege escalation.',
    phaseFindings: {
      reconnaissance: ['Cloud provider identified via response headers', 'EC2 instance metadata service accessible'],
      weaponization: [],
      delivery: [],
      exploitation: ['SSRF to 169.254.169.254 returns IAM role creds', 'API key with S3:* permissions found'],
      installation: [],
      c2: [],
      exfiltration: [],
    },
  },
]

const SEVERITY_META = {
  critical: { color: '#ef4444', label: 'CRITICAL' },
  high:     { color: '#f97316', label: 'HIGH' },
  medium:   { color: '#f59e0b', label: 'MEDIUM' },
  low:      { color: '#22d3ee', label: 'LOW' },
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function KillChainOrchestrator() {
  const [phases, setPhases] = useState([])
  const [chains, setChains] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeChain, setActiveChain] = useState(null)
  const [activePhase, setActivePhase] = useState(null)
  const [filterSeverity, setFilterSeverity] = useState('all')

  // Load kill chain data from API
  useEffect(() => {
    const loadData = async () => {
      setLoading(true)
      setError(null)

      try {
        // Fetch kill chain phases
        const phasesRes = await apiFetch('/api/kill-chain/phases')
        if (phasesRes.ok) {
          const phasesData = await phasesRes.json()
          setPhases(Array.isArray(phasesData) ? phasesData : phasesData.phases || [])
        } else if (phasesRes.status === 404) {
          // API not implemented, use fallback
          setPhases(FALLBACK_PHASES)
        } else {
          throw new Error(`Failed to load phases (HTTP ${phasesRes.status})`)
        }

        // Fetch attack chains
        const chainsRes = await apiFetch('/api/kill-chain/chains')
        if (chainsRes.ok) {
          const chainsData = await chainsRes.json()
          const chainsArray = Array.isArray(chainsData) ? chainsData : chainsData.chains || []
          setChains(chainsArray)
          if (chainsArray.length > 0) {
            setActiveChain(chainsArray[0])
          }
        } else if (chainsRes.status === 404) {
          // API not implemented, use fallback
          setChains(FALLBACK_CHAINS)
          setActiveChain(FALLBACK_CHAINS[0])
        } else {
          throw new Error(`Failed to load attack chains (HTTP ${chainsRes.status})`)
        }
      } catch (err) {
        setError(err?.message || 'Failed to load kill chain data')
        // Use fallback data on error
        setPhases(FALLBACK_PHASES)
        setChains(FALLBACK_CHAINS)
        setActiveChain(FALLBACK_CHAINS[0])
      } finally {
        setLoading(false)
      }
    }

    loadData()
  }, [])

  const filteredChains = useMemo(
    () => filterSeverity === 'all'
      ? chains
      : chains.filter((c) => c.severity === filterSeverity),
    [chains, filterSeverity],
  )

  const overallRisk = useMemo(
    () => chains.length > 0 ? Math.round(chains.reduce((a, c) => a + c.riskScore, 0) / chains.length) : 0,
    [chains],
  )

  const totalTechniques = useMemo(
    () => chains.reduce((a, c) => a + c.techniques.length, 0),
    [chains],
  )

  return (
    <PageShell
      title="Kill Chain Orchestrator"
      subtitle="MITRE ATT&CK · 7-Phase Attack Simulation"
      badge="ATT&CK"
      badgeColor="#ef4444"
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
            <div className="w-8 h-8 border-2 border-red-500/40 border-t-red-500 rounded-full animate-spin mx-auto" />
            <p className="text-sm font-mono text-white/40">Loading kill chain data...</p>
          </div>
        </div>
      )}

      {/* ── KPI Bar ── */}
      {!loading && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
          {[
            { label: 'Active Chains', value: chains.length, color: '#22d3ee' },
            { label: 'Avg Risk Score', value: `${overallRisk}/100`, color: '#ef4444' },
            { label: 'Techniques Mapped', value: totalTechniques, color: '#f97316' },
            { label: 'Phases Covered', value: phases.length, color: '#10b981' },
          ].map((kpi) => (
            <div key={kpi.label} className="rounded-2xl border border-white/10 bg-white/5 p-4 text-center">
              <div className="text-2xl font-bold" style={{ color: kpi.color }}>{kpi.value}</div>
              <div className="text-[11px] text-white/50 mt-1">{kpi.label}</div>
            </div>
          ))}
        </div>
      )}

      {!loading && (
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
              <div className="rounded-2xl border border-white/10 bg-black/20 p-12 text-center">
                <p className="text-sm text-white/40">No attack chains found</p>
              </div>
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
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border flex-shrink-0"
                    style={{ color: sm.color, borderColor: `${sm.color}40`, backgroundColor: `${sm.color}10` }}>
                    {sm.label}
                  </span>
                </div>
                <div className="text-[11px] text-white/40 mb-3 truncate">{chain.target}</div>
                <div className="w-full bg-white/10 rounded-full h-1.5 mb-1">
                  <div className="h-1.5 rounded-full transition-all" style={{ width: `${progress}%`, backgroundColor: sm.color }} />
                </div>
                <div className="flex justify-between text-[10px] text-white/40">
                  <span>{chain.completedPhases}/{chain.totalPhases} phases</span>
                  <span>Risk: <span className="font-mono" style={{ color: sm.color }}>{chain.riskScore}</span></span>
                </div>
                </motion.button>
              )
              })
            )}
          </div>

          {/* ── Center: Phase Timeline ── */}
          <div className="lg:col-span-2 space-y-4">
            {activeChain && (
            <>
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5 mb-2">
                <div className="flex items-start justify-between gap-4 mb-3">
                  <div>
                    <h2 className="text-base font-bold text-white">{activeChain.name}</h2>
                    <div className="text-[11px] text-white/40 mt-1">
                      Target: <span className="text-[#22d3ee]/80">{activeChain.target}</span>
                      {' · '}
                      Detected: <span className="text-white/60">{activeChain.discoveredAt.slice(0, 10)}</span>
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <div className="text-2xl font-bold text-[#ef4444]">{activeChain.riskScore}</div>
                    <div className="text-[10px] text-white/40">Risk Score</div>
                  </div>
                </div>
                <p className="text-xs text-white/60 leading-relaxed">{activeChain.summary}</p>
                <div className="flex flex-wrap gap-2 mt-3">
                  {activeChain.techniques.map((t) => (
                    <span key={t} className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#6366f1]/20 border border-[#6366f1]/30 text-[#a5b4fc]">
                      {t}
                    </span>
                  ))}
                </div>
              </div>

              {/* Phase pipeline */}
              <div className="space-y-2">
                {phases.map((phase, idx) => {
                  const findings = activeChain.phaseFindings[phase.id] ?? []
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
                        isActive ? `bg-white/5` :
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
                          {findings.length > 0 && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/30">
                              {findings.length} findings
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
                                  <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">Mapped Engines</div>
                                  <div className="flex flex-wrap gap-1">
                                    {phase.engines.map((e) => (
                                      <span key={e} className="text-[10px] px-2 py-0.5 rounded bg-white/10 text-white/60 border border-white/10">
                                        {e}
                                      </span>
                                    ))}
                                  </div>
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
                              {findings.length > 0 && (
                                <div>
                                  <div className="text-[10px] uppercase tracking-widest text-white/40 mb-2">Findings</div>
                                  <ul className="space-y-1">
                                    {findings.map((f, i) => (
                                      <li key={i} className="text-xs text-white/70 flex items-start gap-2">
                                        <span className="text-[#ef4444] mt-0.5">▸</span>
                                        {f}
                                      </li>
                                    ))}
                                  </ul>
                                </div>
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
            )}
          </div>
        </div>
      )}
    </PageShell>
  )
}
