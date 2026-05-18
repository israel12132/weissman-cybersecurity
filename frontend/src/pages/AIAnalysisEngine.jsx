/**
 * AI Analysis Engine
 *
 * AI-powered attack pattern recognition, false-positive reduction,
 * threat correlation, and composite risk scoring dashboard.
 * Route: /ai-analysis
 */
import React, { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'

// ─── Attack Patterns ──────────────────────────────────────────────────────────

const ATTACK_PATTERNS = [
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

const CATEGORY_META = {
  cloud_attacks:  { label: 'Cloud Attacks',   color: '#06b6d4', icon: '☁️' },
  supply_chain:   { label: 'Supply Chain',    color: '#f97316', icon: '⛓️' },
  identity:       { label: 'Identity',        color: '#a78bfa', icon: '🆔' },
  cloud_native:   { label: 'Cloud Native',    color: '#34d399', icon: '🐳' },
  web_app:        { label: 'Web App',         color: '#f59e0b', icon: '🌐' },
}

const SEVERITY_META = {
  critical: { color: '#ef4444', label: 'CRITICAL' },
  high:     { color: '#f97316', label: 'HIGH' },
  medium:   { color: '#f59e0b', label: 'MEDIUM' },
  low:      { color: '#22d3ee', label: 'LOW' },
}

// ─── Correlation Feed ─────────────────────────────────────────────────────────

const CORRELATIONS = [
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

// ─── Component ────────────────────────────────────────────────────────────────

export default function AIAnalysisEngine() {
  const [selectedPattern, setSelectedPattern] = useState(null)
  const [filterCategory, setFilterCategory] = useState('all')
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [activeTab, setActiveTab] = useState('patterns')

  const filtered = useMemo(() => {
    return ATTACK_PATTERNS.filter((p) => {
      if (filterCategory !== 'all' && p.category !== filterCategory) return false
      if (filterSeverity !== 'all' && p.severity !== filterSeverity) return false
      return true
    })
  }, [filterCategory, filterSeverity])

  const avgConfidence = useMemo(
    () => Math.round((ATTACK_PATTERNS.reduce((a, p) => a + p.confidence, 0) / ATTACK_PATTERNS.length) * 100),
    [],
  )

  return (
    <PageShell
      title="AI Analysis Engine"
      subtitle="Attack Pattern Recognition · Threat Correlation · Risk Scoring"
      badge="AI"
      badgeColor="#a78bfa"
    >
      {/* ── KPI Bar ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
        {[
          { label: 'Patterns Detected', value: ATTACK_PATTERNS.length, color: '#a78bfa' },
          { label: 'Avg Confidence', value: `${avgConfidence}%`, color: '#10b981' },
          { label: 'Correlations', value: CORRELATIONS.length, color: '#f97316' },
          { label: 'Critical Patterns', value: ATTACK_PATTERNS.filter(p => p.severity === 'critical').length, color: '#ef4444' },
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
                    <div className="flex items-center gap-2">
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
          {CORRELATIONS.map((corr) => (
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
                      const p = ATTACK_PATTERNS.find((x) => x.id === pid)
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
    </PageShell>
  )
}
