/**
 * Incident Response Center
 *
 * World-class IR management: active incidents, automated playbooks,
 * real-time timelines, containment / eradication actions, MTTR metrics.
 * Route: /incident-response
 */
import React, { useState, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'

// ─── Static demo data ─────────────────────────────────────────────────────────

const SEVERITY_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#6b7280',
}

const INITIAL_INCIDENTS = [
  {
    id: 'INC-0041',
    title: 'Ransomware Lateral Movement Detected',
    severity: 'critical',
    status: 'active',
    assignee: 'SOC Tier-3',
    created: '2026-04-20T07:14:00Z',
    updated: '2026-04-20T14:55:00Z',
    source: 'EDR / CrowdStrike',
    affectedAssets: ['DC01', 'FS02', 'WORKSTATION-44'],
    mitre: 'T1486',
    description: 'LockBit 3.0 variant detected moving laterally from compromised endpoint. Encryption activity observed on file server FS02.',
    playbook: 'ransomware',
    timeline: [
      { t: '07:14', actor: 'EDR', msg: 'Suspicious process tree on WORKSTATION-44 — mimikatz.exe child of explorer.exe' },
      { t: '07:19', actor: 'SIEM', msg: 'PsExec lateral movement to DC01 detected (Event 4648)' },
      { t: '07:31', actor: 'EDR', msg: 'File encryption loop started on FS02 — .lockbit extension appended' },
      { t: '07:45', actor: 'SOC', msg: 'Alert escalated to Tier-3 analyst' },
      { t: '08:02', actor: 'SOC', msg: 'Network segment isolated; C2 domain blocked at perimeter' },
    ],
  },
  {
    id: 'INC-0040',
    title: 'Credential Stuffing Campaign — Customer Portal',
    severity: 'high',
    status: 'containment',
    assignee: 'SOC Tier-2',
    created: '2026-04-20T03:00:00Z',
    updated: '2026-04-20T11:30:00Z',
    source: 'WAF / Cloudflare',
    affectedAssets: ['login.acme.com'],
    mitre: 'T1110.004',
    description: '180 k login attempts from 4 200+ unique IPs over 8 hours. 94 accounts compromised. MFA bypass via SIM-swapping suspected.',
    playbook: 'credential_stuffing',
    timeline: [
      { t: '03:00', actor: 'WAF', msg: 'Rate-limit threshold breached — 22 500 req/min on /api/auth/login' },
      { t: '03:07', actor: 'SIEM', msg: 'Geo-anomaly: logins from 43 countries in 7 minutes' },
      { t: '04:15', actor: 'SOC', msg: 'CAPTCHA enforcement activated; suspicious IPs added to block-list' },
      { t: '09:00', actor: 'SOC', msg: 'Forced MFA reset for 94 affected accounts' },
    ],
  },
  {
    id: 'INC-0039',
    title: 'Supply Chain Compromise — NPM Package',
    severity: 'high',
    status: 'eradication',
    assignee: 'AppSec Lead',
    created: '2026-04-19T16:00:00Z',
    updated: '2026-04-20T10:00:00Z',
    source: 'SCA / Snyk',
    affectedAssets: ['build-pipeline-prod', 'node-app-01'],
    mitre: 'T1195.001',
    description: 'Malicious code injected into dependency "event-stream@3.3.7-patch" — crypto-mining payload and data exfiltration hook.',
    playbook: 'supply_chain',
    timeline: [
      { t: '16:00', actor: 'SCA', msg: 'Malicious package flagged in node_modules — event-stream@3.3.7-patch' },
      { t: '16:18', actor: 'DevOps', msg: 'Build pipeline paused; artifact quarantine initiated' },
      { t: '18:30', actor: 'AppSec', msg: 'Reverse engineering confirmed crypto-miner + exfil webhook' },
      { t: '22:00', actor: 'AppSec', msg: 'Package removed; dependency pinned to vetted version' },
    ],
  },
  {
    id: 'INC-0038',
    title: 'Zero-Day Exploitation — Apache HTTP Server',
    severity: 'critical',
    status: 'resolved',
    assignee: 'Vuln-Mgmt',
    created: '2026-04-18T09:00:00Z',
    updated: '2026-04-19T12:00:00Z',
    source: 'IDS / Zeek',
    affectedAssets: ['web-prod-01', 'web-prod-02'],
    mitre: 'T1190',
    description: 'CVE-2026-xxxxx (CVSS 9.8) — path traversal + RCE via mod_proxy. Two production web servers compromised before patch.',
    playbook: 'zero_day',
    timeline: [
      { t: '09:00', actor: 'IDS', msg: 'Anomalous path traversal pattern detected on web-prod-01' },
      { t: '09:11', actor: 'SIEM', msg: 'Reverse shell spawned on web-prod-01 — nc callback to 195.x.x.x' },
      { t: '10:00', actor: 'SOC', msg: 'Web servers removed from load balancer; forensic image taken' },
      { t: '14:00', actor: 'Vuln-Mgmt', msg: 'Emergency patch applied; WAF virtual patch deployed' },
      { t: '12:00+1d', actor: 'SOC', msg: 'Servers restored; IOCs shared with threat intel feeds' },
    ],
  },
]

const PLAYBOOKS = {
  ransomware: {
    label: 'Ransomware Playbook',
    steps: [
      { id: 1, phase: 'Detection',     action: 'Isolate affected endpoints from network', mitre: 'T1486', done: true },
      { id: 2, phase: 'Detection',     action: 'Identify patient-zero via process tree analysis', mitre: 'T1055', done: true },
      { id: 3, phase: 'Containment',   action: 'Block C2 domains/IPs at perimeter firewall', mitre: 'T1071', done: true },
      { id: 4, phase: 'Containment',   action: 'Disable SMB shares and lateral movement paths', mitre: 'T1021.002', done: false },
      { id: 5, phase: 'Eradication',   action: 'Remove malware from all endpoints; restore from backup', mitre: 'T1485', done: false },
      { id: 6, phase: 'Recovery',      action: 'Validate backup integrity before restoration', mitre: null, done: false },
      { id: 7, phase: 'Recovery',      action: 'Re-enable production systems under monitoring', mitre: null, done: false },
      { id: 8, phase: 'Lessons Learned', action: 'Publish post-incident report & update runbooks', mitre: null, done: false },
    ],
  },
  credential_stuffing: {
    label: 'Credential Stuffing Playbook',
    steps: [
      { id: 1, phase: 'Detection',   action: 'Enable enhanced logging on auth endpoints', mitre: 'T1110', done: true },
      { id: 2, phase: 'Containment', action: 'Activate CAPTCHA and rate-limiting', mitre: 'T1110.004', done: true },
      { id: 3, phase: 'Containment', action: 'Block malicious IPs / ASNs at WAF', mitre: null, done: true },
      { id: 4, phase: 'Eradication', action: 'Force password reset for affected accounts', mitre: null, done: true },
      { id: 5, phase: 'Eradication', action: 'Enforce MFA for all active sessions', mitre: null, done: false },
      { id: 6, phase: 'Recovery',    action: 'Notify affected users per breach notification policy', mitre: null, done: false },
      { id: 7, phase: 'Lessons Learned', action: 'Evaluate Passwordless / passkeys adoption', mitre: null, done: false },
    ],
  },
  supply_chain: {
    label: 'Supply Chain Compromise Playbook',
    steps: [
      { id: 1, phase: 'Detection',   action: 'Identify all systems consuming malicious package', mitre: 'T1195.001', done: true },
      { id: 2, phase: 'Containment', action: 'Pause CI/CD pipelines; quarantine built artifacts', mitre: null, done: true },
      { id: 3, phase: 'Eradication', action: 'Remove malicious package; pin dependencies', mitre: null, done: true },
      { id: 4, phase: 'Eradication', action: 'Audit for secrets exfiltrated during compromise window', mitre: 'T1552', done: false },
      { id: 5, phase: 'Recovery',    action: 'Rebuild and redeploy from clean source', mitre: null, done: false },
      { id: 6, phase: 'Lessons Learned', action: 'Implement SLSA / Sigstore supply chain attestation', mitre: null, done: false },
    ],
  },
  zero_day: {
    label: 'Zero-Day Exploitation Playbook',
    steps: [
      { id: 1, phase: 'Detection',   action: 'Confirm exploitation via forensics / PCAP review', mitre: 'T1190', done: true },
      { id: 2, phase: 'Containment', action: 'Remove affected systems from production', mitre: null, done: true },
      { id: 3, phase: 'Containment', action: 'Deploy WAF virtual patch', mitre: null, done: true },
      { id: 4, phase: 'Eradication', action: 'Apply vendor patch or mitigate via config change', mitre: null, done: true },
      { id: 5, phase: 'Recovery',    action: 'Restore from pre-compromise backup', mitre: null, done: true },
      { id: 6, phase: 'Recovery',    action: 'Harden system with minimal attack surface', mitre: null, done: true },
      { id: 7, phase: 'Lessons Learned', action: 'Share IOCs with ISAC / threat intel community', mitre: null, done: true },
    ],
  },
}

const PHASE_COLOR = {
  Detection:       '#ef4444',
  Containment:     '#f97316',
  Eradication:     '#f59e0b',
  Recovery:        '#22d3ee',
  'Lessons Learned': '#8b5cf6',
}

const STATUS_META = {
  active:      { label: 'ACTIVE',      color: '#ef4444' },
  containment: { label: 'CONTAINMENT', color: '#f97316' },
  eradication: { label: 'ERADICATION', color: '#f59e0b' },
  resolved:    { label: 'RESOLVED',    color: '#22d3ee' },
}

// ─── Helper: human-readable duration ─────────────────────────────────────────

function durationHuman(created, updated) {
  const ms = new Date(updated) - new Date(created)
  const h = Math.floor(ms / 3_600_000)
  const m = Math.floor((ms % 3_600_000) / 60_000)
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

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

function IncidentRow({ incident, selected, onSelect }) {
  const sm = STATUS_META[incident.status] ?? { label: incident.status.toUpperCase(), color: '#6b7280' }
  const sc = SEVERITY_COLOR[incident.severity] ?? '#6b7280'
  return (
    <motion.button
      type="button"
      layout
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      onClick={() => onSelect(incident.id)}
      className="w-full text-left rounded-xl border p-4 transition-all hover:scale-[1.005]"
      style={{
        borderColor: selected ? `${sc}50` : 'rgba(255,255,255,0.07)',
        background: selected ? `${sc}08` : 'rgba(0,0,0,0.3)',
      }}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-0.5">
            <span className="text-[10px] font-mono text-white/35">{incident.id}</span>
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
              {incident.severity}
            </span>
          </div>
          <p className="text-xs font-semibold text-white/85 leading-snug">{incident.title}</p>
        </div>
        <div className="shrink-0 text-right">
          <div className="text-[10px] font-mono text-white/30">{incident.source}</div>
          <div className="text-[10px] font-mono text-white/20">{durationHuman(incident.created, incident.updated)}</div>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {incident.affectedAssets.map((a) => (
          <span key={a} className="text-[9px] font-mono px-1.5 py-0.5 bg-white/5 border border-white/10 rounded text-white/45">
            {a}
          </span>
        ))}
      </div>
    </motion.button>
  )
}

function Timeline({ events }) {
  return (
    <div className="space-y-3">
      {events.map((e, i) => (
        <div key={i} className="flex gap-3">
          <div className="flex flex-col items-center gap-0">
            <span className="w-2 h-2 rounded-full bg-cyan-400/70 shrink-0 mt-0.5" />
            {i < events.length - 1 && <div className="w-px flex-1 bg-white/10 mt-1 min-h-[20px]" />}
          </div>
          <div className="pb-3 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <span className="text-[10px] font-mono text-cyan-400/70">{e.t}</span>
              <span className="text-[9px] font-mono bg-white/5 border border-white/10 px-1.5 py-0.5 rounded text-white/40">{e.actor}</span>
            </div>
            <p className="text-xs text-white/65 leading-relaxed">{e.msg}</p>
          </div>
        </div>
      ))}
    </div>
  )
}

function PlaybookSteps({ playbookId, onToggle, localSteps }) {
  const pb = PLAYBOOKS[playbookId]
  if (!pb) return null
  const steps = localSteps ?? pb.steps
  const done = steps.filter((s) => s.done).length
  const pct = Math.round((done / steps.length) * 100)
  const barColor = pct === 100 ? '#22d3ee' : pct > 60 ? '#22d3ee' : pct > 30 ? '#f59e0b' : '#ef4444'
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-mono uppercase tracking-widest text-white/40">{pb.label}</span>
        <span className="text-[10px] font-mono" style={{ color: barColor }}>{done}/{steps.length} ({pct}%)</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/5 mb-4 overflow-hidden">
        <motion.div
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.5 }}
          className="h-full rounded-full"
          style={{ background: barColor }}
        />
      </div>
      <div className="space-y-2">
        {steps.map((step) => {
          const phaseColor = PHASE_COLOR[step.phase] ?? '#6b7280'
          return (
            <motion.div
              key={step.id}
              layout
              className="flex items-start gap-3 rounded-lg p-2.5 border transition-all cursor-pointer hover:border-white/20"
              style={{
                borderColor: step.done ? 'rgba(34,211,238,0.2)' : 'rgba(255,255,255,0.07)',
                background: step.done ? 'rgba(34,211,238,0.04)' : 'rgba(0,0,0,0.2)',
              }}
              onClick={() => onToggle && onToggle(step.id)}
            >
              <div
                className="mt-0.5 w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-all"
                style={{
                  borderColor: step.done ? '#22d3ee' : 'rgba(255,255,255,0.2)',
                  background: step.done ? 'rgba(34,211,238,0.15)' : 'transparent',
                }}
              >
                {step.done && <span className="text-[10px] text-cyan-400">✓</span>}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className="text-[9px] font-mono px-1 py-0.5 rounded border uppercase tracking-wider"
                    style={{ color: phaseColor, borderColor: `${phaseColor}40`, background: `${phaseColor}10` }}
                  >
                    {step.phase}
                  </span>
                  {step.mitre && (
                    <span className="text-[9px] font-mono text-white/25 bg-white/5 border border-white/10 px-1.5 py-0.5 rounded">
                      {step.mitre}
                    </span>
                  )}
                </div>
                <p className="text-xs text-white/70 mt-0.5" style={{ textDecoration: step.done ? 'line-through' : 'none', opacity: step.done ? 0.4 : 0.85 }}>
                  {step.action}
                </p>
              </div>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function IncidentResponseCenter() {
  const [incidents] = useState(INITIAL_INCIDENTS)
  const [selectedId, setSelectedId] = useState(INITIAL_INCIDENTS[0].id)
  const [localSteps, setLocalSteps] = useState({})
  const [tab, setTab] = useState('timeline') // 'timeline' | 'playbook'

  const selected = useMemo(() => incidents.find((i) => i.id === selectedId), [incidents, selectedId])

  const handleToggleStep = useCallback((incidentId, stepId) => {
    setLocalSteps((prev) => {
      const pb = PLAYBOOKS[incidents.find((i) => i.id === incidentId)?.playbook]
      if (!pb) return prev
      const base = prev[incidentId] ?? pb.steps
      const next = base.map((s) => s.id === stepId ? { ...s, done: !s.done } : s)
      return { ...prev, [incidentId]: next }
    })
  }, [incidents])

  const metrics = useMemo(() => {
    const active = incidents.filter((i) => i.status === 'active').length
    const crit = incidents.filter((i) => i.severity === 'critical').length
    const resolved = incidents.filter((i) => i.status === 'resolved').length
    const totalMs = incidents.reduce((sum, i) => sum + (new Date(i.updated) - new Date(i.created)), 0)
    const avgH = (totalMs / incidents.length / 3_600_000).toFixed(1)
    return { active, crit, resolved, avgH }
  }, [incidents])

  return (
    <PageShell
      title="Incident Response Center"
      subtitle={`${incidents.length} incidents tracked`}
      badge="IR"
      badgeColor="#ef4444"
    >
      {/* ── Metrics ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        <MetricCard label="Active Incidents"  value={metrics.active}  sub="Requiring immediate action" color="#ef4444" icon="🔥" />
        <MetricCard label="Critical Severity" value={metrics.crit}    sub="P0 — C-suite notification"  color="#f97316" icon="⚠️" />
        <MetricCard label="Avg MTTR"          value={`${metrics.avgH}h`} sub="Mean time to resolve"   color="#22d3ee" icon="⏱️" />
        <MetricCard label="Resolved (7d)"     value={metrics.resolved} sub="Closed incidents"          color="#4ade80" icon="✅" />
      </div>

      <div className="grid lg:grid-cols-[360px_1fr] gap-6">
        {/* ── Left: Incident List ───────────────────────────────────────── */}
        <div className="space-y-2">
          <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">Incident Queue</h2>
          {incidents.map((inc) => (
            <IncidentRow
              key={inc.id}
              incident={inc}
              selected={selectedId === inc.id}
              onSelect={setSelectedId}
            />
          ))}
        </div>

        {/* ── Right: Incident Detail ────────────────────────────────────── */}
        <AnimatePresence mode="wait">
          {selected && (
            <motion.div
              key={selected.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="rounded-2xl bg-black/40 backdrop-blur border border-white/10 p-6 space-y-6"
            >
              {/* Header */}
              <div>
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="text-[10px] font-mono text-white/30">{selected.id}</span>
                  <span
                    className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
                    style={{
                      color: STATUS_META[selected.status]?.color ?? '#6b7280',
                      borderColor: `${STATUS_META[selected.status]?.color ?? '#6b7280'}40`,
                      background: `${STATUS_META[selected.status]?.color ?? '#6b7280'}10`,
                    }}
                  >
                    {STATUS_META[selected.status]?.label ?? selected.status}
                  </span>
                  <span
                    className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
                    style={{
                      color: SEVERITY_COLOR[selected.severity],
                      borderColor: `${SEVERITY_COLOR[selected.severity]}40`,
                      background: `${SEVERITY_COLOR[selected.severity]}10`,
                    }}
                  >
                    {selected.severity}
                  </span>
                  {selected.mitre && (
                    <span className="text-[9px] font-mono text-white/25 bg-white/5 border border-white/10 px-1.5 py-0.5 rounded">
                      {selected.mitre}
                    </span>
                  )}
                </div>
                <h2 className="text-sm font-bold text-white mb-2">{selected.title}</h2>
                <p className="text-xs text-white/50 leading-relaxed">{selected.description}</p>
              </div>

              {/* Meta row */}
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: 'Assignee', value: selected.assignee },
                  { label: 'Source',   value: selected.source },
                  { label: 'Duration', value: durationHuman(selected.created, selected.updated) },
                ].map(({ label, value }) => (
                  <div key={label} className="rounded-lg bg-black/30 border border-white/8 p-3">
                    <div className="text-[9px] font-mono uppercase tracking-widest text-white/25 mb-1">{label}</div>
                    <div className="text-xs font-semibold text-white/75">{value}</div>
                  </div>
                ))}
              </div>

              {/* Tabs */}
              <div className="flex gap-2 border-b border-white/10 pb-2">
                {['timeline', 'playbook'].map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setTab(t)}
                    className="text-[11px] font-mono uppercase tracking-widest px-3 py-1.5 rounded-lg transition-all"
                    style={{
                      color: tab === t ? '#22d3ee' : 'rgba(255,255,255,0.3)',
                      background: tab === t ? 'rgba(34,211,238,0.08)' : 'transparent',
                      border: tab === t ? '1px solid rgba(34,211,238,0.2)' : '1px solid transparent',
                    }}
                  >
                    {t === 'timeline' ? '📋 Timeline' : '📖 Playbook'}
                  </button>
                ))}
              </div>

              {tab === 'timeline' ? (
                <Timeline events={selected.timeline} />
              ) : (
                <PlaybookSteps
                  playbookId={selected.playbook}
                  localSteps={localSteps[selected.id]}
                  onToggle={(stepId) => handleToggleStep(selected.id, stepId)}
                />
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </PageShell>
  )
}
