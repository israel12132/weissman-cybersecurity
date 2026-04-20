/**
 * Dark Web Monitor
 *
 * World-class dark web threat intelligence: credential exposure alerts,
 * ransomware group intelligence, breach feed, dark web forum mentions.
 * Route: /dark-web
 */
import React, { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'

// ─── Data ─────────────────────────────────────────────────────────────────────

const CREDENTIAL_LEAKS = [
  {
    id: 'leak-001',
    source: 'BreachForums',
    date: '2026-04-18',
    severity: 'critical',
    recordCount: 240_000,
    dataTypes: ['email', 'bcrypt_hash', 'plaintext_password', 'phone'],
    domain: 'acmecorp.com',
    verified: true,
    actor: 'ShinyHunters',
    description: '240k employee and customer credentials from ACME Corp CRM database. 18% already cracked via rainbow tables.',
  },
  {
    id: 'leak-002',
    source: 'RaidForums Mirror',
    date: '2026-04-15',
    severity: 'high',
    recordCount: 14_200,
    dataTypes: ['email', 'md5_hash', 'username', 'api_key'],
    domain: 'dev.acmecorp.com',
    verified: true,
    actor: 'Unknown',
    description: '14k developer portal credentials including 38 API keys still valid at time of discovery.',
  },
  {
    id: 'leak-003',
    source: 'Telegram Channel',
    date: '2026-04-10',
    severity: 'medium',
    recordCount: 3_100,
    dataTypes: ['email', 'name', 'ip_address'],
    domain: 'marketing.acmecorp.com',
    verified: false,
    actor: 'Unverified',
    description: 'Unverified dump of marketing team data. Low-severity PII exposure; no passwords included.',
  },
]

const RANSOMWARE_GROUPS = [
  {
    id: 'lockbit',
    name: 'LockBit 3.0',
    status: 'active',
    nation: 'Russia (suspected)',
    recentVictims: 47,
    sectors: ['Healthcare', 'Finance', 'Manufacturing'],
    color: '#ef4444',
    ttps: ['T1486', 'T1021.002', 'T1055', 'T1078'],
    lastActivity: '2026-04-19',
    description: 'Most prolific ransomware-as-a-service group. Uses triple extortion: encryption, data leak, DDoS.',
    leakSiteActive: true,
  },
  {
    id: 'clop',
    name: 'Cl0p',
    status: 'active',
    nation: 'Russia (TA505)',
    recentVictims: 31,
    sectors: ['Legal', 'Education', 'Tech'],
    color: '#f97316',
    ttps: ['T1190', 'T1560', 'T1537'],
    lastActivity: '2026-04-17',
    description: 'Known for mass-exploitation of MOVEit, GoAnywhere, Accellion — zero-day supply chain attacks targeting file transfer appliances.',
    leakSiteActive: true,
  },
  {
    id: 'alphv',
    name: 'ALPHV / BlackCat',
    status: 'disrupted',
    nation: 'Russia (suspected)',
    recentVictims: 12,
    sectors: ['Healthcare', 'Energy'],
    color: '#f59e0b',
    ttps: ['T1486', 'T1562', 'T1078.004'],
    lastActivity: '2026-03-01',
    description: 'First Rust-based ransomware. FBI operation disrupted in Dec 2023; resurfaced with limited activity.',
    leakSiteActive: false,
  },
  {
    id: 'play',
    name: 'Play',
    status: 'active',
    nation: 'Unknown',
    recentVictims: 19,
    sectors: ['Government', 'Manufacturing'],
    color: '#8b5cf6',
    ttps: ['T1190', 'T1021.001', 'T1486'],
    lastActivity: '2026-04-18',
    description: 'Avoids ransom negotiation — deploys both encryption and data exfiltration simultaneously. No public decryptor.',
    leakSiteActive: true,
  },
]

const DARK_WEB_MENTIONS = [
  { id: 'm-1', ts: '2026-04-20 14:22', source: 'BreachForums',  severity: 'critical', text: '"acmecorp.com" admin panel credentials for sale — $500 BTC. Full DB access.', verified: true },
  { id: 'm-2', ts: '2026-04-20 09:15', source: 'Dread Forum',   severity: 'high',     text: 'Thread: "ACME Corp VPN bypass — works on GlobalProtect 5.2.x, no auth needed"', verified: true },
  { id: 'm-3', ts: '2026-04-19 22:44', source: 'Telegram',      severity: 'high',     text: 'New botnet targeting acmecorp[.]com DNS infra. 2.3k bots active.', verified: false },
  { id: 'm-4', ts: '2026-04-19 11:30', source: 'XSS.is',        severity: 'medium',   text: 'Source code dump: acmecorp internal billing service v2.4 (nodejs/postgres)', verified: false },
  { id: 'm-5', ts: '2026-04-18 08:00', source: 'Exploit.in',    severity: 'medium',   text: 'RDP credentials: acmecorp.com:3389 admin/welcome1 (batch of 14)', verified: true },
  { id: 'm-6', ts: '2026-04-17 17:05', source: 'LockBit Blog',  severity: 'critical', text: 'ACME CORPORATION added to LockBit leak site. 48h countdown to release.', verified: true },
]

const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22d3ee', info: '#6b7280' }

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

function CredentialLeakCard({ leak }) {
  const sc = SEV_COLOR[leak.severity] ?? '#6b7280'
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl bg-black/40 backdrop-blur border border-white/10 p-5 space-y-3"
      style={{ borderColor: `${sc}25` }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: sc, borderColor: `${sc}40`, background: `${sc}10` }}
            >
              {leak.severity}
            </span>
            {leak.verified && (
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border text-green-400 border-green-500/30 bg-green-950/20 uppercase tracking-widest">
                VERIFIED
              </span>
            )}
            <span className="text-[10px] font-mono text-white/30">{leak.source}</span>
            <span className="text-[10px] font-mono text-white/20">{leak.date}</span>
          </div>
          <p className="text-xs font-semibold text-white/80 font-mono">{leak.domain}</p>
          <p className="text-xs text-white/45 mt-1 leading-relaxed">{leak.description}</p>
        </div>
        <div className="text-right shrink-0">
          <div className="text-lg font-bold font-mono" style={{ color: sc }}>
            {leak.recordCount.toLocaleString()}
          </div>
          <div className="text-[9px] font-mono text-white/25">records</div>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {leak.dataTypes.map((dt) => (
          <span key={dt} className="text-[9px] font-mono px-1.5 py-0.5 bg-white/5 border border-white/10 rounded text-white/45 capitalize">
            {dt.replace(/_/g, ' ')}
          </span>
        ))}
      </div>
      {leak.actor !== 'Unknown' && leak.actor !== 'Unverified' && (
        <div className="text-[10px] font-mono text-white/30">
          Attributed to: <span className="text-red-400/70">{leak.actor}</span>
        </div>
      )}
    </motion.div>
  )
}

function RansomwareGroupCard({ group, selected, onSelect }) {
  const isActive = group.status === 'active'
  return (
    <motion.button
      type="button"
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      onClick={() => onSelect(group.id === selected ? null : group.id)}
      className="w-full text-left rounded-xl border p-4 transition-all hover:scale-[1.003]"
      style={{
        borderColor: selected === group.id ? `${group.color}50` : 'rgba(255,255,255,0.07)',
        background: selected === group.id ? `${group.color}08` : 'rgba(0,0,0,0.3)',
      }}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-sm font-bold" style={{ color: group.color }}>{group.name}</span>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{
                color: isActive ? '#ef4444' : '#22d3ee',
                borderColor: isActive ? 'rgba(239,68,68,0.3)' : 'rgba(34,211,238,0.3)',
                background: isActive ? 'rgba(239,68,68,0.08)' : 'rgba(34,211,238,0.08)',
              }}
            >
              {group.status}
            </span>
            {group.leakSiteActive && (
              <span className="text-[9px] font-mono text-red-400/60">● LEAK SITE LIVE</span>
            )}
          </div>
          <div className="text-[10px] font-mono text-white/30">{group.nation} · last seen {group.lastActivity}</div>
        </div>
        <div className="text-right">
          <div className="text-xl font-bold font-mono" style={{ color: group.color }}>{group.recentVictims}</div>
          <div className="text-[9px] font-mono text-white/25">victims (90d)</div>
        </div>
      </div>
      <p className="text-[11px] text-white/45 leading-relaxed mb-2">{group.description}</p>
      <div className="flex flex-wrap gap-1 mb-1">
        {group.sectors.map((s) => (
          <span key={s} className="text-[9px] font-mono px-1.5 py-0.5 bg-white/5 border border-white/10 rounded text-white/40">{s}</span>
        ))}
      </div>
      <div className="flex flex-wrap gap-1">
        {group.ttps.map((t) => (
          <span key={t} className="text-[9px] font-mono px-1 py-0.5 bg-white/5 border border-white/10 rounded text-white/25">{t}</span>
        ))}
      </div>
    </motion.button>
  )
}

function MentionRow({ mention, index }) {
  const sc = SEV_COLOR[mention.severity] ?? '#6b7280'
  return (
    <motion.div
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.04 }}
      className="flex items-start gap-3 py-3 border-b border-white/5"
    >
      <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: sc, boxShadow: `0 0 6px ${sc}80` }} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap mb-0.5">
          <span className="text-[9px] font-mono text-white/25">{mention.ts}</span>
          <span
            className="text-[9px] font-mono px-1 py-0.5 rounded border uppercase tracking-widest"
            style={{ color: sc, borderColor: `${sc}30`, background: `${sc}08` }}
          >
            {mention.severity}
          </span>
          <span className="text-[9px] font-mono text-white/30">{mention.source}</span>
          {mention.verified && (
            <span className="text-[9px] font-mono text-green-400/50">✓ verified</span>
          )}
        </div>
        <p className="text-xs text-white/60 leading-relaxed">{mention.text}</p>
      </div>
    </motion.div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function DarkWebMonitor() {
  const [activeSection, setActiveSection] = useState('leaks') // 'leaks' | 'ransomware' | 'mentions'
  const [selectedRg, setSelectedRg] = useState(null)

  const metrics = useMemo(() => {
    const totalRecords = CREDENTIAL_LEAKS.reduce((s, l) => s + l.recordCount, 0)
    const critLeaks = CREDENTIAL_LEAKS.filter((l) => l.severity === 'critical').length
    const activeRg = RANSOMWARE_GROUPS.filter((r) => r.status === 'active').length
    const critMentions = DARK_WEB_MENTIONS.filter((m) => m.severity === 'critical').length
    return { totalRecords, critLeaks, activeRg, critMentions }
  }, [])

  const sections = [
    { id: 'leaks',      label: '🔑 Credential Leaks',   count: CREDENTIAL_LEAKS.length,    color: '#ef4444' },
    { id: 'ransomware', label: '💀 Ransomware Groups',  count: RANSOMWARE_GROUPS.length,   color: '#f97316' },
    { id: 'mentions',   label: '🕵️ Dark Web Mentions', count: DARK_WEB_MENTIONS.length,   color: '#8b5cf6' },
  ]

  return (
    <PageShell
      title="Dark Web Monitor"
      subtitle="Credential leaks · Ransomware intel · Forum mentions"
      badge="LIVE"
      badgeColor="#ef4444"
    >
      {/* ── Metrics ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        <MetricCard label="Exposed Records"     value={metrics.totalRecords.toLocaleString()} sub="Across all monitored leaks"   color="#ef4444" icon="🔑" />
        <MetricCard label="Critical Leaks"      value={metrics.critLeaks}                     sub="Verified high-risk breaches"  color="#f97316" icon="💥" />
        <MetricCard label="Active Ransomware RG" value={metrics.activeRg}                     sub="Currently operating groups"  color="#f59e0b" icon="💀" />
        <MetricCard label="Critical Mentions"   value={metrics.critMentions}                  sub="High-priority dark web hits"  color="#8b5cf6" icon="🕵️" />
      </div>

      {/* ── Section Tabs ─────────────────────────────────────────────────── */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {sections.map((s) => (
          <button
            key={s.id} type="button" onClick={() => setActiveSection(s.id)}
            className="px-4 py-2 rounded-xl text-xs font-mono border transition-all"
            style={{
              color: activeSection === s.id ? s.color : 'rgba(255,255,255,0.35)',
              borderColor: activeSection === s.id ? `${s.color}40` : 'rgba(255,255,255,0.1)',
              background: activeSection === s.id ? `${s.color}10` : 'transparent',
            }}
          >
            {s.label}
            <span className="ml-2 text-[9px] font-mono opacity-60">({s.count})</span>
          </button>
        ))}
      </div>

      {/* ── Content ──────────────────────────────────────────────────────── */}
      <AnimatePresence mode="wait">
        {activeSection === 'leaks' && (
          <motion.div key="leaks" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
            {CREDENTIAL_LEAKS.map((leak) => (
              <CredentialLeakCard key={leak.id} leak={leak} />
            ))}
          </motion.div>
        )}

        {activeSection === 'ransomware' && (
          <motion.div key="ransomware" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-3">
            {RANSOMWARE_GROUPS.map((group) => (
              <RansomwareGroupCard key={group.id} group={group} selected={selectedRg} onSelect={setSelectedRg} />
            ))}
          </motion.div>
        )}

        {activeSection === 'mentions' && (
          <motion.div key="mentions" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <div className="rounded-2xl bg-black/40 backdrop-blur border border-white/10 px-5">
              {DARK_WEB_MENTIONS.map((m, i) => (
                <MentionRow key={m.id} mention={m} index={i} />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </PageShell>
  )
}
