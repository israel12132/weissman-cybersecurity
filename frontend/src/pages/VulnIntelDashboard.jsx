/**
 * CVE / Vulnerability Intelligence Dashboard
 *
 * World-class vulnerability management: CVSS prioritization, exploitability
 * scoring, patch status tracking, risk matrix, and CVE timeline.
 * Route: /vuln-intel
 */
import React, { useState, useMemo, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'

// ─── Data ─────────────────────────────────────────────────────────────────────

const CVSS_COLOR = (score) => {
  if (score >= 9.0) return '#ef4444'
  if (score >= 7.0) return '#f97316'
  if (score >= 4.0) return '#f59e0b'
  return '#22d3ee'
}

const VULN_DB = [
  {
    id: 'CVE-2024-3400',
    title: 'PAN-OS Command Injection (GlobalProtect)',
    cvss: 10.0,
    exploited: true,
    exploitMaturity: 'weaponized',
    vendor: 'Palo Alto Networks',
    product: 'PAN-OS / GlobalProtect',
    patchStatus: 'available',
    affectedVersions: '< 10.2.9-h1, < 11.0.4-h1, < 11.1.2-h3',
    mitre: 'T1190',
    cwe: 'CWE-78',
    published: '2024-04-12',
    description: 'OS command injection in GlobalProtect allows unauthenticated RCE. Actively exploited by UTA0218 (suspected state nexus).',
    references: ['https://security.paloaltonetworks.com/CVE-2024-3400'],
    epss: 0.975,
    kev: true,
  },
  {
    id: 'CVE-2024-1709',
    title: 'ConnectWise ScreenConnect Auth Bypass',
    cvss: 10.0,
    exploited: true,
    exploitMaturity: 'weaponized',
    vendor: 'ConnectWise',
    product: 'ScreenConnect',
    patchStatus: 'available',
    affectedVersions: '< 23.9.8',
    mitre: 'T1190',
    cwe: 'CWE-288',
    published: '2024-02-19',
    description: 'Authentication bypass using an alternate path allows full admin takeover. Mass exploitation observed within 48 h of disclosure.',
    references: [],
    epss: 0.971,
    kev: true,
  },
  {
    id: 'CVE-2024-6387',
    title: 'OpenSSH Race Condition RCE (regreSSHion)',
    cvss: 8.1,
    exploited: false,
    exploitMaturity: 'poc',
    vendor: 'OpenSSH',
    product: 'OpenSSH',
    patchStatus: 'available',
    affectedVersions: '8.5p1 – 9.7p1 (Linux glibc)',
    mitre: 'T1210',
    cwe: 'CWE-364',
    published: '2024-07-01',
    description: 'Signal handler race condition in sshd may allow unauthenticated RCE as root. Exploitation requires millions of attempts; PoC published.',
    references: [],
    epss: 0.21,
    kev: false,
  },
  {
    id: 'CVE-2024-21762',
    title: 'FortiOS Out-of-Bound Write (SSL-VPN)',
    cvss: 9.6,
    exploited: true,
    exploitMaturity: 'weaponized',
    vendor: 'Fortinet',
    product: 'FortiOS SSL-VPN',
    patchStatus: 'available',
    affectedVersions: '6.0–7.4 (see advisory)',
    mitre: 'T1190',
    cwe: 'CWE-787',
    published: '2024-02-08',
    description: 'Out-of-bounds write in FortiOS SSL-VPN enables unauthenticated RCE. Threat actors exploited it before the patch window.',
    references: [],
    epss: 0.943,
    kev: true,
  },
  {
    id: 'CVE-2024-27198',
    title: 'TeamCity Authentication Bypass',
    cvss: 9.8,
    exploited: true,
    exploitMaturity: 'weaponized',
    vendor: 'JetBrains',
    product: 'TeamCity',
    patchStatus: 'available',
    affectedVersions: '< 2023.11.4',
    mitre: 'T1190',
    cwe: 'CWE-288',
    published: '2024-03-04',
    description: 'Unauthenticated admin account creation on TeamCity instances. Used by multiple threat actors including BianLian ransomware.',
    references: [],
    epss: 0.965,
    kev: true,
  },
  {
    id: 'CVE-2023-46604',
    title: 'Apache ActiveMQ ClassPathXmlApplicationContext RCE',
    cvss: 9.8,
    exploited: true,
    exploitMaturity: 'weaponized',
    vendor: 'Apache',
    product: 'ActiveMQ',
    patchStatus: 'available',
    affectedVersions: '< 5.15.16, < 5.16.7, < 5.17.6, < 5.18.3',
    mitre: 'T1190',
    cwe: 'CWE-502',
    published: '2023-10-25',
    description: 'Deserialization RCE via OpenWire protocol. Used to deploy HelloKitty and TellYouThePass ransomware.',
    references: [],
    epss: 0.984,
    kev: true,
  },
  {
    id: 'CVE-2024-49113',
    title: 'Windows LDAP RCE (DoS/RCE)',
    cvss: 7.5,
    exploited: false,
    exploitMaturity: 'poc',
    vendor: 'Microsoft',
    product: 'Windows LDAP',
    patchStatus: 'available',
    affectedVersions: 'Windows Server 2008–2025',
    mitre: 'T1210',
    cwe: 'CWE-122',
    published: '2024-12-10',
    description: 'LDAPNightmare heap overflow in Windows LDAP service. PoC causes LSASS crash; RCE research ongoing.',
    references: [],
    epss: 0.18,
    kev: false,
  },
  {
    id: 'CVE-2024-38063',
    title: 'Windows TCP/IP IPv6 Remote Code Execution',
    cvss: 9.8,
    exploited: false,
    exploitMaturity: 'poc',
    vendor: 'Microsoft',
    product: 'Windows TCP/IP',
    patchStatus: 'available',
    affectedVersions: 'Windows 10/11 + Server 2008–2022',
    mitre: 'T1210',
    cwe: 'CWE-191',
    published: '2024-08-13',
    description: 'Integer underflow in IPv6 packet processing allows pre-auth RCE by sending crafted IPv6 packets. Disable IPv6 as immediate mitigation.',
    references: [],
    epss: 0.32,
    kev: false,
  },
]

const PATCH_STATUS_META = {
  available:   { label: 'PATCH AVAILABLE',  color: '#4ade80' },
  in_progress: { label: 'PATCHING',         color: '#f59e0b' },
  not_started: { label: 'UNPATCHED',        color: '#ef4444' },
  mitigated:   { label: 'MITIGATED',        color: '#22d3ee' },
}

const EXPLOIT_META = {
  weaponized: { label: 'WEAPONIZED', color: '#ef4444' },
  poc:        { label: 'PoC',        color: '#f59e0b' },
  theoretical:{ label: 'THEORETICAL',color: '#6b7280' },
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function CvssGauge({ score }) {
  const color = CVSS_COLOR(score)
  const pct = (score / 10) * 100
  return (
    <div className="flex items-center gap-3">
      <div className="relative w-12 h-12">
        <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
          <circle cx="18" cy="18" r="15.9155" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="3" />
          <circle
            cx="18" cy="18" r="15.9155" fill="none"
            stroke={color} strokeWidth="3"
            strokeDasharray={`${pct} ${100 - pct}`}
            strokeLinecap="round"
          />
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-[11px] font-bold font-mono" style={{ color }}>
          {score.toFixed(1)}
        </span>
      </div>
    </div>
  )
}

function EpssBar({ epss }) {
  const pct = epss * 100
  const color = epss > 0.8 ? '#ef4444' : epss > 0.5 ? '#f97316' : epss > 0.2 ? '#f59e0b' : '#22d3ee'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-white/5 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6 }}
          className="h-full rounded-full"
          style={{ background: color }}
        />
      </div>
      <span className="text-[10px] font-mono shrink-0" style={{ color }}>{pct.toFixed(1)}%</span>
    </div>
  )
}

function VulnCard({ vuln, selected, onSelect }) {
  const sc = CVSS_COLOR(vuln.cvss)
  const em = EXPLOIT_META[vuln.exploitMaturity] ?? EXPLOIT_META.theoretical
  return (
    <motion.button
      type="button"
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      onClick={() => onSelect(vuln.id)}
      className="w-full text-left rounded-xl border p-4 transition-all hover:scale-[1.003]"
      style={{
        borderColor: selected ? `${sc}50` : 'rgba(255,255,255,0.07)',
        background: selected ? `${sc}08` : 'rgba(0,0,0,0.3)',
      }}
    >
      <div className="flex items-start gap-3">
        <CvssGauge score={vuln.cvss} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-0.5">
            <span className="text-[10px] font-mono text-white/35">{vuln.id}</span>
            {vuln.kev && (
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest text-red-400 border-red-500/30 bg-red-950/30">
                CISA KEV
              </span>
            )}
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: em.color, borderColor: `${em.color}40`, background: `${em.color}10` }}
            >
              {em.label}
            </span>
          </div>
          <p className="text-xs font-semibold text-white/85 leading-snug mb-1">{vuln.title}</p>
          <div className="flex items-center gap-2 text-[10px] font-mono text-white/30">
            <span>{vuln.vendor}</span>
            <span>·</span>
            <span>{vuln.product}</span>
            <span>·</span>
            <span>{vuln.published}</span>
          </div>
        </div>
      </div>
    </motion.button>
  )
}

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

// ─── Main Component ───────────────────────────────────────────────────────────

export default function VulnIntelDashboard() {
  const [selectedId, setSelectedId] = useState(VULN_DB[0].id)
  const [search, setSearch] = useState('')
  const [filterExploited, setFilterExploited] = useState(false)
  const [filterKev, setFilterKev] = useState(false)

  const filtered = useMemo(() => {
    let list = [...VULN_DB].sort((a, b) => b.cvss - a.cvss)
    if (filterExploited) list = list.filter((v) => v.exploited)
    if (filterKev) list = list.filter((v) => v.kev)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(
        (v) =>
          v.id.toLowerCase().includes(q) ||
          v.title.toLowerCase().includes(q) ||
          v.vendor.toLowerCase().includes(q) ||
          v.product.toLowerCase().includes(q),
      )
    }
    return list
  }, [search, filterExploited, filterKev])

  const selected = useMemo(() => VULN_DB.find((v) => v.id === selectedId), [selectedId])

  const metrics = useMemo(() => {
    const critical = VULN_DB.filter((v) => v.cvss >= 9.0).length
    const exploited = VULN_DB.filter((v) => v.exploited).length
    const kev = VULN_DB.filter((v) => v.kev).length
    const avgCvss = (VULN_DB.reduce((s, v) => s + v.cvss, 0) / VULN_DB.length).toFixed(1)
    return { critical, exploited, kev, avgCvss }
  }, [])

  const pm = selected ? (PATCH_STATUS_META[selected.patchStatus] ?? { label: selected.patchStatus.toUpperCase(), color: '#6b7280' }) : null
  const em = selected ? (EXPLOIT_META[selected.exploitMaturity] ?? EXPLOIT_META.theoretical) : null

  return (
    <PageShell
      title="Vulnerability Intelligence"
      subtitle={`${VULN_DB.length} CVEs tracked · CVSS prioritized`}
      badge="CVE"
      badgeColor="#f97316"
    >
      {/* ── Metrics ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        <MetricCard label="Critical CVEs"     value={metrics.critical}  sub="CVSS ≥ 9.0"           color="#ef4444" icon="🔴" />
        <MetricCard label="Actively Exploited" value={metrics.exploited} sub="In-the-wild attacks"  color="#f97316" icon="⚡" />
        <MetricCard label="CISA KEV"           value={metrics.kev}      sub="Known exploited vulns" color="#f59e0b" icon="🏛️" />
        <MetricCard label="Avg CVSS"           value={metrics.avgCvss}  sub="Portfolio risk score"  color="#8b5cf6" icon="📊" />
      </div>

      {/* ── Filters ──────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="flex-1 relative min-w-[200px]">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search CVE ID, product, vendor…"
            className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 placeholder-white/20 font-mono focus:outline-none focus:border-orange-500/40"
          />
          {search && (
            <button type="button" onClick={() => setSearch('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60 text-xs"
            >✕</button>
          )}
        </div>
        {[
          { label: 'Exploited only', active: filterExploited, toggle: () => setFilterExploited((p) => !p), color: '#ef4444' },
          { label: 'CISA KEV only',  active: filterKev,       toggle: () => setFilterKev((p) => !p),       color: '#f59e0b' },
        ].map(({ label, active, toggle, color }) => (
          <button
            key={label} type="button" onClick={toggle}
            className="px-3 py-1.5 rounded-lg text-[11px] font-mono border transition-all"
            style={{
              color: active ? color : 'rgba(255,255,255,0.35)',
              borderColor: active ? `${color}40` : 'rgba(255,255,255,0.1)',
              background: active ? `${color}10` : 'transparent',
            }}
          >
            {label}
          </button>
        ))}
        <span className="text-[10px] font-mono text-white/25">{filtered.length} CVEs</span>
      </div>

      <div className="grid lg:grid-cols-[380px_1fr] gap-6">
        {/* ── Left: CVE list ───────────────────────────────────────────── */}
        <div className="space-y-2 max-h-[78vh] overflow-y-auto pr-1">
          {filtered.map((vuln) => (
            <VulnCard key={vuln.id} vuln={vuln} selected={selectedId === vuln.id} onSelect={setSelectedId} />
          ))}
          {filtered.length === 0 && (
            <div className="py-12 text-center text-white/25 text-xs font-mono">No CVEs match your filter.</div>
          )}
        </div>

        {/* ── Right: CVE Detail ────────────────────────────────────────── */}
        <AnimatePresence mode="wait">
          {selected && (
            <motion.div
              key={selected.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="rounded-2xl bg-black/40 backdrop-blur border border-white/10 p-6 space-y-6 self-start"
            >
              {/* Header */}
              <div>
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="text-[10px] font-mono text-white/35">{selected.id}</span>
                  {selected.kev && (
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border text-red-400 border-red-500/30 bg-red-950/30 uppercase tracking-widest">
                      CISA KEV
                    </span>
                  )}
                  <span
                    className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
                    style={{ color: em?.color, borderColor: `${em?.color}40`, background: `${em?.color}10` }}
                  >
                    {em?.label}
                  </span>
                  <span
                    className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
                    style={{ color: pm?.color, borderColor: `${pm?.color}40`, background: `${pm?.color}10` }}
                  >
                    {pm?.label}
                  </span>
                </div>
                <h2 className="text-sm font-bold text-white mb-2">{selected.title}</h2>
                <p className="text-xs text-white/50 leading-relaxed">{selected.description}</p>
              </div>

              {/* Scores */}
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-xl bg-black/30 border border-white/8 p-4">
                  <div className="text-[9px] font-mono uppercase tracking-widest text-white/25 mb-2">CVSS v3.1 Base Score</div>
                  <div className="flex items-center gap-3">
                    <CvssGauge score={selected.cvss} />
                    <div>
                      <div className="text-xl font-bold font-mono" style={{ color: CVSS_COLOR(selected.cvss) }}>
                        {selected.cvss.toFixed(1)}
                      </div>
                      <div className="text-[10px] font-mono text-white/30">
                        {selected.cvss >= 9 ? 'Critical' : selected.cvss >= 7 ? 'High' : selected.cvss >= 4 ? 'Medium' : 'Low'}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="rounded-xl bg-black/30 border border-white/8 p-4">
                  <div className="text-[9px] font-mono uppercase tracking-widest text-white/25 mb-2">EPSS Score (exploitation probability)</div>
                  <EpssBar epss={selected.epss} />
                  <div className="text-[10px] font-mono text-white/25 mt-2">
                    {(selected.epss * 100).toFixed(1)}% chance of exploitation in 30 days
                  </div>
                </div>
              </div>

              {/* Meta grid */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Vendor',          value: selected.vendor },
                  { label: 'Product',         value: selected.product },
                  { label: 'Published',       value: selected.published },
                  { label: 'CWE',             value: selected.cwe },
                  { label: 'MITRE ATT&CK',    value: selected.mitre },
                  { label: 'Patch Status',    value: pm?.label ?? selected.patchStatus },
                ].map(({ label, value }) => (
                  <div key={label} className="rounded-lg bg-black/30 border border-white/8 p-3">
                    <div className="text-[9px] font-mono uppercase tracking-widest text-white/25 mb-0.5">{label}</div>
                    <div className="text-xs font-semibold text-white/70">{value}</div>
                  </div>
                ))}
              </div>

              {/* Affected versions */}
              <div className="rounded-xl bg-black/30 border border-white/8 p-4">
                <div className="text-[9px] font-mono uppercase tracking-widest text-white/25 mb-2">Affected Versions</div>
                <p className="text-xs font-mono text-amber-400/80">{selected.affectedVersions}</p>
              </div>

              {/* Risk priority indicator */}
              <div className="rounded-xl bg-black/30 border border-white/8 p-4">
                <div className="text-[9px] font-mono uppercase tracking-widest text-white/25 mb-2">Risk Priority Score</div>
                <div className="h-2 rounded-full bg-white/5 overflow-hidden">
                  <motion.div
                    animate={{ width: `${Math.min(100, (selected.cvss / 10) * 70 + selected.epss * 30)}%` }}
                    transition={{ duration: 0.7 }}
                    className="h-full rounded-full"
                    style={{ background: CVSS_COLOR(selected.cvss) }}
                  />
                </div>
                <div className="flex justify-between mt-1">
                  <span className="text-[9px] font-mono text-white/25">Low</span>
                  <span className="text-[9px] font-mono" style={{ color: CVSS_COLOR(selected.cvss) }}>
                    {((selected.cvss / 10) * 70 + selected.epss * 30).toFixed(0)} / 100
                  </span>
                  <span className="text-[9px] font-mono text-white/25">Critical</span>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </PageShell>
  )
}
