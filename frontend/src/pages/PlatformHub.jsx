/**
 * Platform Hub — World-class command portal.
 *
 * The unified entry point to all Weissman Cybersecurity modules.
 * - Live KPI stats from real APIs (findings, scan status, health, config)
 * - All 20+ module cards organised by category with real-time indicators
 * - Domain configuration quick-check
 * - Global threat ticker
 *
 * Route: /platform-hub
 */
import React, { useState, useEffect, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { apiFetch } from '../lib/apiBase'
import { ENGINES_REGISTRY, ENGINE_GROUP_DEFS } from '../lib/enginesRegistry'
import { useAuth } from '../context/AuthContext'
import PageShell from './PageShell'

// ─── Constants ───────────────────────────────────────────────────────────────

const MODULE_CATEGORIES = [
  {
    id: 'operations',
    label: 'Threat Operations',
    icon: '🎯',
    color: '#ef4444',
    gradient: 'from-red-950/40 to-transparent',
    modules: [
      { id: 'hub-mod-findings',   to: '/findings',         label: 'Findings C2',        icon: '◉', desc: 'All vulnerability findings with workflow management', color: '#ef4444', api: '/api/findings?limit=1' },
      { id: 'hub-mod-ir',         to: '/incident-response',label: 'IR Center',           icon: '🚨', desc: 'Active incidents, playbooks & MTTR tracking', color: '#f87171' },
      { id: 'hub-mod-hunting',    to: '/threat-hunting',   label: 'Threat Hunting',      icon: '🔎', desc: 'Proactive hunt workbench & hypothesis tracking', color: '#f97316' },
      { id: 'hub-mod-vuln',       to: '/vuln-intel',       label: 'Vuln Intelligence',   icon: '⚡', desc: 'CVE tracking, EPSS scores & exploit maturity', color: '#fb923c' },
    ],
  },
  {
    id: 'intelligence',
    label: 'Intelligence & Analytics',
    icon: '🧠',
    color: '#8b5cf6',
    gradient: 'from-violet-950/40 to-transparent',
    modules: [
      { id: 'hub-mod-threat-intel',to: '/threat-intel',    label: 'Threat Intel Hub',    icon: '🎯', desc: `${ENGINES_REGISTRY.length} engines · MITRE ATT&CK coverage heatmap`, color: '#8b5cf6' },
      { id: 'hub-mod-engines',    to: '/engines',          label: 'Engine Matrix',        icon: '⬡', desc: 'Configure, run & monitor all attack engines', color: '#a78bfa' },
      { id: 'hub-mod-dark-web',   to: '/dark-web',         label: 'Dark Web Monitor',     icon: '🕵', desc: 'Credential leaks, paste sites & marketplace alerts', color: '#7c3aed' },
      { id: 'hub-mod-emulation',  to: '/threat-emulation', label: 'APT Emulation',        icon: '◈', desc: 'Real APT TTP simulation with MITRE mapping', color: '#6d28d9' },
    ],
  },
  {
    id: 'discovery',
    label: 'Attack Surface Discovery',
    icon: '🌐',
    color: '#06b6d4',
    gradient: 'from-cyan-950/40 to-transparent',
    modules: [
      { id: 'hub-mod-discovery',  to: '/domain-discovery', label: 'Domain Discovery',    icon: '🌐', desc: 'Asset enumeration · subdomain & certificate scans', color: '#22d3ee' },
      { id: 'hub-mod-network',    to: '/network',          label: 'Network Intelligence', icon: '📡', desc: 'Protocol analysis, port scanning & BGP intel', color: '#06b6d4' },
      { id: 'hub-mod-supply',     to: '/supply-chain',     label: 'Supply Chain Hub',     icon: '⛓', desc: 'Dependency auditing & third-party risk scoring', color: '#0891b2' },
      { id: 'hub-mod-cloud',      to: '/cloud',            label: 'Cloud Control Tower',  icon: '☁', desc: 'AWS/GCP/Azure misconfiguration & IAM analysis', color: '#0ea5e9' },
    ],
  },
  {
    id: 'platform',
    label: 'Platform & Security Engineering',
    icon: '⚙️',
    color: '#10b981',
    gradient: 'from-emerald-950/40 to-transparent',
    modules: [
      { id: 'hub-mod-oast',       to: '/oast',             label: 'OAST / OOB Probes',   icon: '⊂', desc: 'Out-of-band callback detection & DNS verification', color: '#10b981' },
      { id: 'hub-mod-pqc',        to: '/pqc-radar',        label: 'PQC Radar',            icon: '🔐', desc: 'Post-quantum cryptography readiness assessment', color: '#059669' },
      { id: 'hub-mod-twin',       to: '/digital-twin',     label: 'Digital Twin',         icon: '⟐', desc: 'Full-stack environment mirroring & replay attacks', color: '#047857' },
      { id: 'hub-mod-council',    to: '/council-queue',    label: 'Council HITL Queue',   icon: '⚖', desc: 'Human-in-the-loop exploit approval workflow', color: '#065f46' },
    ],
  },
  {
    id: 'admin',
    label: 'Administration',
    icon: '🔑',
    color: '#f59e0b',
    gradient: 'from-amber-950/40 to-transparent',
    modules: [
      { id: 'hub-mod-admin',      to: '/admin',            label: 'User Management',     icon: '👤', desc: 'Users, roles, permissions & audit logs', color: '#f59e0b' },
      { id: 'hub-mod-sso',        to: '/sso-config',       label: 'SSO / IdP Config',    icon: '🔑', desc: 'SAML, OIDC & MFA configuration', color: '#d97706' },
      { id: 'hub-mod-system-status', to: '/system-status', label: 'System Status',       icon: '✓', desc: 'Domain config check, API health & engine status', color: '#b45309' },
    ],
  },
]

// ─── KPI data ─────────────────────────────────────────────────────────────────

function useKPIs() {
  const [kpis, setKpis] = useState({
    totalFindings: null,
    criticalCount: null,
    securityScore: null,
    activeScans: null,
    engineCount: ENGINES_REGISTRY.length,
    groupCount: ENGINE_GROUP_DEFS.length,
    apiOnline: null,
    region: null,
    version: null,
  })

  const refresh = useCallback(async () => {
    try {
      const [statsR, configR, healthR] = await Promise.allSettled([
        apiFetch('/api/dashboard/stats'),
        apiFetch('/api/config/public'),
        fetch('/api/health'),
      ])
      const updates = {}

      if (statsR.status === 'fulfilled' && statsR.value.ok) {
        const d = await statsR.value.json().catch(() => ({}))
        updates.totalFindings = d.total_vulnerabilities ?? d.total_findings ?? null
        updates.securityScore = d.security_score ?? null
        updates.activeScans   = d.active_scans ? 1 : 0
      }
      if (configR.status === 'fulfilled' && configR.value.ok) {
        const d = await configR.value.json().catch(() => ({}))
        updates.region  = d.region || d.WEISSMAN_REGION || null
        updates.version = d.version || null
      }
      if (healthR.status === 'fulfilled') {
        updates.apiOnline = healthR.value.ok
      } else {
        updates.apiOnline = false
      }

      // Fetch findings to get critical count
      try {
        const fR = await apiFetch('/api/findings?limit=500')
        if (fR.ok) {
          const fd = await fR.json().catch(() => [])
          const arr = Array.isArray(fd) ? fd : fd.findings || fd.data || []
          updates.totalFindings = updates.totalFindings ?? arr.length
          updates.criticalCount = arr.filter((f) => (f.severity || '').toLowerCase() === 'critical').length
        }
      } catch (_) {}

      setKpis((prev) => ({ ...prev, ...updates }))
    } catch (_) {}
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 20000)
    return () => clearInterval(t)
  }, [refresh])

  return kpis
}

// ─── KPI Card ─────────────────────────────────────────────────────────────────

function KpiCard({ label, value, sub, color, icon, pulse = false }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border border-white/8 p-5 flex flex-col gap-2 relative overflow-hidden"
      style={{ background: `linear-gradient(135deg, ${color}12 0%, rgba(0,0,0,0.4) 100%)`, borderColor: `${color}25` }}
    >
      <div
        className="absolute inset-0 pointer-events-none"
        style={{ background: `radial-gradient(ellipse 60% 40% at 10% 20%, ${color}08 0%, transparent 70%)` }}
      />
      <div className="flex items-center gap-2 relative">
        <span className="text-xl">{icon}</span>
        <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: `${color}99` }}>{label}</span>
        {pulse && value !== null && (
          <span className="ml-auto w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: color }} />
        )}
      </div>
      <div className="text-3xl font-black font-mono relative tabular-nums" style={{ color }}>
        {value === null ? <span className="text-white/20 text-lg">…</span> : value}
      </div>
      {sub && <div className="text-[10px] font-mono text-white/30 relative">{sub}</div>}
    </motion.div>
  )
}

// ─── Module Card ──────────────────────────────────────────────────────────────

function ModuleCard({ mod, index }) {
  const navigate = useNavigate()
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03 }}
      whileHover={{ y: -2, scale: 1.01 }}
      onClick={() => navigate(mod.to)}
      className="rounded-xl border border-white/8 p-4 cursor-pointer transition-all duration-200 hover:border-white/20 hover:shadow-[0_4px_24px_rgba(0,0,0,0.4)] group relative overflow-hidden"
      style={{ background: `linear-gradient(145deg, ${mod.color}10 0%, rgba(0,0,0,0.5) 100%)`, borderColor: `${mod.color}20` }}
    >
      <div
        className="absolute top-0 right-0 w-24 h-24 pointer-events-none opacity-30"
        style={{ background: `radial-gradient(circle at 80% 20%, ${mod.color}30 0%, transparent 70%)` }}
      />
      <div className="flex items-start justify-between gap-2 mb-2">
        <span className="text-2xl">{mod.icon}</span>
        <svg
          className="w-4 h-4 text-white/20 group-hover:text-white/50 transition-colors mt-0.5 shrink-0"
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
      </div>
      <div className="font-semibold text-sm text-white/90 mb-1">{mod.label}</div>
      <div className="text-[11px] text-white/40 font-mono leading-relaxed">{mod.desc}</div>
      <Link
        id={mod.id}
        to={mod.to}
        className="mt-3 inline-flex items-center gap-1 text-[11px] font-mono font-semibold transition-colors"
        style={{ color: mod.color }}
        onClick={(e) => e.stopPropagation()}
      >
        Open →
      </Link>
    </motion.div>
  )
}

// ─── Category section ─────────────────────────────────────────────────────────

function CategorySection({ cat, idx }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: idx * 0.08 }}
      className="mb-10"
    >
      <div className="flex items-center gap-3 mb-4">
        <span className="text-2xl">{cat.icon}</span>
        <h2 className="text-base font-bold text-white/90 tracking-wide">{cat.label}</h2>
        <div className="flex-1 h-px" style={{ background: `linear-gradient(90deg, ${cat.color}40 0%, transparent 100%)` }} />
        <span className="text-[10px] font-mono text-white/20">{cat.modules.length} modules</span>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {cat.modules.map((mod, i) => (
          <ModuleCard key={mod.id} mod={mod} index={i} />
        ))}
      </div>
    </motion.div>
  )
}

// ─── Live scan ticker ─────────────────────────────────────────────────────────

function ScanStatusBanner({ activeScans }) {
  if (!activeScans) return null
  return (
    <div
      className="flex items-center gap-3 px-4 py-2.5 rounded-xl border mb-6"
      style={{ borderColor: '#22d3ee40', background: '#22d3ee08' }}
    >
      <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
      <span className="text-xs font-mono text-cyan-300">Active scan in progress — real-time findings updating</span>
      <Link to="/findings" className="ml-auto text-[11px] font-mono text-cyan-400 hover:text-cyan-300 transition-colors">
        View findings →
      </Link>
    </div>
  )
}

// ─── Domain status banner ──────────────────────────────────────────────────────

function DomainBanner({ region }) {
  if (!region) return null
  return (
    <div
      className="flex items-center gap-3 px-4 py-2.5 rounded-xl border mb-6"
      style={{ borderColor: '#10b98140', background: '#10b98108' }}
    >
      <span className="text-emerald-400 text-sm">✓</span>
      <span className="text-xs font-mono text-emerald-300/80">
        Platform configured · Region: <strong className="text-emerald-200">{region}</strong>
      </span>
      <Link to="/system-status" className="ml-auto text-[11px] font-mono text-emerald-400 hover:text-emerald-300 transition-colors">
        Full status →
      </Link>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function PlatformHub() {
  const kpis = useKPIs()
  const { session } = useAuth()

  const scoreColor = kpis.securityScore === null ? '#6b7280'
    : kpis.securityScore >= 70 ? '#4ade80'
    : kpis.securityScore >= 40 ? '#f59e0b'
    : '#ef4444'

  return (
    <PageShell
      title="Platform Hub"
      subtitle="Unified cybersecurity command portal"
      badge="LIVE"
      badgeColor="#22d3ee"
    >
      {/* ── Welcome header ─────────────────────────────────────────────────── */}
      <div className="mb-8">
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 mb-6"
        >
          <div>
            <h1 className="text-3xl font-black text-white mb-1 tracking-tight">
              Weissman{' '}
              <span
                className="bg-clip-text text-transparent"
                style={{ backgroundImage: 'linear-gradient(90deg, #22d3ee 0%, #8b5cf6 50%, #ec4899 100%)' }}
              >
                Command Center
              </span>
            </h1>
            <p className="text-sm text-white/40 font-mono">
              {session?.email ? `Logged in as ${session.email}` : 'Cyber Intelligence Platform'} ·{' '}
              {kpis.engineCount} engines · {kpis.groupCount} engine groups
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Link
              to="/system-status"
              id="hub-btn-status"
              className="flex items-center gap-2 px-4 py-2 rounded-lg border text-xs font-mono font-semibold transition-all hover:scale-105"
              style={{ borderColor: '#22d3ee30', color: '#22d3ee', background: '#22d3ee10' }}
            >
              ✓ System Status
            </Link>
            <Link
              to="/engines"
              id="hub-btn-engines"
              className="flex items-center gap-2 px-4 py-2 rounded-lg border text-xs font-mono font-semibold transition-all hover:scale-105"
              style={{ borderColor: '#8b5cf630', color: '#a78bfa', background: '#8b5cf610' }}
            >
              ⬡ All Engines
            </Link>
          </div>
        </motion.div>

        {/* Banners */}
        <ScanStatusBanner activeScans={kpis.activeScans} />
        <DomainBanner region={kpis.region} />

        {/* KPI cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-2">
          <KpiCard
            label="Total Findings"
            value={kpis.totalFindings}
            icon="◉"
            color="#f97316"
            sub="All severities"
            pulse
          />
          <KpiCard
            label="Critical"
            value={kpis.criticalCount}
            icon="🔴"
            color="#ef4444"
            sub="Needs immediate action"
            pulse
          />
          <KpiCard
            label="Security Score"
            value={kpis.securityScore !== null ? `${kpis.securityScore}%` : null}
            icon="🛡"
            color={scoreColor}
            sub="Overall posture"
          />
          <KpiCard
            label="Scan Status"
            value={kpis.activeScans === null ? null : kpis.activeScans > 0 ? 'Active' : 'Idle'}
            icon="⟳"
            color={kpis.activeScans ? '#22d3ee' : '#6b7280'}
            sub="Engine orchestration"
            pulse={!!kpis.activeScans}
          />
          <KpiCard
            label="Attack Engines"
            value={kpis.engineCount}
            icon="⬡"
            color="#8b5cf6"
            sub={`${kpis.groupCount} groups`}
          />
          <KpiCard
            label="API Status"
            value={kpis.apiOnline === null ? null : kpis.apiOnline ? 'Online' : 'Offline'}
            icon="📡"
            color={kpis.apiOnline ? '#4ade80' : kpis.apiOnline === false ? '#ef4444' : '#6b7280'}
            sub="Backend connectivity"
            pulse={kpis.apiOnline === true}
          />
        </div>
      </div>

      {/* Divider */}
      <div className="h-px bg-white/5 mb-8" />

      {/* ── Module categories ──────────────────────────────────────────────── */}
      {MODULE_CATEGORIES.map((cat, idx) => (
        <CategorySection key={cat.id} cat={cat} idx={idx} />
      ))}

      {/* ── Quick actions footer ───────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
        className="mt-6 rounded-2xl border border-white/8 p-6"
        style={{ background: 'linear-gradient(135deg, rgba(34,211,238,0.05) 0%, rgba(0,0,0,0.4) 100%)' }}
      >
        <div className="flex items-center gap-3 mb-4">
          <span className="text-lg">⚡</span>
          <h3 className="text-sm font-bold text-white/80">Quick Actions</h3>
        </div>
        <div className="flex flex-wrap gap-2">
          {[
            { id: 'hub-qa-run-all',     to: '/',               label: '▶ Run All Scans',       color: '#22d3ee' },
            { id: 'hub-qa-new-client',  to: '/',               label: '＋ Add Client',           color: '#4ade80' },
            { id: 'hub-qa-export',      to: '/findings',       label: '⬇ Export Findings CSV',  color: '#f59e0b' },
            { id: 'hub-qa-audit',       to: '/admin',          label: '📋 Audit Logs',           color: '#a78bfa' },
            { id: 'hub-qa-sso',         to: '/sso-config',     label: '🔑 Configure SSO',        color: '#34d399' },
            { id: 'hub-qa-openapi',     to: '/api/openapi.json', label: '📄 OpenAPI Spec',       color: '#60a5fa', external: true },
          ].map((a) =>
            a.external ? (
              <a
                key={a.id}
                id={a.id}
                href={a.to}
                target="_blank"
                rel="noopener noreferrer"
                className="px-4 py-2 rounded-lg border text-xs font-mono font-medium transition-all hover:scale-105"
                style={{ borderColor: `${a.color}30`, color: a.color, background: `${a.color}10` }}
              >
                {a.label}
              </a>
            ) : (
              <Link
                key={a.id}
                id={a.id}
                to={a.to}
                className="px-4 py-2 rounded-lg border text-xs font-mono font-medium transition-all hover:scale-105"
                style={{ borderColor: `${a.color}30`, color: a.color, background: `${a.color}10` }}
              >
                {a.label}
              </Link>
            )
          )}
        </div>
      </motion.div>
    </PageShell>
  )
}
