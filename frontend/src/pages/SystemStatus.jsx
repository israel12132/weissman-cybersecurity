/**
 * System Status — Domain configuration & full platform health check.
 *
 * Checks every major API endpoint, shows domain config, engine count,
 * backend version, database connectivity status, and scan engine availability.
 *
 * Route: /system-status
 */
import React, { useState, useCallback, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { apiFetch } from '../lib/apiBase'
import { ENGINES_REGISTRY, ENGINE_GROUP_DEFS } from '../lib/enginesRegistry'
import PageShell from './PageShell'

// ─── Endpoint checks ──────────────────────────────────────────────────────────

const CHECKS = [
  {
    id: 'health',
    label: 'API Gateway',
    description: 'Core API server connectivity',
    endpoint: '/api/health',
    auth: false,
    category: 'core',
  },
  {
    id: 'auth_me',
    label: 'Auth Service',
    description: 'JWT session validation',
    endpoint: '/api/auth/me',
    auth: true,
    category: 'core',
  },
  {
    id: 'config_public',
    label: 'Platform Config',
    description: 'Domain, region & version metadata',
    endpoint: '/api/config/public',
    auth: true,
    category: 'core',
  },
  {
    id: 'dashboard_stats',
    label: 'Dashboard Stats',
    description: 'Findings count & security score',
    endpoint: '/api/dashboard/stats',
    auth: true,
    category: 'data',
  },
  {
    id: 'findings',
    label: 'Findings API',
    description: 'Vulnerability findings store',
    endpoint: '/api/findings?limit=1',
    auth: true,
    category: 'data',
  },
  {
    id: 'clients',
    label: 'Clients API',
    description: 'Client & tenant management',
    endpoint: '/api/clients',
    auth: true,
    category: 'data',
  },
  {
    id: 'scan_status',
    label: 'Scan Orchestrator',
    description: 'Engine scheduling & run status',
    endpoint: '/api/scan/status',
    auth: true,
    category: 'engines',
  },
  {
    id: 'audit_logs',
    label: 'Audit Logs',
    description: 'Immutable audit trail store',
    endpoint: '/api/audit-logs?limit=1',
    auth: true,
    category: 'platform',
  },
  {
    id: 'openapi',
    label: 'OpenAPI Spec',
    description: 'Machine-readable API documentation',
    endpoint: '/api/openapi.json',
    auth: false,
    category: 'platform',
  },
]

const CATEGORY_LABELS = {
  core: { label: 'Core Services', color: '#22d3ee', icon: '⚡' },
  data: { label: 'Data Layer',    color: '#8b5cf6', icon: '🗄' },
  engines: { label: 'Engine Orchestration', color: '#f97316', icon: '⬡' },
  platform: { label: 'Platform Services', color: '#10b981', icon: '⚙' },
}

// ─── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status, latencyMs }) {
  const cfg = {
    ok:       { color: '#4ade80', label: 'Online',   bg: '#4ade8015' },
    error:    { color: '#ef4444', label: 'Error',    bg: '#ef444415' },
    checking: { color: '#f59e0b', label: 'Checking', bg: '#f59e0b15' },
    skipped:  { color: '#6b7280', label: 'N/A',      bg: '#6b728015' },
  }[status] ?? { color: '#6b7280', label: 'Unknown', bg: 'transparent' }

  return (
    <div className="flex items-center gap-2">
      <span
        className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider"
        style={{ color: cfg.color, backgroundColor: cfg.bg, border: `1px solid ${cfg.color}30` }}
      >
        {status === 'checking' && <span className="inline-block animate-spin mr-1">⟳</span>}
        {cfg.label}
      </span>
      {latencyMs !== undefined && latencyMs !== null && status === 'ok' && (
        <span className="text-[10px] font-mono text-white/30">{latencyMs}ms</span>
      )}
    </div>
  )
}

// ─── Check row ────────────────────────────────────────────────────────────────

function CheckRow({ check, result, index }) {
  const cat = CATEGORY_LABELS[check.category]
  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.04 }}
      className="flex items-center justify-between gap-4 px-4 py-3 rounded-xl border border-white/6 hover:border-white/12 transition-colors"
      style={{
        background: result?.status === 'ok' ? 'rgba(74,222,128,0.03)' : result?.status === 'error' ? 'rgba(239,68,68,0.03)' : 'rgba(0,0,0,0.3)',
      }}
    >
      <div className="flex items-center gap-3 min-w-0">
        <span className="text-base shrink-0">{cat?.icon}</span>
        <div className="min-w-0">
          <div className="text-sm font-semibold text-white/90">{check.label}</div>
          <div className="text-[11px] font-mono text-white/30 mt-0.5">{check.description}</div>
          {result?.error && (
            <div className="text-[11px] font-mono text-red-400/80 mt-0.5 truncate max-w-xs">{result.error}</div>
          )}
          {result?.detail && result.status === 'ok' && (
            <div className="text-[11px] font-mono text-white/20 mt-0.5 truncate max-w-xs">{result.detail}</div>
          )}
        </div>
      </div>
      <div className="shrink-0">
        <StatusBadge status={result?.status ?? 'checking'} latencyMs={result?.latencyMs} />
      </div>
    </motion.div>
  )
}

// ─── Domain config card ───────────────────────────────────────────────────────

function DomainConfigCard({ config }) {
  if (!config) {
    return (
      <div className="rounded-2xl border border-white/8 p-6 mb-6" style={{ background: 'rgba(0,0,0,0.4)' }}>
        <div className="text-sm text-white/30 font-mono">Loading platform configuration…</div>
      </div>
    )
  }

  const fields = [
    { label: 'Region',        value: config.region || config.WEISSMAN_REGION || '—' },
    { label: 'Version',       value: config.version ? `v${config.version}` : '—' },
    { label: 'Engine Count',  value: `${ENGINES_REGISTRY.length} engines` },
    { label: 'Engine Groups', value: `${ENGINE_GROUP_DEFS.length} groups` },
    { label: 'API Base',      value: typeof window !== 'undefined' ? window.location.origin : '—' },
    { label: 'Deployment',    value: config.deployment || 'production' },
  ]

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border p-6 mb-6"
      style={{
        background: 'linear-gradient(135deg, rgba(16,185,129,0.08) 0%, rgba(0,0,0,0.5) 100%)',
        borderColor: '#10b98130',
      }}
    >
      <div className="flex items-center gap-3 mb-4">
        <span className="text-xl">🌐</span>
        <h2 className="text-base font-bold text-white">Platform Configuration</h2>
        <span
          className="ml-auto px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider border"
          style={{ color: '#4ade80', borderColor: '#4ade8030', background: '#4ade8010' }}
        >
          ✓ Configured
        </span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {fields.map(({ label, value }) => (
          <div key={label} className="rounded-lg bg-black/30 border border-white/6 px-3 py-2.5">
            <div className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-1">{label}</div>
            <div className="text-sm font-mono text-white/80 break-all">{value}</div>
          </div>
        ))}
      </div>
    </motion.div>
  )
}

// ─── Engine groups overview ────────────────────────────────────────────────────

function EngineGroupsCard() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      className="rounded-2xl border border-white/8 p-6 mb-6"
      style={{ background: 'linear-gradient(135deg, rgba(139,92,246,0.08) 0%, rgba(0,0,0,0.5) 100%)' }}
    >
      <div className="flex items-center gap-3 mb-4">
        <span className="text-xl">⬡</span>
        <h2 className="text-base font-bold text-white">Attack Engine Registry</h2>
        <span
          className="ml-auto px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border"
          style={{ color: '#a78bfa', borderColor: '#8b5cf630', background: '#8b5cf610' }}
        >
          {ENGINES_REGISTRY.length} Engines Active
        </span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-2">
        {ENGINE_GROUP_DEFS.map((g) => {
          const count = ENGINES_REGISTRY.filter((e) => e.group === g.id).length
          return (
            <Link
              key={g.id}
              to={`/engines?group=${g.id}`}
              id={`sysstat-engine-group-${g.id}`}
              className="rounded-lg p-2.5 border transition-all hover:border-white/20 hover:scale-105 text-center"
              style={{ borderColor: `${g.color}20`, background: `${g.color}08` }}
            >
              <div className="text-xl font-black font-mono" style={{ color: g.color }}>{count}</div>
              <div className="text-[9px] font-mono text-white/40 mt-0.5 leading-tight">{g.label}</div>
            </Link>
          )
        })}
      </div>
    </motion.div>
  )
}

// ─── Overall score ────────────────────────────────────────────────────────────

function OverallScore({ results }) {
  const total = results.length
  const ok = results.filter((r) => r?.status === 'ok').length
  const errors = results.filter((r) => r?.status === 'error').length
  const checking = results.filter((r) => !r || r?.status === 'checking').length
  const pct = total ? Math.round((ok / total) * 100) : 0

  const color = pct >= 90 ? '#4ade80' : pct >= 60 ? '#f59e0b' : '#ef4444'

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      className="rounded-2xl border p-6 mb-6 flex flex-col sm:flex-row items-start sm:items-center gap-6"
      style={{ borderColor: `${color}30`, background: `linear-gradient(135deg, ${color}08 0%, rgba(0,0,0,0.5) 100%)` }}
    >
      <div className="flex flex-col items-center shrink-0">
        <div className="text-5xl font-black font-mono tabular-nums" style={{ color }}>{pct}%</div>
        <div className="text-[10px] font-mono text-white/30 mt-1 uppercase tracking-widest">System Health</div>
      </div>
      <div className="flex-1 space-y-2">
        <div className="flex items-center gap-3">
          <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0" />
          <span className="text-xs font-mono text-white/70">{ok} services online</span>
        </div>
        {errors > 0 && (
          <div className="flex items-center gap-3">
            <span className="w-2 h-2 rounded-full bg-red-400 shrink-0" />
            <span className="text-xs font-mono text-red-300/80">{errors} services with errors</span>
          </div>
        )}
        {checking > 0 && (
          <div className="flex items-center gap-3">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse shrink-0" />
            <span className="text-xs font-mono text-white/50">{checking} checking…</span>
          </div>
        )}
      </div>
      <button
        type="button"
        id="sysstat-btn-recheck"
        onClick={() => window.location.reload()}
        className="px-4 py-2 rounded-lg border text-xs font-mono font-semibold transition-all hover:scale-105 shrink-0"
        style={{ borderColor: `${color}30`, color, background: `${color}10` }}
      >
        ⟳ Re-check All
      </button>
    </motion.div>
  )
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export default function SystemStatus() {
  const [results, setResults] = useState({})
  const [platformConfig, setPlatformConfig] = useState(null)
  const [running, setRunning] = useState(false)

  const runChecks = useCallback(async () => {
    setRunning(true)
    setResults({})

    await Promise.all(
      CHECKS.map(async (check) => {
        const t0 = performance.now()
        try {
          const fetchFn = check.auth ? apiFetch : fetch
          const r = await fetchFn(check.endpoint, { cache: 'no-store' })
          const latencyMs = Math.round(performance.now() - t0)

          let detail = null
          // 401/403 responses mean the endpoint exists and is protected — considered 'ok' for
          // connectivity purposes (the auth check endpoint itself handles session validation).
          const isConnectivityOk = r.ok || r.status === 401 || r.status === 403
          const isError = !r.ok && r.status !== 401 && r.status !== 403
          if (check.id === 'config_public' && r.ok) {
            const d = await r.json().catch(() => ({}))
            setPlatformConfig(d)
            detail = [d.region, d.version ? `v${d.version}` : null].filter(Boolean).join(' · ') || null
          } else if (check.id === 'dashboard_stats' && r.ok) {
            const d = await r.json().catch(() => ({}))
            detail = `${d.total_vulnerabilities ?? '?'} findings · score ${d.security_score ?? '?'}%`
          } else if (check.id === 'scan_status' && r.ok) {
            const d = await r.json().catch(() => ({}))
            detail = d.running ? 'Scan active' : 'Idle'
          }

          setResults((prev) => ({
            ...prev,
            [check.id]: {
              status: isConnectivityOk ? 'ok' : 'error',
              latencyMs,
              detail,
              error: isError ? `HTTP ${r.status}` : null,
            },
          }))
        } catch (err) {
          setResults((prev) => ({
            ...prev,
            [check.id]: {
              status: 'error',
              latencyMs: Math.round(performance.now() - t0),
              error: err?.message || 'Network error',
            },
          }))
        }
      })
    )
    setRunning(false)
  }, [])

  useEffect(() => {
    runChecks()
  }, [runChecks])

  const resultsList = CHECKS.map((c) => results[c.id])
  const categories = Object.entries(CATEGORY_LABELS)

  return (
    <PageShell
      title="System Status"
      subtitle="Domain configuration & platform health"
      badge="LIVE"
      badgeColor="#10b981"
    >
      <div className="max-w-4xl mx-auto">
        {/* Overall score */}
        <OverallScore results={resultsList} />

        {/* Domain / platform config */}
        <DomainConfigCard config={platformConfig} />

        {/* Engine groups */}
        <EngineGroupsCard />

        {/* Per-category service checks */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="rounded-2xl border border-white/8 p-6 mb-6"
          style={{ background: 'rgba(0,0,0,0.35)' }}
        >
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-3">
              <span className="text-xl">📡</span>
              <h2 className="text-base font-bold text-white">API Endpoint Health</h2>
            </div>
            <button
              type="button"
              id="sysstat-btn-run-checks"
              onClick={runChecks}
              disabled={running}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono font-semibold transition-all hover:scale-105 disabled:opacity-50"
              style={{ borderColor: '#22d3ee30', color: '#22d3ee', background: '#22d3ee10' }}
            >
              {running ? <span className="animate-spin">⟳</span> : '⟳'}
              {running ? 'Checking…' : 'Run Checks'}
            </button>
          </div>

          <div className="space-y-2">
            {categories.map(([catId, catMeta]) => {
              const catChecks = CHECKS.filter((c) => c.category === catId)
              return (
                <div key={catId} className="mb-5">
                  <div className="flex items-center gap-2 mb-2 px-1">
                    <span className="text-sm">{catMeta.icon}</span>
                    <span
                      className="text-[10px] font-mono uppercase tracking-widest font-semibold"
                      style={{ color: catMeta.color }}
                    >
                      {catMeta.label}
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    {catChecks.map((check, i) => (
                      <CheckRow
                        key={check.id}
                        check={check}
                        result={results[check.id]}
                        index={i}
                      />
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        </motion.div>

        {/* Quick links */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4 }}
          className="rounded-2xl border border-white/8 p-6"
          style={{ background: 'rgba(0,0,0,0.3)' }}
        >
          <div className="flex items-center gap-3 mb-4">
            <span className="text-xl">🔗</span>
            <h2 className="text-base font-bold text-white">Quick Links</h2>
          </div>
          <div className="flex flex-wrap gap-2">
            {[
              { id: 'sysstat-ql-hub',      to: '/platform-hub',     label: 'Platform Hub',   color: '#22d3ee' },
              { id: 'sysstat-ql-engines',  to: '/engines',          label: 'Engine Matrix',  color: '#8b5cf6' },
              { id: 'sysstat-ql-findings', to: '/findings',         label: 'Findings C2',    color: '#f97316' },
              { id: 'sysstat-ql-admin',    to: '/admin',            label: 'Admin',          color: '#f59e0b' },
              { id: 'sysstat-ql-openapi',  href: '/api/openapi.json', label: 'OpenAPI Spec', color: '#60a5fa', external: true },
            ].map((l) =>
              l.external ? (
                <a
                  key={l.id}
                  id={l.id}
                  href={l.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-4 py-2 rounded-lg border text-xs font-mono font-medium transition-all hover:scale-105"
                  style={{ borderColor: `${l.color}30`, color: l.color, background: `${l.color}10` }}
                >
                  {l.label} ↗
                </a>
              ) : (
                <Link
                  key={l.id}
                  id={l.id}
                  to={l.to}
                  className="px-4 py-2 rounded-lg border text-xs font-mono font-medium transition-all hover:scale-105"
                  style={{ borderColor: `${l.color}30`, color: l.color, background: `${l.color}10` }}
                >
                  {l.label}
                </Link>
              )
            )}
          </div>
        </motion.div>
      </div>
    </PageShell>
  )
}
