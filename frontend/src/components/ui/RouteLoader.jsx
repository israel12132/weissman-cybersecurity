import React from 'react'
import { useLocation } from 'react-router-dom'
import Logo from '../Logo'

const MODULE_LABELS = {
  '': 'Command Center',
  engines: 'Engine Matrix',
  findings: 'Findings Command Center',
  clients: 'Client Management',
  'vuln-intel': 'Vulnerability Intelligence',
  agents: 'Agent Management',
  jobs: 'Jobs Dashboard',
  ask: 'Ask Weissman',
  playbooks: 'SOAR Playbooks',
  'audit-log': 'Audit Log',
  'system-config': 'System Configuration',
  'engine-catalog': 'Engine Catalog',
  'threat-intel': 'Threat Intelligence',
  metrics: 'Metrics Dashboard',
  admin: 'Administration',
}

function resolveModuleName(pathname) {
  const segments = pathname.split('/').filter(Boolean)
  const first = segments[0] || ''
  if (MODULE_LABELS[first]) return MODULE_LABELS[first]
  if (segments.length > 1 && MODULE_LABELS[segments[0]]) {
    return MODULE_LABELS[segments[0]]
  }
  const last = segments[segments.length - 1] || 'dashboard'
  if (/^[0-9a-f-]{36}$/i.test(last) || /^[0-9]+$/.test(last)) {
    const parent = segments[segments.length - 2] || 'module'
    return MODULE_LABELS[parent] || parent.replace(/-/g, ' ')
  }
  return last.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

/**
 * Branded Suspense fallback — Weissman shield pulse + contextual module label.
 */
export default function RouteLoader() {
  const { pathname } = useLocation()
  const moduleName = resolveModuleName(pathname)

  return (
    <div
      className="min-h-[60vh] flex items-center justify-center bg-[#020617] animate-fade-in"
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label={`Loading ${moduleName}`}
    >
      <div className="text-center px-6">
        <div className="relative inline-flex items-center justify-center mb-5">
          <span
            className="absolute inset-0 -m-3 rounded-full bg-cyan-500/10 animate-pulse-subtle"
            aria-hidden="true"
          />
          <span
            className="absolute inset-0 -m-1 rounded-full border border-cyan-500/20 animate-pulse-subtle"
            style={{ animationDelay: '0.15s' }}
            aria-hidden="true"
          />
          <Logo compact size={44} className="relative animate-pulse-subtle drop-shadow-[0_0_18px_rgba(34,211,238,0.35)]" />
        </div>
        <p className="text-[10px] font-mono tracking-[0.22em] text-white/35 uppercase mb-1.5">
          Loading module…
        </p>
        <p className="text-sm font-medium text-cyan-200/80 capitalize">
          {moduleName}
        </p>
        <div className="mt-5 mx-auto w-32 h-[2px] rounded-full overflow-hidden bg-white/5">
          <div className="h-full w-1/2 rounded-full bg-gradient-to-r from-transparent via-cyan-400/70 to-transparent animate-shimmer" />
        </div>
      </div>
    </div>
  )
}
