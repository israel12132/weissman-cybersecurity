import React from 'react'
import { ShieldAlert, TrendingUp } from 'lucide-react'

function formatEpss(epss) {
  if (epss == null || epss === '') return null
  const n = typeof epss === 'number' ? epss : parseFloat(epss)
  if (Number.isNaN(n)) return null
  return n <= 1 ? `${(n * 100).toFixed(1)}%` : n.toFixed(2)
}

function epssTier(epss) {
  if (epss == null || epss === '') return 'none'
  const n = typeof epss === 'number' ? epss : parseFloat(epss)
  if (Number.isNaN(n)) return 'none'
  const pct = n <= 1 ? n : n / 100
  if (pct >= 0.7) return 'high'
  if (pct >= 0.3) return 'medium'
  return 'low'
}

/**
 * CISA KEV + EPSS score display for vuln intel rows.
 *
 * Props:
 *  - kev: boolean — listed in CISA Known Exploited Vulnerabilities catalog
 *  - epss: number 0–1 (or percentage)
 *  - compact: tighter inline layout
 *  - className
 */
export default function KevEpssBadge({ kev, epss, compact = false, className = '' }) {
  const epssLabel = formatEpss(epss)
  const tier = epssTier(epss)
  const hasKev = !!kev
  const hasEpss = epssLabel != null

  if (!hasKev && !hasEpss) {
    return <span className={`text-[11px] font-mono text-white/25 ${className}`}>—</span>
  }

  const epssColor =
    tier === 'high' ? 'var(--epss-high)' : tier === 'medium' ? '#94a3b8' : 'var(--text-muted)'

  const gap = compact ? 'gap-1' : 'gap-1.5'
  const pad = compact ? 'px-1.5 py-0.5 text-[9px]' : 'px-2 py-0.5 text-[10px]'

  return (
    <div className={`inline-flex items-center ${gap} ${className}`}>
      {hasKev && (
        <span
          className={`inline-flex items-center gap-1 rounded border font-mono font-semibold uppercase tracking-wider ${pad}`}
          style={{
            color: 'var(--kev)',
            backgroundColor: 'var(--kev-bg)',
            borderColor: 'rgba(245, 158, 11, 0.35)',
          }}
          title="CISA Known Exploited Vulnerability"
        >
          <ShieldAlert className={compact ? 'w-2.5 h-2.5' : 'w-3 h-3'} strokeWidth={2.25} />
          KEV
        </span>
      )}
      {hasEpss && (
        <span
          className={`inline-flex items-center gap-1 rounded border font-mono font-semibold ${pad}`}
          style={{
            color: epssColor,
            backgroundColor: 'var(--epss-bg)',
            borderColor: tier === 'high' ? 'rgba(167, 139, 250, 0.35)' : 'rgba(255,255,255,0.1)',
          }}
          title="Exploit Prediction Scoring System probability"
        >
          <TrendingUp className={compact ? 'w-2.5 h-2.5' : 'w-3 h-3'} strokeWidth={2.25} />
          EPSS {epssLabel}
        </span>
      )}
    </div>
  )
}
