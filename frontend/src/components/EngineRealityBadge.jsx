import { useMemo } from 'react'
import { useEngineCapabilities } from '../lib/useEngineCapabilities'

/** Reality kind styling — mirrors backend `/api/engines/capabilities` legend. */
export const REALITY_KIND_META = {
  real_probe: {
    label: 'LIVE PROBE',
    color: '#34d399',
    border: 'rgba(52,211,153,0.35)',
    bg: 'rgba(52,211,153,0.08)',
    description: 'Live probe — real network/host detection',
  },
  alias: {
    label: 'ALIAS',
    color: '#9ca3af',
    border: 'rgba(156,163,175,0.30)',
    bg: 'rgba(156,163,175,0.07)',
    description: 'Alias — same detection as its canonical engine',
  },
  agent_required: {
    label: 'AGENT REQUIRED',
    color: '#f59e0b',
    border: 'rgba(245,158,11,0.35)',
    bg: 'rgba(245,158,11,0.08)',
    description: 'Requires the endpoint agent; info-only from a remote scan',
  },
  special: {
    label: 'PoE',
    color: '#a78bfa',
    border: 'rgba(167,139,250,0.35)',
    bg: 'rgba(167,139,250,0.08)',
    description: 'poe_synthesis — runs via the async-job path',
  },
}

const SIZE_CLASSES = {
  xs: 'text-[8px] px-1.5 py-0.5 tracking-[0.14em]',
  sm: 'text-[9px] px-1.5 py-0.5 tracking-wider',
  md: 'text-[10px] px-2 py-0.5 tracking-wider',
}

function badgeTitle({ kind, canonical, remoteDetection, legendHint }) {
  const parts = [REALITY_KIND_META[kind]?.description || `Engine reality: ${kind}`]
  if (canonical) parts.push(`Resolves to ${canonical}`)
  if (remoteDetection != null) {
    parts.push(remoteDetection ? 'Remote detection: yes' : 'Remote detection: no (agent required)')
  }
  if (legendHint) parts.push(legendHint)
  return parts.join(' · ')
}

/**
 * Per-engine reality badge sourced from GET /api/engines/capabilities.
 * Pass `engineId` to resolve kind/canonical/remote_detection from the shared hook cache,
 * or pass `kind` (+ optional canonical/remoteDetection) directly.
 */
export default function EngineRealityBadge({
  engineId,
  kind: kindProp,
  canonical: canonicalProp,
  remoteDetection: remoteProp,
  size = 'xs',
  showRemote = false,
  showCanonical = false,
  className = '',
}) {
  const { byId, legend, loading } = useEngineCapabilities()

  const cap = engineId ? byId[engineId] : null
  const kind = kindProp ?? cap?.kind
  const canonical = canonicalProp ?? cap?.canonical
  const remoteDetection = remoteProp ?? cap?.remote_detection

  const meta = REALITY_KIND_META[kind]
  const legendHint = legend?.[kind]

  const title = useMemo(
    () => badgeTitle({ kind, canonical, remoteDetection, legendHint }),
    [kind, canonical, remoteDetection, legendHint],
  )

  if (!meta) {
    if (loading && engineId) {
      return (
        <span
          className={`inline-block rounded-md border border-white/10 bg-white/5 animate-pulse ${SIZE_CLASSES[size] ?? SIZE_CLASSES.xs} ${className}`}
          aria-hidden
        >
          &nbsp;&nbsp;&nbsp;
        </span>
      )
    }
    return null
  }

  return (
    <span className={`inline-flex items-center gap-1 flex-wrap ${className}`}>
      <span
        className={`font-mono rounded-md border uppercase font-semibold ${SIZE_CLASSES[size] ?? SIZE_CLASSES.xs}`}
        style={{ color: meta.color, borderColor: meta.border, backgroundColor: meta.bg }}
        title={title}
      >
        {meta.label}
      </span>
      {showRemote && remoteDetection != null && (
        <span
          className={`font-mono rounded border uppercase font-semibold ${SIZE_CLASSES[size] ?? SIZE_CLASSES.xs}`}
          style={
            remoteDetection
              ? { color: '#22d3ee', borderColor: 'rgba(34,211,238,0.35)', backgroundColor: 'rgba(34,211,238,0.08)' }
              : { color: '#6b7280', borderColor: 'rgba(107,114,128,0.35)', backgroundColor: 'rgba(107,114,128,0.08)' }
          }
          title={remoteDetection ? 'Detects remotely without an agent' : 'Not remotely detectable'}
        >
          {remoteDetection ? 'REMOTE' : 'LOCAL'}
        </span>
      )}
      {showCanonical && canonical && (
        <span className="text-[9px] font-mono text-gray-500 truncate max-w-[140px]" title={`Canonical: ${canonical}`}>
          → {canonical}
        </span>
      )}
    </span>
  )
}

/** Fleet-wide reality summary strip from capabilities API summary counts. */
export function EngineRealitySummary({ className = '', compact = false }) {
  const { total, summary, remoteDetectionCount, loading } = useEngineCapabilities()

  if (loading && !total) {
    return (
      <div className={`flex gap-2 ${className}`}>
        {[1, 2, 3, 4].map((i) => (
          <span key={i} className="h-5 w-16 rounded bg-white/5 animate-pulse" />
        ))}
      </div>
    )
  }

  const items = [
    { key: 'real_probe', tone: '#34d399' },
    { key: 'alias', tone: '#9ca3af' },
    { key: 'agent_required', tone: '#f59e0b' },
    { key: 'special', tone: '#a78bfa' },
  ]

  return (
    <div className={`flex flex-wrap items-center gap-2 text-[10px] font-mono ${className}`}>
      {!compact && (
        <span className="text-gray-500 uppercase tracking-wider">
          {total} engines · {remoteDetectionCount} remote
        </span>
      )}
      {items.map(({ key, tone }) => (
        <span
          key={key}
          className="px-2 py-0.5 rounded border"
          style={{ color: tone, borderColor: `${tone}44`, backgroundColor: `${tone}14` }}
          title={REALITY_KIND_META[key]?.description}
        >
          {REALITY_KIND_META[key]?.label ?? key} {summary[key] ?? 0}
        </span>
      ))}
    </div>
  )
}
