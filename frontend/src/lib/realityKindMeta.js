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
    description: 'Alias — runs the same live probes as its canonical engine',
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
