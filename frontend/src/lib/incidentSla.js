/**
 * Incident SLA model — derived entirely from live incident data (created
 * timestamp + severity + status). No backend SLA field required; the target is
 * a policy the UI applies so analysts see time-to-breach at a glance.
 */

/** Time-to-resolve target per severity, in hours. */
export const SLA_TARGET_HOURS = {
  critical: 1,
  high: 4,
  medium: 24,
  low: 72,
  info: 72,
}

const HOUR_MS = 3_600_000

/**
 * Compute SLA state for an incident.
 * @param {{ created?: string, updated?: string, severity?: string, status?: string }} incident
 * @param {number} nowMs current epoch ms (pass a ticking value for a live clock)
 * @returns {{ targetMs: number, elapsedMs: number, remainingMs: number, breached: boolean, pct: number, resolved: boolean, unknown: boolean }}
 */
export function computeSla(incident, nowMs) {
  const sev = String(incident?.severity ?? 'high').toLowerCase()
  const hours = SLA_TARGET_HOURS[sev] ?? SLA_TARGET_HOURS.high
  const targetMs = hours * HOUR_MS
  const createdMs = incident?.created ? new Date(incident.created).getTime() : NaN
  if (!Number.isFinite(createdMs)) {
    return { targetMs, elapsedMs: 0, remainingMs: targetMs, breached: false, pct: 0, resolved: false, unknown: true }
  }
  const resolved = String(incident?.status ?? '').toLowerCase() === 'resolved'
  // A resolved incident freezes the clock. Prefer its `updated` timestamp; if it
  // is missing, freeze at `created` (elapsed 0 → treated as met) rather than
  // letting the live clock keep counting up for finished work.
  const endMs = resolved
    ? (incident?.updated ? new Date(incident.updated).getTime() : createdMs)
    : nowMs
  const elapsedMs = Math.max(0, (Number.isFinite(endMs) ? endMs : nowMs) - createdMs)
  const remainingMs = targetMs - elapsedMs
  const breached = remainingMs <= 0
  const pct = Math.max(0, Math.min(100, (elapsedMs / targetMs) * 100))
  return { targetMs, elapsedMs, remainingMs, breached, pct, resolved, unknown: false }
}

/** Coarse status band for coloring: 'met' | 'ok' | 'warning' | 'breached'. */
export function slaBand(sla) {
  if (sla.resolved) return sla.breached ? 'breached' : 'met'
  if (sla.breached) return 'breached'
  if (sla.pct >= 75) return 'warning'
  return 'ok'
}

export const SLA_BAND_COLOR = {
  met: '#4ade80',
  ok: '#22d3ee',
  warning: '#f59e0b',
  breached: '#ef4444',
}

/**
 * Human countdown string, e.g. "2h 14m left" or "1h 3m over".
 * @param {ReturnType<typeof computeSla>} sla
 * @param {(key: string, opts?: object) => string} t i18n translator
 */
export function slaCountdownLabel(sla, t) {
  if (sla.unknown) return t('pages.incidentResponseCenter.sla_unknown')
  const ms = Math.abs(sla.remainingMs)
  const h = Math.floor(ms / HOUR_MS)
  const m = Math.floor((ms % HOUR_MS) / 60_000)
  const parts = h > 0 ? `${h}h ${m}m` : `${m}m`
  if (sla.resolved) {
    return sla.breached
      ? t('pages.incidentResponseCenter.sla_resolved_late', { time: parts })
      : t('pages.incidentResponseCenter.sla_resolved_ontime')
  }
  return sla.breached
    ? t('pages.incidentResponseCenter.sla_over', { time: parts })
    : t('pages.incidentResponseCenter.sla_left', { time: parts })
}
