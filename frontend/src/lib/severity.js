/**
 * Shared severity vocabulary for SOC surfaces (findings, IOCs, UEBA, live feed).
 *
 * Centralises the severity rank + colour used across list/table pages so
 * sorting and row-accent colours stay identical everywhere. Values are the
 * canonical set previously duplicated inline in several pages.
 */

/** Numeric rank for ordering (higher = more severe). */
export const SEV_ORDER = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })

/** Hex colour per severity, used for badges and row accents. */
export const SEV_COLOR = Object.freeze({
  critical: '#f43f5e',
  high: '#f97316',
  medium: '#facc15',
  low: '#38bdf8',
  info: '#94a3b8',
})

/** Normalise an arbitrary severity value to a lowercase known key (default 'info'). */
export function normalizeSeverity(sev) {
  const s = String(sev ?? '').toLowerCase().trim()
  return s in SEV_ORDER ? s : 'info'
}

/** Rank for a severity value (unknown → 0). */
export function sevRank(sev) {
  return SEV_ORDER[normalizeSeverity(sev)] ?? 0
}

/** Colour for a severity value (unknown → info colour). */
export function sevColor(sev) {
  return SEV_COLOR[normalizeSeverity(sev)] ?? SEV_COLOR.info
}

/** Comparator for ascending severity sort; negate for descending. */
export function compareSeverity(a, b) {
  return sevRank(a) - sevRank(b)
}
