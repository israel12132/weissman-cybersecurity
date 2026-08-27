/**
 * Shared risk/posture formatting used by the executive + posture surfaces.
 *
 * Scope note: only the posture-family palette lives here (grade A–F on the
 * emerald→rose scale used by SecurityPosture and ExecutiveOverview). Other
 * engine surfaces deliberately use their own grade palettes, so they are NOT
 * consolidated here — keep this to the posture family to avoid changing their
 * look.
 */

/** Compact USD: $1.23M / $4.5K / $678. Matches the executive/financial tiles. */
export function fmtUsd(n) {
  const v = Number(n) || 0
  const abs = Math.abs(v)
  if (abs >= 1_000_000) return `$${(v / 1_000_000).toFixed(2)}M`
  if (abs >= 1_000) return `$${(v / 1_000).toFixed(1)}K`
  return `$${v.toLocaleString()}`
}

/**
 * FAIR ALE compact label for cockpit / PDF / kill-chain CEO tiles.
 * Unpriced or empty inputs → null (fail-visible). Never invents $0.
 */
export function fairAleLabel(fair) {
  if (!fair || fair.priced !== true) return null
  const n = Number(fair.ale_annualised_usd)
  if (!Number.isFinite(n) || n <= 0) return null
  return fmtUsd(n)
}

/** FAIR worst-case SLE compact label. Null when FAIR cannot price. */
export function fairSleLabel(fair) {
  if (!fair || fair.priced !== true) return null
  const n = Number(fair.sle_worst_usd)
  if (!Number.isFinite(n) || n <= 0) return null
  return fmtUsd(n)
}

/** Colour for a letter grade A–F on the posture scale (unknown → cyan). */
export function postureGradeColor(grade) {
  return (
    { A: '#4ade80', B: '#84cc16', C: '#facc15', D: '#f97316', F: '#ef4444' }[
      String(grade || '').toUpperCase()
    ] || '#22d3ee'
  )
}

/** Colour for a 0–100 posture score, banded green→rose. */
export function postureScoreColor(score) {
  const s = Number(score) || 0
  if (s >= 90) return '#4ade80'
  if (s >= 75) return '#84cc16'
  if (s >= 60) return '#facc15'
  if (s >= 40) return '#f97316'
  return '#ef4444'
}
