/** Live attack-readiness gaps from GET /api/attack-coverage. Empty strings are not gaps. */
export function readinessGaps(readiness) {
  if (!readiness || !Array.isArray(readiness.gaps)) return []
  return readiness.gaps.filter((g) => String(g || '').trim())
}
