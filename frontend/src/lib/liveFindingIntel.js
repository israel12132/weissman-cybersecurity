export function liveCvssLabel(finding) {
  const n = Number(finding?.cvss_score)
  if (Number.isFinite(n) && n > 0) return n.toFixed(1)
  return '—'
}
