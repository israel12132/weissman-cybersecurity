/**
 * Pure derivations for the platform Security-Posture self-audit page.
 * Extracted from the page so the weighted-score math and worklist ordering are
 * unit-testable (a mis-weight would otherwise ship green — the page only smoke-
 * tests "doesn't crash").
 */

/**
 * Summarize posture checks into pass counts + the weighted pass ratio the score
 * ring is built from. Non-numeric/missing weights count as 0; passed is truthy.
 * @param {Array<{passed?:boolean, weight?:number|string}>} checks
 * @returns {{ passed:number, total:number, passedWeight:number, totalWeight:number }}
 */
export function summarizePostureChecks(checks) {
  const list = Array.isArray(checks) ? checks : []
  const passed = list.filter((c) => c && c.passed)
  const passedWeight = passed.reduce((s, c) => s + (Number(c.weight) || 0), 0)
  const totalWeight = list.reduce((s, c) => s + (Number(c.weight) || 0), 0)
  return { passed: passed.length, total: list.length, passedWeight, totalWeight }
}

/**
 * Order checks failed-first, then by descending weight — the remediation
 * worklist. Does not mutate the input.
 * @param {Array<{passed?:boolean, weight?:number|string}>} checks
 * @returns {Array}
 */
export function orderPostureChecks(checks) {
  const list = Array.isArray(checks) ? checks : []
  return [...list].sort((a, b) =>
    a.passed === b.passed ? (Number(b.weight) || 0) - (Number(a.weight) || 0) : a.passed ? 1 : -1,
  )
}
