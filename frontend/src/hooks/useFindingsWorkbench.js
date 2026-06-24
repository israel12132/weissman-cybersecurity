import { useMemo, useState, useCallback } from 'react'
import { exportStandardFindingsCsv } from '../lib/exportFindingsCsv'

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

/**
 * Search + severity filter + KPI counts + CSV export for live finding arrays.
 */
export function useFindingsWorkbench(findings, { csvPrefix = 'weissman-findings', haystackFn } = {}) {
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')

  const sorted = useMemo(() => {
    return [...(findings || [])].sort(
      (a, b) =>
        (SEVERITY_ORDER[(a.severity || 'info').toLowerCase()] ?? 9)
        - (SEVERITY_ORDER[(b.severity || 'info').toLowerCase()] ?? 9),
    )
  }, [findings])

  const defaultHaystack = useCallback(
    (f) => `${f.title || ''} ${f.type || ''} ${f.description || ''} ${f.remediation || ''} ${f.policy_id || ''} ${f.file || ''} ${f.resource || ''} ${f.framework || ''} ${f.component || ''} ${f.owasp_api || ''}`,
    [],
  )

  const toHaystack = haystackFn || defaultHaystack

  const filteredFindings = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return sorted.filter((f) => {
      const sev = (f.severity || 'info').toLowerCase()
      if (severityFilter !== 'all' && sev !== severityFilter) return false
      if (!q) return true
      return toHaystack(f).toLowerCase().includes(q)
    })
  }, [sorted, searchQuery, severityFilter, toHaystack])

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of sorted) {
      const s = (f.severity || 'info').toLowerCase()
      if (c[s] !== undefined) c[s] += 1
    }
    return c
  }, [sorted])

  const exportCsv = useCallback(() => {
    if (!filteredFindings.length) return
    exportStandardFindingsCsv(filteredFindings, csvPrefix)
  }, [filteredFindings, csvPrefix])

  return {
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    sortedFindings: sorted,
    filteredFindings,
    counts,
    exportCsv,
    total: sorted.length,
  }
}
