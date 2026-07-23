import { escapeCsvCell, downloadCsv } from './exportFindingsCsv.js'

/**
 * Audit-trail export — turns audit log entries into tamper-aware CSV/JSON
 * downloads. Reuses the findings CSV helpers so formula-injection escaping is
 * consistent across the app.
 */

export const AUDIT_COLUMNS = ['timestamp', 'actor', 'action', 'target', 'ip', 'result', 'detail']

/** Map audit entries to header + rows (stable column order). */
export function auditTrailToRows(entries) {
  const list = Array.isArray(entries) ? entries : []
  const header = AUDIT_COLUMNS
  const rows = list.map((e) => AUDIT_COLUMNS.map((k) => e?.[k] ?? ''))
  return { header, rows }
}

/** Download audit entries as CSV. */
export function exportAuditTrailCsv(entries, filenamePrefix = 'audit-trail') {
  const { header, rows } = auditTrailToRows(entries)
  downloadCsv(rows, header, filenamePrefix)
}

/** Serialize audit entries to pretty JSON (stable column subset). */
export function auditTrailToJson(entries) {
  const list = Array.isArray(entries) ? entries : []
  const normalized = list.map((e) =>
    AUDIT_COLUMNS.reduce((acc, k) => {
      acc[k] = e?.[k] ?? null
      return acc
    }, {}),
  )
  return JSON.stringify(normalized, null, 2)
}

/** Download audit entries as JSON. */
export function exportAuditTrailJson(entries, filenamePrefix = 'audit-trail') {
  if (typeof document === 'undefined') return
  const blob = new Blob([auditTrailToJson(entries)], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${filenamePrefix}.json`
  a.click()
  URL.revokeObjectURL(url)
}

// Re-export for callers that want the low-level escaper.
export { escapeCsvCell }
