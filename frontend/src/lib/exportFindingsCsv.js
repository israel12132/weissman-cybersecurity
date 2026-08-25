export const UTF8_BOM = '\uFEFF'

/**
 * Export tenant findings rows to CSV — live data only, no fabricated columns.
 */
export function escapeCsvCell(v) {
  let s = String(v ?? '')
  // Neutralize spreadsheet formula injection: a cell that Excel/Sheets would evaluate as a formula
  // (leading = + - @, or tab/CR) is prefixed with a single quote so it's treated as literal text.
  if (/^[=+\-@\t\r]/.test(s)) {
    s = `'${s}`
  }
  return `"${s.replace(/"/g, '""')}"`
}

export function downloadCsv(rows, header, filenamePrefix) {
  const safeHeader = Array.isArray(header) ? header : []
  const safeRows = Array.isArray(rows) ? rows : []
  const lines = [
    safeHeader.map(escapeCsvCell).join(','),
    ...safeRows.map((row) => (Array.isArray(row) ? row : []).map(escapeCsvCell).join(',')),
  ]
  const blob = new Blob([UTF8_BOM + lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${filenamePrefix}-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

/** Standard finding shape → CSV */
export function exportStandardFindingsCsv(findings, filenamePrefix, extraKeys = []) {
  const header = ['severity', 'title', 'type', 'description', 'remediation', ...extraKeys]
  const rows = findings.map((f) => [
    f.severity,
    f.title,
    f.type,
    f.description,
    f.remediation,
    ...extraKeys.map((k) => f[k]),
  ])
  downloadCsv(rows, header, filenamePrefix)
}

/** IaC / policy finding shape */
export function exportPolicyFindingsCsv(findings, filenamePrefix) {
  const header = ['severity', 'policy_id', 'title', 'file', 'resource', 'framework', 'description']
  const rows = findings.map((f) => [
    f.severity,
    f.policy_id,
    f.title,
    f.file,
    f.resource,
    f.framework,
    f.description,
  ])
  downloadCsv(rows, header, filenamePrefix)
}
