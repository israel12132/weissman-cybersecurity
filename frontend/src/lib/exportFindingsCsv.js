/**
 * Export tenant findings rows to CSV — live data only, no fabricated columns.
 */
export function escapeCsvCell(v) {
  return `"${String(v ?? '').replace(/"/g, '""')}"`
}

export function downloadCsv(rows, header, filenamePrefix) {
  const lines = [
    header.join(','),
    ...rows.map((row) => row.map(escapeCsvCell).join(',')),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
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
