/**
 * Unified page export — CSV + PDF for Command Center panels.
 *
 * CSV goes through `downloadCsv`, which prefixes any cell beginning with = + - @ (or
 * tab/CR) with a single quote, so exported data can never be evaluated as a spreadsheet
 * formula (CSV injection). PDF is generated fully client-side by `buildSimpleTextPdf`
 * (no external libraries, CSP-safe). Both take the same (header, rows) shape so a page
 * defines its columns once and gets both formats.
 */
import { downloadCsv } from './exportFindingsCsv'
import { buildSimpleTextPdf, downloadBytes } from './pdfExport'

/** Formula-injection-safe CSV of `rows` (array of arrays) under `header` (array of strings). */
export function exportRowsCsv(header, rows, filenamePrefix) {
  downloadCsv(Array.isArray(rows) ? rows : [], Array.isArray(header) ? header : [], filenamePrefix)
}

/**
 * Self-contained text PDF of the same tabular data. `title` is the document heading.
 * buildSimpleTextPdf caps at 120 lines / 120 chars per line, which comfortably covers
 * the pre-aggregated panels this is used for; longer rows are truncated by that helper.
 */
export function exportRowsPdf(title, header, rows, filenamePrefix) {
  const safeHeader = Array.isArray(header) ? header : []
  const safeRows = Array.isArray(rows) ? rows : []
  const lines = [
    String(title || filenamePrefix || 'Weissman export'),
    `Generated ${new Date().toISOString()}`,
    '',
    safeHeader.join('  |  '),
    ...safeRows.map((r) => (Array.isArray(r) ? r : []).map((c) => String(c ?? '')).join('  |  ')),
  ]
  downloadBytes(
    buildSimpleTextPdf(lines),
    `${filenamePrefix}-${new Date().toISOString().slice(0, 10)}.pdf`,
    'application/pdf',
  )
}

/** Case-insensitive substring match of `query` against the concatenated `fields`. */
export function rowMatchesQuery(query, fields) {
  const q = String(query || '').trim().toLowerCase()
  if (!q) return true
  return fields.some((f) => String(f ?? '').toLowerCase().includes(q))
}
