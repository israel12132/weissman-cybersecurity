/**
 * Unified page export — CSV + Excel + PDF for Command Center panels.
 *
 * CSV goes through `downloadCsv` (formula-injection safe, UTF-8 BOM). Excel and PDF
 * prefer the live `/api/export/workbook` and `/api/export/document` engines and fall
 * back to CSV / client-side text PDF when the API is unreachable.
 */
import { downloadCsv } from './exportFindingsCsv'
import { exportWorkbook, tableToWorkbookSpec } from './exportWorkbook'
import { exportDocument, tableToDocumentSpec } from './documentExport'

/** Formula-injection-safe CSV of `rows` (array of arrays) under `header` (array of strings). */
export function exportRowsCsv(header, rows, filenamePrefix) {
  downloadCsv(Array.isArray(rows) ? rows : [], Array.isArray(header) ? header : [], filenamePrefix)
}

/** Board-grade PDF of the same tabular data via `/api/export/document`. */
export function exportRowsPdf(title, header, rows, filenamePrefix) {
  const safeHeader = Array.isArray(header) ? header : []
  const safeRows = Array.isArray(rows) ? rows : []
  return exportDocument(
    tableToDocumentSpec({ title, header: safeHeader, rows: safeRows }),
    filenamePrefix,
  )
}

/** Board-grade XLSX of the same tabular data via `/api/export/workbook`. */
export function exportRowsXlsx(title, header, rows, filenamePrefix) {
  const safeHeader = Array.isArray(header) ? header : []
  const safeRows = Array.isArray(rows) ? rows : []
  return exportWorkbook(
    tableToWorkbookSpec({ title, header: safeHeader, rows: safeRows }),
    filenamePrefix,
  )
}

/** Case-insensitive substring match of `query` against the concatenated `fields`. */
export function rowMatchesQuery(query, fields) {
  const q = String(query || '').trim().toLowerCase()
  if (!q) return true
  return fields.some((f) => String(f ?? '').toLowerCase().includes(q))
}
