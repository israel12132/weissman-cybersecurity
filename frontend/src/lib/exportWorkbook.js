/**
 * Server-rendered XLSX download. Falls back to formula-safe CSV when the API
 * is unreachable so an analyst still leaves with live rows.
 */
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from './exportFindingsCsv'

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function stamp(prefix, ext) {
  return `${prefix || 'weissman-export'}-${new Date().toISOString().slice(0, 10)}.${ext}`
}

/** @param {{ title?: string, subtitle?: string, client?: string, lang?: string, sheets: { name: string, columns: { title: string, weight?: number, style?: string }[], rows: string[][] }[] }} spec */
export async function exportWorkbook(spec, filenamePrefix) {
  const prefix = filenamePrefix || 'weissman-export'
  try {
    const res = await apiFetch('/api/export/workbook', {
      method: 'POST',
      raw: true,
      body: spec,
    })
    if (!res.ok) throw new Error(`xlsx ${res.status}`)
    const blob = await res.blob()
    triggerDownload(blob, stamp(prefix, 'xlsx'))
    return
  } catch {
    const sheet = spec?.sheets?.[0]
    const header = (sheet?.columns || []).map((c) => c.title || '')
    const rows = Array.isArray(sheet?.rows) ? sheet.rows : []
    downloadCsv(rows, header, prefix)
  }
}

export function tableToWorkbookSpec({ title, client, lang, header, rows, sheetName }) {
  return {
    title: title || 'Weissman export',
    subtitle: 'Live Command Center export',
    org: 'Weissman Cybersecurity',
    client: client || '',
    classification: 'Confidential',
    lang: lang || 'en',
    sheets: [
      {
        name: sheetName || 'Data',
        columns: (header || []).map((title) => ({
          title,
          weight: 1,
          style: /sev/i.test(title) ? 'severity' : '',
        })),
        rows: Array.isArray(rows) ? rows.map((r) => (Array.isArray(r) ? r.map((c) => String(c ?? '')) : [])) : [],
      },
    ],
  }
}
