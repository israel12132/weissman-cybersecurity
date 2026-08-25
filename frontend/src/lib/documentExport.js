/**
 * Server-rendered PDF download. Falls back to the client-side text PDF when
 * the live export API is unreachable so the analyst still gets a file.
 */
import { apiFetch } from '../utils/apiFetch'
import { buildSimpleTextPdf, downloadBytes } from './pdfExport'

function stamp(prefix) {
  return `${prefix || 'weissman-export'}-${new Date().toISOString().slice(0, 10)}.pdf`
}

/** @param {{ title?: string, subtitle?: string, client?: string, lang?: string, sections: object[] }} spec */
export async function exportDocument(spec, filenamePrefix) {
  const prefix = filenamePrefix || 'weissman-export'
  try {
    const res = await apiFetch('/api/export/document', {
      method: 'POST',
      raw: true,
      body: spec,
    })
    if (!res.ok) throw new Error(`pdf ${res.status}`)
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = stamp(prefix)
    a.click()
    URL.revokeObjectURL(url)
    return
  } catch {
    const lines = [
      String(spec?.title || prefix),
      String(spec?.subtitle || ''),
      `Generated ${new Date().toISOString()}`,
      '',
      ...(spec?.sections || []).flatMap((s) => [
        s.title || '',
        ...(s.blocks || []).flatMap((b) => {
          if (b.type === 'paragraph') return [b.text]
          if (b.type === 'heading') return [b.text]
          if (b.type === 'bullets') return b.items || []
          if (b.type === 'table') {
            const header = (b.columns || []).map((c) => c.title).join(' | ')
            return [header, ...(b.rows || []).map((r) => (r || []).join(' | '))]
          }
          return []
        }),
      ]),
    ]
    downloadBytes(buildSimpleTextPdf(lines), stamp(prefix), 'application/pdf')
  }
}

export function tableToDocumentSpec({ title, client, lang, header, rows }) {
  return {
    title: title || 'Weissman export',
    subtitle: 'Live Command Center export',
    org: 'Weissman Cybersecurity',
    client: client || '',
    classification: 'Confidential',
    lang: lang || 'en',
    sections: [
      {
        title: 'Data',
        blocks: [
          {
            type: 'table',
            columns: (header || []).map((t) => ({ title: t, weight: 1, style: '' })),
            rows: Array.isArray(rows) ? rows.map((r) => (Array.isArray(r) ? r.map((c) => String(c ?? '')) : [])) : [],
          },
        ],
      },
    ],
  }
}
