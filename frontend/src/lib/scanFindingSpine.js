/**
 * CSV + filter helpers for the live scan-finding spine (GET /api/scan-finding-spine).
 */

export const SPINE_CSV_HEADER = [
  'row_kind',
  'id',
  'status_or_source',
  'findings',
  'evidence',
  'proven',
  'unverified_critical',
  'detail',
]

export function spineCsvRows(data) {
  const rows = []
  for (const g of data?.gaps || []) {
    rows.push([
      'gap',
      g.id || '',
      g.severity || '',
      g.count ?? '',
      '',
      '',
      '',
      g.detail || '',
    ])
  }
  for (const e of data?.engines || []) {
    rows.push([
      'engine',
      e.source || '',
      e.reality_kind || '',
      e.findings ?? 0,
      e.evidence ?? 0,
      e.proven ?? 0,
      e.unverified_critical ?? 0,
      '',
    ])
  }
  for (const j of data?.scans || []) {
    rows.push([
      'scan',
      j.id || '',
      j.status || '',
      '',
      '',
      '',
      '',
      `${j.kind || ''} ${j.target || ''}`.trim(),
    ])
  }
  return rows
}

export function filterEngines(engines, query) {
  const q = String(query || '').trim().toLowerCase()
  if (!q) return Array.isArray(engines) ? engines : []
  return (engines || []).filter((e) => {
    const hay = `${e.source || ''} ${e.reality_kind || ''}`.toLowerCase()
    return hay.includes(q)
  })
}

export function filterGaps(gaps, query) {
  const q = String(query || '').trim().toLowerCase()
  if (!q) return Array.isArray(gaps) ? gaps : []
  return (gaps || []).filter((g) => {
    const hay = `${g.id || ''} ${g.severity || ''} ${g.detail || ''}`.toLowerCase()
    return hay.includes(q)
  })
}
