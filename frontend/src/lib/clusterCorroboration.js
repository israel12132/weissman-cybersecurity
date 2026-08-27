/**
 * Cluster corroboration display helpers — mirrors
 * `fingerprint_engine::finding_identity::corroborate_cluster_severity`.
 *
 * Live API fields: corroboration_boost, engine_planes, native_severity, max_severity.
 */

export const BOOST_NONE = 'none'
export const BOOST_MULTI = 'multi_engine'
export const BOOST_CROSS = 'cross_plane'

/** @param {string|undefined|null} boost */
export function isCorroborated(boost) {
  return Boolean(boost) && boost !== BOOST_NONE
}

/** Accent colour for a corroboration boost badge. */
export function boostColor(boost) {
  if (boost === BOOST_CROSS) return '#f43f5e'
  if (boost === BOOST_MULTI) return '#f59e0b'
  return '#64748b'
}

/**
 * @param {string|undefined|null} boost
 * @param {(key: string) => string} t
 */
export function boostLabel(boost, t) {
  if (boost === BOOST_CROSS) return t('pages.findingClusters.boost_cross_plane')
  if (boost === BOOST_MULTI) return t('pages.findingClusters.boost_multi_engine')
  return t('pages.findingClusters.boost_none')
}

/** @param {string[]|undefined|null} planes */
export function planesLabel(planes) {
  const set = new Set((planes || []).map((p) => String(p).toLowerCase()).filter(Boolean))
  if (set.has('agent') && set.has('network')) return 'network+agent'
  if (set.has('agent')) return 'agent'
  if (set.has('network')) return 'network'
  return '—'
}

export function clustersCsv(rows) {
  return rows.map((r) => [
    r.id,
    r.max_severity,
    r.native_severity,
    r.corroboration_boost,
    (r.engine_planes || []).join('|'),
    (r.engines || []).join('|'),
    r.member_count,
    r.target,
    r.vuln_signature,
    r.cwe,
    r.status,
    r.kev_listed ? '1' : '0',
    r.last_seen_at,
  ])
}

export const CLUSTERS_CSV_HEADER = [
  'id',
  'max_severity',
  'native_severity',
  'corroboration_boost',
  'engine_planes',
  'engines',
  'member_count',
  'target',
  'vuln_signature',
  'cwe',
  'status',
  'kev_listed',
  'last_seen_at',
]
