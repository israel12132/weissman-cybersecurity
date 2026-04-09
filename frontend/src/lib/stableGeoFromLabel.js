/**
 * Deterministic coordinates from a host/name (no Math.random — avoids map/UI flicker on re-render).
 */
export function stableGeoFromLabel(domainOrName) {
  const s = (domainOrName || '').toString().toLowerCase()
  if (s.includes('juice') || s.includes('owasp')) return [52.52, 13.405]
  if (s.includes('eu') || s.includes('europe')) return [48.8566, 2.3522]
  if (s.includes('asia') || s.includes('jp')) return [35.6762, 139.6503]
  if (s.includes('uk') || s.includes('london')) return [51.5074, -0.1278]
  if (s.includes('il') || s.includes('israel')) return [32.0853, 34.7818]
  let h = 2166136261 >>> 0
  const str = s || 'unknown'
  for (let i = 0; i < str.length; i++) h = Math.imul(h ^ str.charCodeAt(i), 16777619) >>> 0
  const lat = 24 + (h % 10000) / 10000 * 20
  const lng = -125 + ((h >>> 16) % 10000) / 10000 * 65
  return [lat, lng]
}
