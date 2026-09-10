/** Depth 1–3 → engine Arsenal intensity string used by POST /api/command-center/scan. */
export const WAR_POWER_INTENSITY = {
  1: 'light',
  2: 'normal',
  3: 'aggressive',
}

export function intensityFromDepth(depth) {
  const n = Number(depth)
  if (n <= 1) return WAR_POWER_INTENSITY[1]
  if (n >= 3) return WAR_POWER_INTENSITY[3]
  return WAR_POWER_INTENSITY[2]
}

/** First authorized client domain as an https target. Empty if the client has no domains. */
export function resolveClientScanTarget(client) {
  if (!client) return ''
  let raw = client.domains
  if (Array.isArray(raw)) {
    raw = raw[0]
  } else if (typeof raw === 'string') {
    const trimmed = raw.trim()
    if (!trimmed) return ''
    try {
      const parsed = JSON.parse(trimmed)
      raw = Array.isArray(parsed) ? parsed[0] : trimmed
    } catch {
      raw = trimmed.split(/[\s,]+/).filter(Boolean)[0]
    }
  }
  const s = String(raw || '').trim()
  if (!s) return ''
  if (/^https?:\/\//i.test(s)) return s
  return `https://${s}`
}

export function productionEngineIds(payload) {
  const raw = payload?.production
  if (!Array.isArray(raw)) return []
  return raw
    .map((item) => (typeof item === 'string' ? item : item?.id))
    .map((id) => String(id || '').trim())
    .filter(Boolean)
}
