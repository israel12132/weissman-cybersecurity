/** First scope URL for engine targets (https:// + primary domain). */
export function clientPrimaryTargetUrl(client) {
  if (!client) return ''
  let list = []
  const raw = client.domains
  if (Array.isArray(raw)) {
    list = raw.map(String).filter(Boolean)
  } else if (typeof raw === 'string') {
    try {
      const arr = JSON.parse(raw)
      list = Array.isArray(arr) ? arr.map(String).filter(Boolean) : []
    } catch {
      list = []
    }
  }
  const first = list[0] || ''
  if (!first) return ''
  return first.startsWith('http') ? first.trim() : `https://${first.replace(/^\/+/, '')}`
}

/** Engines that do not need a URL target (tenant/global job). */
export function engineRunsWithoutTarget(engineId) {
  return engineId === 'zero_day_radar'
}
