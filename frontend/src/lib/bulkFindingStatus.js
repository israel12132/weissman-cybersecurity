/**
 * Bulk finding status updates.
 *
 * The backend exposes only a per-finding endpoint (PATCH /api/findings/:id/status),
 * so a bulk action batches real requests with a concurrency cap and returns an
 * aggregate result. Every mutation is a genuine server call — nothing is faked.
 *
 * @param {Array<string|number>} targets  raw finding ids to update
 * @param {string} status                 new status value
 * @param {object} deps
 * @param {(url: string, opts: object) => Promise<Response>} deps.apiFetch
 * @param {(rawId: string|number, serverStatus: string) => void} [deps.onSuccess]
 * @param {number} [deps.concurrency=5]
 * @returns {Promise<{ ok: number, failed: Array<string|number> }>}
 */
export async function bulkUpdateFindingStatus(targets, status, { apiFetch, onSuccess, concurrency = 5 } = {}) {
  const ids = (targets || []).filter((id) => id != null)
  if (!status || ids.length === 0 || typeof apiFetch !== 'function') {
    return { ok: 0, failed: [] }
  }
  const cap = Math.max(1, concurrency)
  let ok = 0
  const failed = []
  for (let i = 0; i < ids.length; i += cap) {
    const batch = ids.slice(i, i + cap)
    const results = await Promise.all(batch.map(async (rawId) => {
      try {
        const r = await apiFetch(`/api/findings/${rawId}/status`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status }),
        })
        const d = await r.json().catch(() => ({}))
        if (r.ok && d.ok) {
          onSuccess?.(rawId, d.status ?? status)
          return { rawId, ok: true }
        }
        return { rawId, ok: false }
      } catch {
        return { rawId, ok: false }
      }
    }))
    for (const res of results) {
      if (res.ok) ok += 1
      else failed.push(res.rawId)
    }
  }
  return { ok, failed }
}
