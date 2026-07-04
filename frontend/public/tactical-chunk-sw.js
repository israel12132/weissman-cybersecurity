/**
 * Tactical chunk cache service worker — stale-while-revalidate for hashed assets.
 */
const CACHE = 'weissman-tactical-v1'
const ASSET_RE = /\/command-center\/assets\/[a-zA-Z0-9_.-]+\.(js|css|wasm)$/

self.addEventListener('install', (event) => {
  self.skipWaiting()
  event.waitUntil(caches.open(CACHE))
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))),
    ).then(() => self.clients.claim()),
  )
})

async function cacheFirst(request) {
  const cache = await caches.open(CACHE)
  const hit = await cache.match(request)
  if (hit) {
    void fetch(request).then((res) => {
      if (res.ok) cache.put(request, res.clone())
    }).catch(() => {})
    return hit
  }
  const res = await fetch(request)
  if (res.ok) cache.put(request, res.clone())
  return res
}

self.addEventListener('fetch', (event) => {
  const { request } = event
  if (request.method !== 'GET') return
  const url = new URL(request.url)
  if (!ASSET_RE.test(url.pathname)) return
  event.respondWith(cacheFirst(request))
})

self.addEventListener('message', (event) => {
  const data = event.data
  if (!data || data.type !== 'PREFETCH_CHUNKS') return
  const urls = Array.isArray(data.urls) ? data.urls : []
  event.waitUntil(
    caches.open(CACHE).then(async (cache) => {
      for (const path of urls) {
        try {
          const res = await fetch(path, { credentials: 'same-origin' })
          if (res.ok) await cache.put(path, res.clone())
        } catch { /* ignore */ }
      }
    }),
  )
})
