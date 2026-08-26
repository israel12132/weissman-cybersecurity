/**
 * Tactical service worker.
 *  - Hashed build assets (js/css/wasm): cache-first + stale-while-revalidate.
 *  - Navigations: network-first with an offline app-shell fallback, so the
 *    Command Center still boots (from cache) when the network is unavailable.
 *  - PREFETCH_CHUNKS message: warm the cache with predicted route chunks.
 */
const CACHE = 'weissman-tactical-v3'
const ASSET_RE = /\/command-center\/assets\/[a-zA-Z0-9_.-]+\.(js|css|wasm)$/

// The app shell is stored under this stable key and served for any navigation
// when offline. Resolved against the registration scope (e.g. /command-center/).
const shellKey = () => `${self.registration.scope}index.html`

self.addEventListener('install', (event) => {
  self.skipWaiting()
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE)
      // Precache the shell so a first-load-then-offline visit still boots.
      // allSettled: never fail the install if one path 404s in a given deploy.
      await Promise.allSettled(
        [self.registration.scope, shellKey()].map((url) =>
          cache.add(new Request(url, { credentials: 'same-origin' })),
        ),
      )
    })(),
  )
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  )
})

async function cacheFirst(request) {
  const cache = await caches.open(CACHE)
  const hit = await cache.match(request)
  if (hit) {
    void fetch(request)
      .then((res) => {
        if (res.ok) cache.put(request, res.clone())
      })
      .catch(() => {})
    return hit
  }
  const res = await fetch(request)
  if (res.ok) cache.put(request, res.clone())
  return res
}

const OFFLINE_HTML =
  '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1">' +
  '<title>Offline — Weissman Command Center</title></head>' +
  '<body style="font-family:system-ui,sans-serif;background:#020617;color:#e2e8f0;' +
  'display:grid;place-items:center;min-height:100vh;margin:0">' +
  '<div style="text-align:center;max-width:28rem;padding:2rem">' +
  '<h1 style="font-size:1.25rem;margin:0 0 .5rem">You are offline</h1>' +
  '<p style="color:#94a3b8;line-height:1.6;margin:0">The Command Center cannot reach the network. ' +
  'Cached views may still be available — reconnect to resume live operations.</p></div></body></html>'

// Network-first for navigations: fresh HTML when online, cached shell when not.
async function navigationHandler(request) {
  const cache = await caches.open(CACHE)
  try {
    const res = await fetch(request)
    if (res.ok) cache.put(shellKey(), res.clone())
    return res
  } catch {
    const shell = (await cache.match(shellKey())) || (await cache.match(self.registration.scope))
    if (shell) return shell
    return new Response(OFFLINE_HTML, {
      status: 503,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    })
  }
}

self.addEventListener('fetch', (event) => {
  const { request } = event
  if (request.method !== 'GET') return

  // SPA navigations → offline app shell.
  if (request.mode === 'navigate') {
    event.respondWith(navigationHandler(request))
    return
  }

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
        } catch {
          /* ignore */
        }
      }
    }),
  )
})
