export async function registerTacticalServiceWorker() {
  if (!('serviceWorker' in navigator) || import.meta.env.DEV) return null
  try {
    // The service worker is a progressive enhancement (offline app shell). It must
    // NEVER gate first paint. `bootstrapTacticalShell()` awaits this in a Promise.all *before*
    // React mounts, so if `register()` stalls — observed in headless Chromium and on restrictive
    // live hosts where the SW script or its scope is served unexpectedly — the app is stranded on
    // its boot spinner forever (the login form never renders). Cap registration with a timeout so
    // boot always proceeds; the SW attaches whenever it does resolve.
    const reg = await Promise.race([
      navigator.serviceWorker.register(`${import.meta.env.BASE_URL}tactical-chunk-sw.js`, {
        scope: import.meta.env.BASE_URL,
      }),
      new Promise((resolve) => setTimeout(() => resolve(null), 3000)),
    ])
    return reg
  } catch (e) {
    if (import.meta.env.DEV) console.warn('[tactical-sw] registration failed', e)
    return null
  }
}
