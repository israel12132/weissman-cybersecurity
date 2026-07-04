import { attachServiceWorker } from './intentPrefetch'

export async function registerTacticalServiceWorker() {
  if (!('serviceWorker' in navigator) || import.meta.env.DEV) return null
  try {
    const reg = await navigator.serviceWorker.register(
      `${import.meta.env.BASE_URL}tactical-chunk-sw.js`,
      { scope: import.meta.env.BASE_URL },
    )
    attachServiceWorker(reg)
    return reg
  } catch (e) {
    if (import.meta.env.DEV) console.warn('[tactical-sw] registration failed', e)
    return null
  }
}
