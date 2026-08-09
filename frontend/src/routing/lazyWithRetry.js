/**
 * `React.lazy` with transient-failure resilience for code-split route chunks.
 *
 * A route chunk can fail to load for reasons that are recoverable and NOT the component's fault:
 *   • a brief network / edge-proxy blip while dozens of chunks are fetched at once on navigation;
 *   • a chunk that 404s because a new deploy rotated the hashed filenames while an open tab still
 *     references the previous `index.html`.
 *
 * Bare `React.lazy(() => import(...))` surfaces any of these as a permanent "This view crashed"
 * error boundary — a real, user-facing outage for a fault that a single retry (or a reload onto the
 * fresh bundle) would clear. This wrapper:
 *   1. retries the dynamic import a few times with a short linear backoff (handles transient blips);
 *   2. if every attempt still fails, triggers ONE full-page reload so the browser re-fetches
 *      `index.html` + matching chunk hashes (the usual recovery for a stale deploy — note this is
 *      a plain `location.reload()`, so an intermediary/SW holding the previous `index.html` may
 *      still serve it; the guard in step 3 keeps that from looping);
 *   3. guards that reload so it can fire at most once per short window — a genuinely, permanently
 *      unavailable chunk falls through to the error boundary instead of looping the page.
 */
import React from 'react'

const RELOAD_GUARD_KEY = 'weissman:chunk-reload-at'
const RELOAD_MIN_INTERVAL_MS = 10_000
const DEFAULT_ATTEMPTS = 3
const BACKOFF_MS = 250

async function importWithRetry(factory, attempts, backoffMs) {
  let lastErr
  for (let i = 0; i < attempts; i += 1) {
    try {
      return await factory()
    } catch (err) {
      lastErr = err
      if (i < attempts - 1) {
        // Linear backoff (250ms, 500ms, …) — long enough to ride out a transient blip, short
        // enough that the boot spinner does not feel stuck.
        await new Promise((resolve) => setTimeout(resolve, backoffMs * (i + 1)))
      }
    }
  }
  throw lastErr
}

function reloadOnceForStaleChunk() {
  // Only reload if we have not already done so very recently: a permanently-missing chunk must
  // reach the error boundary, not put the page into a reload loop.
  try {
    const last = Number(window.sessionStorage.getItem(RELOAD_GUARD_KEY) || 0)
    if (!Number.isFinite(last) || Date.now() - last > RELOAD_MIN_INTERVAL_MS) {
      window.sessionStorage.setItem(RELOAD_GUARD_KEY, String(Date.now()))
      window.location.reload()
      return true
    }
  } catch {
    // sessionStorage unavailable (private mode / sandboxed) — cannot guard a reload safely,
    // so skip it and let the error propagate.
  }
  return false
}

export function lazyWithRetry(factory, attempts = DEFAULT_ATTEMPTS) {
  return React.lazy(() =>
    importWithRetry(factory, attempts, BACKOFF_MS).catch((err) => {
      if (reloadOnceForStaleChunk()) {
        // Return a never-settling promise so React keeps showing the Suspense fallback until the
        // reload navigates the document away — never a flash of the crash boundary.
        return new Promise(() => {})
      }
      throw err
    }),
  )
}

export default lazyWithRetry
