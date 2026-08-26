import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { Suspense } from 'react'
import { render, screen, waitFor, cleanup } from '@testing-library/react'
import {
  isStaleChunkError,
  lazyWithRetry,
  recoverStaleChunkError,
  reloadOnceForStaleChunk,
  RELOAD_GUARD_KEY,
} from './lazyWithRetry.js'

function Mission() {
  return <div>mission-control</div>
}

describe('lazyWithRetry', () => {
  beforeEach(() => {
    sessionStorage.clear()
    vi.restoreAllMocks()
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('detects browser stale-chunk load errors', () => {
    expect(
      isStaleChunkError(
        new TypeError(
          'error loading dynamically imported module: http://127.0.0.1/command-center/assets/CeoMissionControlTab-BfGwQoxI.js',
        ),
      ),
    ).toBe(true)
    expect(
      isStaleChunkError(new TypeError('Failed to fetch dynamically imported module: http://x/a.js')),
    ).toBe(true)
    expect(isStaleChunkError(new Error('telemetry unavailable'))).toBe(false)
  })

  it('renders after a transient import failure', async () => {
    let n = 0
    const Cmp = lazyWithRetry(() => {
      n += 1
      if (n === 1) return Promise.reject(new TypeError('Failed to fetch dynamically imported module'))
      return Promise.resolve({ default: Mission })
    }, 3)
    render(
      <Suspense fallback={<div>loading</div>}>
        <Cmp />
      </Suspense>,
    )
    expect(await screen.findByText('mission-control', {}, { timeout: 4000 })).toBeInTheDocument()
    expect(n).toBe(2)
  })

  it('cockpit tabs must not use bare React.lazy for hashed chunks', async () => {
    const { readFile } = await import('node:fs/promises')
    const { dirname, join } = await import('node:path')
    const { fileURLToPath } = await import('node:url')
    const src = await readFile(
      join(dirname(fileURLToPath(import.meta.url)), '../components/cockpit/ClientCockpit.jsx'),
      'utf8',
    )
    expect(src).toContain("lazyWithRetry(() => import('./CeoMissionControlTab'))")
    expect(src).not.toMatch(/\blazy\(\(\)\s*=>\s*import\(/)
  })

  it('reloads once when the hashed chunk is gone', async () => {
    const reload = vi.fn()
    vi.stubGlobal('location', { reload, href: 'http://127.0.0.1/command-center/' })
    const Cmp = lazyWithRetry(
      () =>
        Promise.reject(
          new TypeError(
            'error loading dynamically imported module: http://127.0.0.1/command-center/assets/CeoMissionControlTab-BfGwQoxI.js',
          ),
        ),
      1,
    )
    render(
      <Suspense fallback={<div>loading</div>}>
        <Cmp />
      </Suspense>,
    )
    await waitFor(() => expect(reload).toHaveBeenCalledTimes(1))
    expect(sessionStorage.getItem(RELOAD_GUARD_KEY)).toBeTruthy()
    expect(screen.getByText('loading')).toBeInTheDocument()
  })

  it('does not loop-reload inside the guard window', () => {
    const reload = vi.fn()
    vi.stubGlobal('location', { reload, href: 'http://127.0.0.1/command-center/' })
    sessionStorage.setItem(RELOAD_GUARD_KEY, String(Date.now()))
    expect(reloadOnceForStaleChunk()).toBe(false)
    expect(reload).not.toHaveBeenCalled()
    expect(
      recoverStaleChunkError(
        new TypeError('error loading dynamically imported module: http://127.0.0.1/x.js'),
      ),
    ).toBe(false)
  })
})
