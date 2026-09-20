import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  apiFetch,
  isMaintenanceResponse,
  setMaintenanceCallback,
  getMaintenanceCallback,
} from './apiBase.js'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SW_PATH = path.resolve(HERE, '../../public/tactical-chunk-sw.js')

function res(status, { headers = {}, body, contentType = 'application/json' } = {}) {
  const h = new Headers({ ...(body !== undefined ? { 'content-type': contentType } : {}), ...headers })
  const text = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body)
  return new Response(text, { status, headers: h })
}

const branded = { 'x-weissman-maintenance': '1', 'retry-after': '30' }

describe('isMaintenanceResponse truth table', () => {
  it.each([
    // [status, header present, body, expected]
    [503, true, undefined, true],
    [502, true, undefined, true],
    [504, true, undefined, true],
    [503, false, { status: 'maintenance', code: 503 }, true], // dist/api.json shape
    [503, false, { error: 'maintenance' }, true], // legacy body marker
    [502, false, { error: 'maintenance' }, true],
    [503, false, { ok: false, error: 'smtp_unconfigured' }, false], // legitimate upstream 503
    [503, false, undefined, false], // bare gateway 503, no marker
    [503, false, null, false],
    [503, false, 'maintenance', false], // body must be an object
    [500, true, { error: 'maintenance' }, false], // wrong status even with both markers
    [200, true, { error: 'maintenance' }, false],
    [429, true, undefined, false],
    [404, false, { status: 'maintenance' }, false],
  ])('status %s · header %s · body %j → %s', (status, header, body, expected) => {
    const r = res(status, { headers: header ? branded : {} })
    expect(isMaintenanceResponse(r, body)).toBe(expected)
  })

  it('tolerates plain objects without headers and nullish input', () => {
    expect(isMaintenanceResponse({ status: 503 }, { status: 'maintenance' })).toBe(true)
    expect(isMaintenanceResponse({ status: 503 })).toBe(false)
    expect(isMaintenanceResponse(null)).toBe(false)
    expect(isMaintenanceResponse(undefined, { error: 'maintenance' })).toBe(false)
  })

  it('treats a throwing headers.get as "no header"', () => {
    const r = {
      status: 503,
      headers: {
        get() {
          throw new Error('boom')
        },
      },
    }
    expect(isMaintenanceResponse(r)).toBe(false)
    expect(isMaintenanceResponse(r, { error: 'maintenance' })).toBe(true)
  })
})

describe('lib/apiBase apiFetch → maintenance callback', () => {
  const fetchMock = vi.fn()
  const cb = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    cb.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    setMaintenanceCallback(cb)
  })
  afterEach(() => {
    setMaintenanceCallback(null)
    vi.unstubAllGlobals()
  })

  it('registry round-trips', () => {
    expect(getMaintenanceCallback()).toBe(cb)
    setMaintenanceCallback(null)
    expect(getMaintenanceCallback()).toBeNull()
  })

  it('fires { status, retryAfter } on a header-branded 503 and returns the response unchanged', async () => {
    const r = res(503, { headers: branded, body: { status: 'maintenance' } })
    fetchMock.mockResolvedValueOnce(r)
    const out = await apiFetch('/api/findings')
    expect(out).toBe(r)
    expect(out.status).toBe(503)
    expect(cb).toHaveBeenCalledTimes(1)
    expect(cb).toHaveBeenCalledWith({ status: 503, retryAfter: 30 })
    // The body is still readable by the caller after detection.
    await expect(out.json()).resolves.toEqual({ status: 'maintenance' })
  })

  it('fires on a body-only marker (no header) for 502', async () => {
    fetchMock.mockResolvedValueOnce(res(502, { body: { error: 'maintenance' } }))
    await apiFetch('/api/x')
    expect(cb).toHaveBeenCalledWith({ status: 502, retryAfter: 60 })
  })

  it('does NOT fire on a legitimate upstream 503 without markers', async () => {
    fetchMock.mockResolvedValueOnce(res(503, { body: { ok: false, error: 'smtp_unconfigured' } }))
    const out = await apiFetch('/api/public/demo-request', { method: 'POST' })
    expect(out.status).toBe(503)
    expect(cb).not.toHaveBeenCalled()
  })

  it('does NOT fire on an HTML 502 from a non-branded proxy', async () => {
    fetchMock.mockResolvedValueOnce(res(502, { body: '<html>Bad Gateway</html>', contentType: 'text/html' }))
    await apiFetch('/api/x')
    expect(cb).not.toHaveBeenCalled()
  })

  it('does NOT fire on 200 / 429 / 500 even when the header is present', async () => {
    for (const status of [200, 429, 500]) {
      fetchMock.mockResolvedValueOnce(res(status, { headers: branded, body: { error: 'maintenance' } }))
      await apiFetch('/api/x')
    }
    expect(cb).not.toHaveBeenCalled()
  })

  it('does nothing when no callback is registered', async () => {
    setMaintenanceCallback(null)
    fetchMock.mockResolvedValueOnce(res(503, { headers: branded }))
    await expect(apiFetch('/api/x')).resolves.toMatchObject({ status: 503 })
  })

  it('a throwing callback never changes the returned response', async () => {
    cb.mockImplementation(() => {
      throw new Error('ui exploded')
    })
    fetchMock.mockResolvedValueOnce(res(504, { headers: branded }))
    await expect(apiFetch('/api/x')).resolves.toMatchObject({ status: 504 })
    expect(cb).toHaveBeenCalledTimes(1)
  })
})

describe('service worker (public/tactical-chunk-sw.js)', () => {
  const src = readFileSync(SW_PATH, 'utf8')

  it('still parses (node --check)', () => {
    expect(() => execFileSync(process.execPath, ['--check', SW_PATH], { stdio: 'pipe' })).not.toThrow()
  })

  it('precaches offline.html relative to the scope and bumped the cache name', () => {
    expect(src).toContain("const CACHE = 'weissman-tactical-v4'")
    expect(src).toContain('const offlineKey = () => `${self.registration.scope}offline.html`')
    expect(src).toMatch(/\[self\.registration\.scope, shellKey\(\), offlineKey\(\)\]\.map/)
    expect(src).toContain('Promise.allSettled')
  })

  it('navigation fallback order: shell → offline.html (503 + maintenance headers) → inline string', () => {
    const shellIdx = src.indexOf('cache.match(shellKey())')
    const offlineIdx = src.indexOf('cache.match(offlineKey())')
    const inlineIdx = src.indexOf('new Response(OFFLINE_HTML')
    expect(shellIdx).toBeGreaterThan(-1)
    expect(offlineIdx).toBeGreaterThan(shellIdx)
    expect(inlineIdx).toBeGreaterThan(offlineIdx)
    expect(src).toContain("'X-Weissman-Maintenance': '1'")
    expect(src).toContain("'Retry-After': '30'")
    expect(src).toContain('new Response(offline.body, { status: 503, headers: MAINTENANCE_HEADERS })')
  })
})
