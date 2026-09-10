import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { normalizeDirectory, FALLBACK_TENANT_SLUG } from './useTenantDirectory'

/**
 * `normalizeDirectory` is the whole trust boundary between the public tenant-directory endpoint and
 * a `<select>` a user has to log in through. Every shape below either rendered an unusable option or
 * would have left the picker with no way forward, so each is pinned here.
 */
describe('normalizeDirectory', () => {
  it('accepts a listed directory and keeps slug order', () => {
    const state = normalizeDirectory({
      ok: true,
      listing: 'enumerated',
      tenants: [
        { slug: 'default', name: 'Weissman HQ' },
        { slug: 'acme-energy', name: 'Acme Energy' },
      ],
      default_slug: 'default',
      allow_custom: false,
    })
    expect(state.status).toBe('ready')
    expect(state.tenants.map((tenant) => tenant.slug)).toEqual(['default', 'acme-energy'])
    expect(state.tenants[0].name).toBe('Weissman HQ')
    expect(state.defaultSlug).toBe('default')
    expect(state.allowCustom).toBe(false)
  })

  it('treats a restricted listing as manual-entry-only', () => {
    const state = normalizeDirectory({
      ok: true,
      listing: 'restricted',
      tenants: [],
      default_slug: 'default',
      allow_custom: true,
    })
    expect(state.status).toBe('restricted')
    expect(state.tenants).toEqual([])
    expect(state.allowCustom).toBe(true)
  })

  it('treats an enumerated-but-empty listing as restricted, so the user can still type a slug', () => {
    const state = normalizeDirectory({ ok: true, listing: 'enumerated', tenants: [] })
    expect(state.status).toBe('restricted')
    expect(state.allowCustom).toBe(true)
  })

  it('keeps allow_custom from the server when the list may be truncated', () => {
    const state = normalizeDirectory({
      listing: 'enumerated',
      tenants: [{ slug: 'default', name: 'Default' }],
      allow_custom: true,
    })
    expect(state.status).toBe('ready')
    expect(state.allowCustom).toBe(true)
  })

  it('drops entries that could never resolve to a tenant', () => {
    const state = normalizeDirectory({
      listing: 'enumerated',
      tenants: [
        { slug: 'default', name: 'Default' },
        { slug: '', name: 'blank' },
        { slug: '   ', name: 'whitespace' },
        { slug: 'has space', name: 'space' },
        { slug: 'UPPER', name: 'uppercase is lowercased' },
        { slug: '-leading-dash', name: 'illegal start' },
        { slug: 42, name: 'not a string' },
        null,
        { name: 'no slug at all' },
      ],
    })
    expect(state.tenants.map((tenant) => tenant.slug)).toEqual(['default', 'upper'])
  })

  it('de-duplicates slugs so React keys stay unique', () => {
    const state = normalizeDirectory({
      listing: 'enumerated',
      tenants: [
        { slug: 'default', name: 'First' },
        { slug: 'default', name: 'Duplicate' },
      ],
    })
    expect(state.tenants).toHaveLength(1)
    expect(state.tenants[0].name).toBe('First')
  })

  it('falls back to the slug when a display name is missing or blank', () => {
    const state = normalizeDirectory({
      listing: 'enumerated',
      tenants: [{ slug: 'acme', name: '   ' }, { slug: 'beta' }],
    })
    expect(state.tenants[0].name).toBe('acme')
    expect(state.tenants[1].name).toBe('beta')
  })

  it('falls back to the documented default slug when the server sends none', () => {
    const state = normalizeDirectory({ listing: 'enumerated', tenants: [{ slug: 'only' }] })
    expect(state.defaultSlug).toBe(FALLBACK_TENANT_SLUG)
  })

  it('survives a completely unexpected payload', () => {
    expect(normalizeDirectory(null).status).toBe('restricted')
    expect(normalizeDirectory({ tenants: 'nope' }).status).toBe('restricted')
    expect(normalizeDirectory(undefined).allowCustom).toBe(true)
  })
})

describe('useTenantDirectory transport', () => {
  let useTenantDirectory
  let renderHook
  let waitFor
  let cleanup

  beforeEach(async () => {
    ;({ renderHook, waitFor, cleanup } = await import('@testing-library/react'))
    useTenantDirectory = (await import('./useTenantDirectory')).default
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('reports ready with the parsed workspaces on a 200', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          ok: true,
          listing: 'enumerated',
          tenants: [{ slug: 'default', name: 'Weissman HQ' }],
          default_slug: 'default',
        }),
      }),
    )
    const { result } = renderHook(() => useTenantDirectory())
    await waitFor(() => expect(result.current.status).toBe('ready'))
    expect(result.current.tenants).toEqual([{ slug: 'default', name: 'Weissman HQ' }])
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/auth/tenant-directory'),
      expect.objectContaining({ method: 'GET' }),
    )
  })

  it('reports error (never a silent empty list) when the endpoint fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
        json: async () => ({ ok: false, default_slug: 'default' }),
      }),
    )
    const { result } = renderHook(() => useTenantDirectory())
    await waitFor(() => expect(result.current.status).toBe('error'))
    expect(result.current.allowCustom).toBe(true)
    expect(result.current.defaultSlug).toBe('default')
  })

  it('reports error when the request cannot be made at all', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))
    const { result } = renderHook(() => useTenantDirectory())
    await waitFor(() => expect(result.current.status).toBe('error'))
    expect(result.current.tenants).toEqual([])
    expect(result.current.allowCustom).toBe(true)
  })

  it('re-requests on reload', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}) })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ listing: 'enumerated', tenants: [{ slug: 'default' }] }),
      })
    vi.stubGlobal('fetch', fetchMock)
    const { result } = renderHook(() => useTenantDirectory())
    await waitFor(() => expect(result.current.status).toBe('error'))
    result.current.reload()
    await waitFor(() => expect(result.current.status).toBe('ready'))
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})
