import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'

const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('./apiBase', () => ({ apiFetch }))

import { invalidateEngineCapabilitiesCache, useEngineCapabilities } from './useEngineCapabilities.js'

describe('useEngineCapabilities', () => {
  beforeEach(() => {
    invalidateEngineCapabilitiesCache()
    apiFetch.mockReset()
  })

  it('invalidate noop', () => expect(() => invalidateEngineCapabilitiesCache()).not.toThrow())

  it('does not report 0 engines on first-load unavailability', async () => {
    apiFetch.mockResolvedValue({
      ok: false,
      unavailable: true,
      engines: [],
      total: 0,
      detail: 'store down',
    })
    const { result } = renderHook(() => useEngineCapabilities())
    await waitFor(() => expect(result.current.unavailable).toBe(true))
    expect(result.current.total).toBeNull()
    expect(result.current.remoteDetectionCount).toBeNull()
  })
})
