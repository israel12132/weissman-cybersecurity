import { describe, it, expect, vi } from 'vitest'
vi.mock('./apiBase.js', () => ({
  apiFetch: vi.fn(async () => ({ ok: true, json: async () => ([{ id: 42 }]) })),
}))
import { fetchFirstTenantClientId } from './aliasClient.js'

describe('aliasClient deep', () => {
  it('fetchFirstTenantClientId', async () => {
    const id = await fetchFirstTenantClientId()
    expect(id).toBe(42)
  })
})
