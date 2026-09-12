import { describe, it, expect, vi, beforeEach } from 'vitest'

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch.js', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import { fetchFirstTenantClientId } from './aliasClient.js'

describe('aliasClient deep', () => {
  beforeEach(() => apiFetch.mockReset())

  it('fetchFirstTenantClientId', async () => {
    apiFetch.mockResolvedValue([{ id: 42 }])
    const id = await fetchFirstTenantClientId()
    expect(id).toBe(42)
  })

  it('does not treat a store-down clients list as an empty tenant', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, clients: [], detail: 'store down' })
    await expect(fetchFirstTenantClientId()).rejects.toMatchObject({ code: 'clients_unavailable' })
  })
})
