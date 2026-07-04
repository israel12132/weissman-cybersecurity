import { describe, it, expect, vi } from 'vitest'
vi.mock('./apiBase.js', () => ({
  apiFetch: vi.fn(async () => ({ ok: true, json: async () => ({ job_id: '9' }) })),
}))
import { launchEngineScan, postEngineScan, fetchClientIntegrations } from './launchEngineScan.js'

describe('launchEngineScan deep', () => {
  it('fetchClientIntegrations', async () => {
    const data = await fetchClientIntegrations(1)
    expect(data.job_id).toBe('9')
  })

  it('postEngineScan', async () => {
    const r = await postEngineScan({ engine: 'osint', client_id: 1 })
    expect(r.ok).toBe(true)
  })

  it('launch with integrations', async () => {
    const r = await launchEngineScan({
      engineId: 'osint',
      clientId: 1,
      target: 'https://example.com',
      integrations: { github_token: 'x' },
    })
    expect(r.ok).toBe(true)
  })
})
