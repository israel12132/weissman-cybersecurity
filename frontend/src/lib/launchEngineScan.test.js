import { describe, it, expect, vi } from 'vitest'
vi.mock('./apiBase.js', () => ({
  apiFetch: vi.fn(async () => ({ ok: true, json: async () => ({ job_id: '1' }) })),
}))
import { launchEngineScan } from './launchEngineScan.js'
describe('launchEngineScan', () => {
  it('posts scan', async () => {
    const r = await launchEngineScan({ engineId: 'osint', clientId: 1, target: 'https://x.test' })
    expect(r.ok).toBe(true)
  })
})