import { describe, it, expect, vi } from 'vitest'
vi.mock('./apiBase.js', () => ({
  apiFetch: vi.fn(async () => ({ ok: true, json: async () => ({ job_id: '1' }) })),
}))
const posted = []
vi.mock('./scanIntakeRetry.js', () => ({
  apiFetchScanIntake: vi.fn(async (_url, opts) => {
    posted.push(JSON.parse(opts.body))
    return { ok: true, status: 202, json: async () => ({ job_id: '1' }) }
  }),
}))
import { launchEngineScan, postEngineScan } from './launchEngineScan.js'

describe('launchEngineScan', () => {
  it('posts scan', async () => {
    posted.length = 0
    const r = await launchEngineScan({ engineId: 'osint', clientId: 1, target: 'https://x.test' })
    expect(r.ok).toBe(true)
    expect(posted[0].target).toBe('https://x.test')
  })

  it('scoped user auto-sends assigned client domain', async () => {
    posted.length = 0
    const r = await launchEngineScan({
      engineId: 'osint',
      clientId: 7,
      target: '',
      client: { id: 7, domains: '["acme.example"]' },
      clientScopeLocked: true,
      integrations: {},
    })
    expect(r.ok).toBe(true)
    expect(posted[0].client_id).toBe(7)
    expect(posted[0].target).toBe('https://acme.example')
  })

  it('targetless engines enqueue without a URL', async () => {
    posted.length = 0
    const r = await launchEngineScan({
      engineId: 'aws_attack',
      clientId: 1,
      target: '',
      integrations: {},
    })
    expect(r.ok).toBe(true)
    expect(posted[0].target).toBeUndefined()
  })

  it('postEngineScan scoped auto-binds assigned domain', async () => {
    posted.length = 0
    const r = await postEngineScan(
      { engine: 'osint', client_id: 7 },
      {},
      {
        client: { id: 7, domains: '["acme.example"]' },
        clientScopeLocked: true,
      },
    )
    expect(r.ok).toBe(true)
    expect(posted[0].target).toBe('https://acme.example')
  })

  it('postEngineScan targetless does not 400-shape a blank target', async () => {
    posted.length = 0
    const r = await postEngineScan(
      { engine: 'cloud_posture', client_id: 1, target: '' },
      {},
    )
    expect(r.ok).toBe(true)
    expect(posted[0].target).toBeUndefined()
  })
})