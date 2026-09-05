import { describe, it, expect } from 'vitest'
import {
  clientPrimaryTargetUrl,
  resolveClient,
  engineRunsWithoutTarget,
  engineRequiresTarget,
  resolveEnqueueTarget,
} from './clientTarget.js'
import { TARGETLESS_ENGINE_IDS } from './enginesRegistry.js'

const scopedClient = { id: 7, name: 'Acme', domains: '["acme.example"]' }

describe('clientTarget', () => {
  it('builds https URL', () => {
    expect(clientPrimaryTargetUrl({ domains: '["example.com"]' })).toBe('https://example.com')
  })

  it('resolveClient', () => {
    expect(resolveClient('1', [{ id: 1 }])).toMatchObject({ id: 1 })
  })

  it('targetless engines match the registry contract', () => {
    expect(engineRunsWithoutTarget('zero_day_radar')).toBe(true)
    expect(engineRequiresTarget('aws_attack')).toBe(false)
    expect(engineRequiresTarget('osint')).toBe(true)
    expect(engineRequiresTarget('asm')).toBe(true)
    expect(engineRequiresTarget('k8s_container')).toBe(false)
    for (const id of TARGETLESS_ENGINE_IDS) {
      expect(engineRequiresTarget(id)).toBe(false)
    }
  })

  it('scoped user auto-binds assigned domain for target-required engines', () => {
    expect(
      resolveEnqueueTarget({
        engineId: 'osint',
        target: '',
        client: scopedClient,
        clientScopeLocked: true,
      }),
    ).toBe('https://acme.example')
  })

  it('targetless engines do not require a typed URL', () => {
    expect(
      resolveEnqueueTarget({
        engineId: 'aws_attack',
        target: '',
        client: null,
        clientScopeLocked: false,
      }),
    ).toBe('')
  })

  it('typed target wins over assigned domain', () => {
    expect(
      resolveEnqueueTarget({
        engineId: 'osint',
        target: 'https://app.acme.example',
        client: scopedClient,
        clientScopeLocked: true,
      }),
    ).toBe('https://app.acme.example')
  })

  it('unknown engines fail closed (require a target)', () => {
    expect(engineRequiresTarget('not_a_real_engine')).toBe(true)
  })
})
