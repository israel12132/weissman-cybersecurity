import { describe, it, expect } from 'vitest'
import { reasoningFromPayload, emptyGraphCopy } from './semanticLogicHelpers.js'

const t = (k) => k

describe('semanticLogicHelpers', () => {
  it('reads reasoning_text from the live GET envelope', () => {
    expect(reasoningFromPayload({ reasoning_text: 'step 1' })).toBe('step 1')
    expect(reasoningFromPayload({ log: 'legacy' })).toBe('legacy')
    expect(reasoningFromPayload({ ok: false, unavailable: true, reasoning_text: null })).toBe('')
  })

  it('does not treat live fuzz logs as a missing OpenAPI', () => {
    expect(emptyGraphCopy({ logs: [{ id: 1 }], message: 'Live fuzz log present' }, t, 'ns'))
      .toBe('Live fuzz log present')
    expect(emptyGraphCopy({ logs: [{ id: 1 }] }, t, 'ns'))
      .toBe('ns.graph_not_persisted')
    expect(emptyGraphCopy({ logs: [], nodes: [] }, t, 'ns')).toBe('ns.no_openapi')
  })
})
