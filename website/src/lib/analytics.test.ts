/** @vitest-environment jsdom */
import { describe, expect, it } from 'vitest'
import { track } from './analytics'

describe('analytics adapter', () => {
  it('dispatches weissman:analytics on window and does not send data off-origin', () => {
    const received: Array<{ event: string; payload: Record<string, unknown> }> = []
    const onEvent = (e: Event) => {
      const detail = (e as CustomEvent).detail as { event: string; payload: Record<string, unknown> }
      received.push({ event: detail.event, payload: detail.payload })
    }
    window.addEventListener('weissman:analytics', onEvent)
    track('demo_cta_click', { placement: 'hero' })
    window.removeEventListener('weissman:analytics', onEvent)
    expect(received).toEqual([{ event: 'demo_cta_click', payload: { placement: 'hero' } }])
  })
})
