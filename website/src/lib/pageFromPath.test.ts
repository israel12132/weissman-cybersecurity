import { describe, expect, it } from 'vitest'
import { products } from '../content/products'
import { resources } from '../content/resources'
import { metrics } from '../content/metrics'

describe('content integrity', () => {
  it('lists seven product modules', () => {
    expect(products).toHaveLength(7)
    for (const p of products) {
      expect(p.href.startsWith('/platform/')).toBe(true)
      expect(p.outcomes).toHaveLength(3)
    }
  })

  it('does not invent empty resource categories as fake papers', () => {
    expect(resources.every((r) => r.href.length > 0)).toBe(true)
  })

  it('keeps engine counts honest', () => {
    expect(metrics.productionEngines.value).toBe(563)
    expect(metrics.liveProbes.value).toBe(303)
    expect(metrics.slaUptime.value).toBe('99.95%')
  })
})
