import { describe, it, expect } from 'vitest'
import { liveCvssLabel } from './liveFindingIntel.js'

describe('liveCvssLabel', () => {
  it('shows a live score and never invents one from severity', () => {
    expect(liveCvssLabel({ cvss_score: 9.8, severity: 'low' })).toBe('9.8')
    expect(liveCvssLabel({ severity: 'critical' })).toBe('—')
    expect(liveCvssLabel({ cvss_score: 0 })).toBe('—')
    expect(liveCvssLabel({})).toBe('—')
  })
})
