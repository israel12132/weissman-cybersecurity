import { describe, expect, it } from 'vitest'
import {
  intensityFromDepth,
  productionEngineIds,
  resolveClientScanTarget,
} from './warPower'

describe('warPower helpers', () => {
  it('maps depth to Arsenal intensity', () => {
    expect(intensityFromDepth(1)).toBe('light')
    expect(intensityFromDepth(2)).toBe('normal')
    expect(intensityFromDepth(3)).toBe('aggressive')
    expect(intensityFromDepth(99)).toBe('aggressive')
  })

  it('resolves JSON-string domains to https targets', () => {
    expect(resolveClientScanTarget({ domains: '["https://www.augury.com"]' })).toBe(
      'https://www.augury.com',
    )
    expect(resolveClientScanTarget({ domains: 'augury.com' })).toBe('https://augury.com')
    expect(resolveClientScanTarget({ domains: [] })).toBe('')
  })

  it('reads production ids from live /api/engines/production shapes', () => {
    expect(productionEngineIds({ production: ['osint', 'asm'] })).toEqual(['osint', 'asm'])
    expect(productionEngineIds({ production: [{ id: 'pki_tls' }] })).toEqual(['pki_tls'])
  })
})
