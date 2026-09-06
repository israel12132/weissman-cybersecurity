import { describe, it, expect } from 'vitest'
import {
  isCorroborated,
  boostColor,
  planesLabel,
  clustersCsv,
  BOOST_CROSS,
  BOOST_MULTI,
  BOOST_NONE,
} from './clusterCorroboration.js'

describe('clusterCorroboration', () => {
  it('treats only non-none boosts as corroborated', () => {
    expect(isCorroborated(BOOST_CROSS)).toBe(true)
    expect(isCorroborated(BOOST_MULTI)).toBe(true)
    expect(isCorroborated(BOOST_NONE)).toBe(false)
    expect(isCorroborated('')).toBe(false)
    expect(isCorroborated(null)).toBe(false)
  })

  it('uses adrenaline red for cross-plane and amber for multi-engine', () => {
    expect(boostColor(BOOST_CROSS)).toBe('#f43f5e')
    expect(boostColor(BOOST_MULTI)).toBe('#f59e0b')
  })

  it('labels planes including the network+agent fusion case', () => {
    expect(planesLabel(['network', 'agent'])).toBe('network+agent')
    expect(planesLabel(['agent'])).toBe('agent')
    expect(planesLabel(['network'])).toBe('network')
    expect(planesLabel([])).toBe('—')
  })

  it('flattens live cluster rows for CSV export', () => {
    const rows = clustersCsv([
      {
        id: 7,
        max_severity: 'critical',
        watermark_severity: 'critical',
        native_severity: 'medium',
        corroboration_boost: BOOST_CROSS,
        engine_planes: ['network', 'agent'],
        engines: ['asm', 'process_inventory'],
        member_count: 2,
        target: 'https://app.example.com/login',
        vuln_signature: 'sqli',
        cwe: 'CWE-89',
        status: 'OPEN',
        kev_listed: true,
        last_seen_at: '2026-08-27T00:00:00Z',
      },
    ])
    expect(rows).toHaveLength(1)
    expect(rows[0][0]).toBe(7)
    expect(rows[0][1]).toBe('critical')
    expect(rows[0][2]).toBe('critical')
    expect(rows[0][4]).toBe(BOOST_CROSS)
    expect(rows[0][5]).toBe('network|agent')
    expect(rows[0][12]).toBe('1')
  })
})
