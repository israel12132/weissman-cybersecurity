import { describe, it, expect } from 'vitest'
import { matchesQuery, filterEngines, batchEngineIds, formatEta, excludeAliases } from './ArsenalInventory.jsx'

const ENGINES = [
  { id: 'graphql_attack', category: 'Web / API', techniques: ['T1190'], kind: 'real_probe' },
  { id: 'aws_attack', category: 'Cloud / Infra', techniques: [], kind: 'real_probe' },
  { id: 'apt28_techniques', category: 'APT / Top-Tier', techniques: ['T1566'], kind: 'real_probe' },
]

describe('ArsenalInventory helpers', () => {
  describe('matchesQuery', () => {
    it('matches on id, category, and techniques; empty query matches all', () => {
      expect(matchesQuery(ENGINES[0], 'graphql')).toBe(true)
      expect(matchesQuery(ENGINES[0], 'web')).toBe(true)      // category
      expect(matchesQuery(ENGINES[0], 't1190')).toBe(true)    // technique
      expect(matchesQuery(ENGINES[0], '')).toBe(true)
      expect(matchesQuery(ENGINES[0], 'aws')).toBe(false)
    })
  })

  describe('filterEngines', () => {
    it('filters by free-text query', () => {
      expect(filterEngines(ENGINES, 'attack').map((e) => e.id)).toEqual(['graphql_attack', 'aws_attack'])
    })
    it('filters by exact category', () => {
      expect(filterEngines(ENGINES, '', 'Cloud / Infra').map((e) => e.id)).toEqual(['aws_attack'])
    })
    it('combines query and category', () => {
      expect(filterEngines(ENGINES, 'techniques', 'APT / Top-Tier').map((e) => e.id)).toEqual(['apt28_techniques'])
    })
    it('is robust to non-array input', () => {
      expect(filterEngines(null, 'x')).toEqual([])
      expect(filterEngines(undefined, '')).toEqual([])
    })
  })

  describe('batchEngineIds', () => {
    it('extracts distinct engine ids, capped', () => {
      const list = [{ id: 'a' }, { id: 'b' }, { id: 'a' }, { id: '' }, {}, { id: 'c' }]
      expect(batchEngineIds(list)).toEqual(['a', 'b', 'c'])
      expect(batchEngineIds(list, 2)).toEqual(['a', 'b'])
      expect(batchEngineIds(null)).toEqual([])
    })
  })

  describe('excludeAliases', () => {
    it('drops alias-kind engines, keeps distinct', () => {
      const list = [
        { id: 'a', kind: 'real_probe' },
        { id: 'b', kind: 'alias', canonical: 'a' },
        { id: 'c', kind: 'agent_required' },
      ]
      expect(excludeAliases(list).map((e) => e.id)).toEqual(['a', 'c'])
      expect(excludeAliases(null)).toEqual([])
    })
  })

  describe('formatEta', () => {
    it('humanises milliseconds', () => {
      expect(formatEta(4200)).toBe('4s')
      expect(formatEta(60000)).toBe('1m')
      expect(formatEta(95000)).toBe('1m 35s')
      expect(formatEta(0)).toBe('0s')
      expect(formatEta('nope')).toBe('0s')
    })
  })
})
