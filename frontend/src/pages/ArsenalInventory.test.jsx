import { describe, it, expect } from 'vitest'
import { matchesQuery, filterEngines } from './ArsenalInventory.jsx'

const ENGINES = [
  { id: 'graphql_attack', category: 'Web / API', techniques: ['T1190'] },
  { id: 'aws_attack', category: 'Cloud / Infra', techniques: [] },
  { id: 'apt28_techniques', category: 'APT / Top-Tier', techniques: ['T1566'] },
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
})
