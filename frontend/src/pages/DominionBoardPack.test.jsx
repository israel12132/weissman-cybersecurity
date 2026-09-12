import { describe, it, expect } from 'vitest'
import { filterPackFindings, isLeakFinding } from './DominionBoardPack.jsx'

describe('DominionBoardPack helpers', () => {
  it('classifies leak engines only', () => {
    expect(isLeakFinding({ source: 'darkweb_intel' })).toBe(true)
    expect(isLeakFinding({ source: 'jwt_attack' })).toBe(false)
    expect(isLeakFinding({ type: 'leak_hunter' })).toBe(true)
  })

  it('filters by title/source/severity without fabricating rows', () => {
    const rows = [
      { title: 'Exposed .env', severity: 'critical', source: 'leak_hunter', status: 'OPEN' },
      { title: 'Weak JWT', severity: 'high', source: 'jwt_attack', status: 'OPEN' },
    ]
    expect(filterPackFindings(rows, 'jwt')).toHaveLength(1)
    expect(filterPackFindings(rows, '')).toHaveLength(2)
    expect(filterPackFindings(null, 'x')).toEqual([])
  })
})
