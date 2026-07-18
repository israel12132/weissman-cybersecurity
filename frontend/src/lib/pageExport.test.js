import { describe, it, expect } from 'vitest'
import { rowMatchesQuery } from './pageExport'

describe('rowMatchesQuery', () => {
  it('matches everything when the query is empty or whitespace', () => {
    expect(rowMatchesQuery('', ['anything'])).toBe(true)
    expect(rowMatchesQuery('   ', ['anything'])).toBe(true)
  })

  it('is case-insensitive and matches across any field', () => {
    expect(rowMatchesQuery('T1059', ['exec', 'T1059', 12])).toBe(true)
    expect(rowMatchesQuery('t1059', ['exec', 'T1059', 12])).toBe(true)
    expect(rowMatchesQuery('EXEC', ['exec', 'T1059'])).toBe(true)
  })

  it('matches numeric fields coerced to string', () => {
    expect(rowMatchesQuery('42', ['host', 42])).toBe(true)
  })

  it('returns false when no field contains the query', () => {
    expect(rowMatchesQuery('nope', ['exec', 'T1059', 12])).toBe(false)
  })

  it('tolerates null/undefined fields without throwing', () => {
    expect(rowMatchesQuery('x', [null, undefined, 'xyz'])).toBe(true)
    expect(rowMatchesQuery('x', [null, undefined])).toBe(false)
  })
})
