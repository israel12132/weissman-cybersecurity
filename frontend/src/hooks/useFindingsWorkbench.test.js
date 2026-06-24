import { describe, it, expect } from 'vitest'
import { useFindingsWorkbench } from './useFindingsWorkbench'
import { renderHook, act } from '@testing-library/react'

describe('useFindingsWorkbench', () => {
  const sample = [
    { severity: 'critical', title: 'Alpha JWT', description: 'alg none' },
    { severity: 'low', title: 'Beta info', description: 'minor' },
  ]

  it('filters by severity', () => {
    const { result } = renderHook(() => useFindingsWorkbench(sample))
    act(() => result.current.setSeverityFilter('critical'))
    expect(result.current.filteredFindings).toHaveLength(1)
    expect(result.current.filteredFindings[0].title).toBe('Alpha JWT')
  })

  it('filters by search query', () => {
    const { result } = renderHook(() => useFindingsWorkbench(sample))
    act(() => result.current.setSearchQuery('beta'))
    expect(result.current.filteredFindings).toHaveLength(1)
  })

  it('counts severities', () => {
    const { result } = renderHook(() => useFindingsWorkbench(sample))
    expect(result.current.counts.critical).toBe(1)
    expect(result.current.counts.low).toBe(1)
  })
})
