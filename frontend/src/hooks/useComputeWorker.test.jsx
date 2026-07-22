import { describe, it, expect, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'
import { useComputeWorker } from './useComputeWorker.js'

afterEach(cleanup)

// jsdom has no Worker, so this exercises the main-thread fallback — the same
// computation the worker would run, verifying the Promise API and correctness.
describe('useComputeWorker (fallback path)', () => {
  it('reports Workers as unsupported in jsdom', () => {
    const { result } = renderHook(() => useComputeWorker())
    expect(result.current.supported).toBe(false)
  })

  it('runs a task and resolves the result', async () => {
    const { result } = renderHook(() => useComputeWorker())
    let out
    await act(async () => {
      out = await result.current.run('computeRiskSummary', [
        { severity: 'critical', status: 'open' },
        { severity: 'medium', status: 'resolved' },
      ])
    })
    expect(out.total).toBe(2)
    expect(out.bySeverity.critical).toBe(1)
  })

  it('rejects an unknown task', async () => {
    const { result } = renderHook(() => useComputeWorker())
    await act(async () => {
      await expect(result.current.run('nope', {})).rejects.toThrow(/Unknown task/)
    })
  })
})
