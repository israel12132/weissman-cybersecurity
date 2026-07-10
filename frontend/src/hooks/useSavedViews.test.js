import { describe, it, expect } from 'vitest'
import { upsertView, removeView, readViews } from './useSavedViews'

describe('saved views pure helpers', () => {
  it('upserts a view and returns a new array', () => {
    const v1 = upsertView([], 'Critical open', { severityFilter: 'critical' }, 'a')
    expect(v1).toEqual([{ id: 'a', name: 'Critical open', state: { severityFilter: 'critical' } }])
  })

  it('replaces a view with the same (case-insensitive, trimmed) name', () => {
    let views = upsertView([], 'My View', { a: 1 }, 'a')
    views = upsertView(views, '  my view ', { a: 2 }, 'b')
    expect(views.length).toBe(1)
    expect(views[0]).toEqual({ id: 'b', name: 'my view', state: { a: 2 } })
  })

  it('ignores blank names', () => {
    expect(upsertView([], '   ', { a: 1 }, 'a')).toEqual([])
  })

  it('removes by id', () => {
    const views = [{ id: 'a', name: 'A', state: {} }, { id: 'b', name: 'B', state: {} }]
    expect(removeView(views, 'a')).toEqual([{ id: 'b', name: 'B', state: {} }])
  })

  it('readViews tolerates malformed storage', () => {
    try { localStorage.setItem('k_bad', '{not json') } catch { /* ignore */ }
    expect(readViews('k_bad')).toEqual([])
    try { localStorage.setItem('k_arr', JSON.stringify([{ id: 'a', name: 'A', state: {} }, { nope: 1 }])) } catch { /* ignore */ }
    expect(readViews('k_arr')).toEqual([{ id: 'a', name: 'A', state: {} }])
  })
})
