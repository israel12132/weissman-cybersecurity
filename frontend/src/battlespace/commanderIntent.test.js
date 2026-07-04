import { describe, it, expect } from 'vitest'
import { buildAdjacency, findPerimeterNodes, nodesReachableToTarget } from './commanderIntent.js'
describe('commanderIntent', () => {
  it('adjacency', () => {
    const a = buildAdjacency([{ source: '1', target: '2' }])
    expect(a.get('1')?.has('2')).toBe(true)
  })
  it('perimeter', () => {
    expect(findPerimeterNodes([{ id: 'p', internet_exposed: true }])).toContain('p')
  })
  it('reachable nodes', () => {
    const adj = buildAdjacency([{ source: 'a', target: 'b' }, { source: 'b', target: 'c' }])
    const nodes = nodesReachableToTarget(['a'], 'c', adj)
    expect(nodes.has('c')).toBe(true)
  })
})