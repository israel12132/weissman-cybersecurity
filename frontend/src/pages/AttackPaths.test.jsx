import { describe, it, expect } from 'vitest'
import { filterGraphNodes } from './attackPathsGraph.js'

describe('filterGraphNodes', () => {
  const nodes = [
    { id: 1, label: 'db.prod', node_type: 'host' },
    { id: 2, label: 'vpn.edge', node_type: 'network' },
  ]

  it('returns all nodes when the query is empty', () => {
    expect(filterGraphNodes(nodes, '')).toHaveLength(2)
    expect(filterGraphNodes(nodes, '  ')).toHaveLength(2)
  })

  it('matches label or node type', () => {
    expect(filterGraphNodes(nodes, 'db.prod').map((n) => n.id)).toEqual([1])
    expect(filterGraphNodes(nodes, 'network').map((n) => n.id)).toEqual([2])
  })

  it('is safe on non-array input', () => {
    expect(filterGraphNodes(null, 'x')).toEqual([])
  })
})
