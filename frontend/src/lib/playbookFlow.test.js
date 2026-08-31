import { describe, it, expect } from 'vitest'
import { makeNode, connect, removeNode, serializeGraph, isBlockedWebhookUrl, playbookActionsHaveBlockedWebhook } from './playbookFlow.js'

describe('playbookFlow', () => {
  it('builds a typed node with a deterministic id', () => {
    const n = makeNode('action', 3, { x: 10, y: 20 })
    expect(n.id).toBe('n3')
    expect(n.type).toBe('playbook')
    expect(n.data).toEqual({ label: 'Action', nodeType: 'action' })
    expect(n.position).toEqual({ x: 10, y: 20 })
  })

  it('connects two nodes and de-dupes edges', () => {
    let edges = connect([], 'n1', 'n2')
    expect(edges).toHaveLength(1)
    expect(edges[0].id).toBe('e-n1-n2')
    edges = connect(edges, 'n1', 'n2') // duplicate
    expect(edges).toHaveLength(1)
  })

  it('ignores self / empty connections', () => {
    expect(connect([], 'n1', 'n1')).toHaveLength(0)
    expect(connect([], '', 'n2')).toHaveLength(0)
  })

  it('removes a node and its incident edges', () => {
    const nodes = [{ id: 'n1' }, { id: 'n2' }, { id: 'n3' }]
    const edges = [
      { id: 'e-n1-n2', source: 'n1', target: 'n2' },
      { id: 'e-n2-n3', source: 'n2', target: 'n3' },
    ]
    const out = removeNode(nodes, edges, 'n2')
    expect(out.nodes.map((n) => n.id)).toEqual(['n1', 'n3'])
    expect(out.edges).toHaveLength(0)
  })

  it('serializes to a compact persistable graph', () => {
    const nodes = [makeNode('trigger', 1), makeNode('action', 2)]
    const edges = connect([], 'n1', 'n2')
    const g = serializeGraph(nodes, edges)
    expect(g.nodes).toEqual([
      { id: 'n1', type: 'trigger', position: { x: 0, y: 0 } },
      { id: 'n2', type: 'action', position: { x: 0, y: 0 } },
    ])
    expect(g.edges).toEqual([{ source: 'n1', target: 'n2' }])
  })

  it('blocks metadata and private webhook hosts', () => {
    expect(isBlockedWebhookUrl('http://169.254.169.254/latest/meta-data/')).toBe(true)
    expect(isBlockedWebhookUrl('http://127.0.0.1/hook')).toBe(true)
    expect(isBlockedWebhookUrl('http://localhost/hook')).toBe(true)
    expect(isBlockedWebhookUrl('https://hooks.slack.com/services/T/B/X')).toBe(false)
    expect(playbookActionsHaveBlockedWebhook([
      { kind: 'webhook', params: { url: 'http://169.254.169.254/' } },
    ])).toBe(true)
    expect(playbookActionsHaveBlockedWebhook([
      { kind: 'set_status', params: { status: 'OPEN' } },
    ])).toBe(false)
  })
})
