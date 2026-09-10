import { describe, it, expect } from 'vitest'
import {
  makeNode,
  connect,
  removeNode,
  serializeGraph,
  isBlockedWebhookUrl,
  playbookActionsHaveBlockedWebhook,
  dslToFlow,
  flowToDsl,
  stripCanvas,
  canConnect,
  wouldCreateCycle,
  graphHasCycle,
  nextNumericId,
  patchNode,
  validatePlaybookGraph,
  autoLayoutFlow,
  logicalPlaybookKey,
  nodeTitleKey,
  summarizeTrigger,
  summarizeAction,
  kindMeta,
} from './playbookFlow.js'

describe('playbookFlow', () => {
  it('builds a typed node with a deterministic id', () => {
    const n = makeNode('action', 3, { x: 10, y: 20 })
    expect(n.id).toBe('n3')
    expect(n.type).toBe('playbook')
    expect(n.data.nodeType).toBe('action')
    expect(n.data.kind).toBe('set_status')
    expect(n.data.label).toBe('Action')
    expect(n.data.params).toEqual({ status: 'IN_PROGRESS' })
    expect(n.position).toEqual({ x: 10, y: 20 })
  })

  it('maps palette aliases and persistable kinds', () => {
    expect(kindMeta('notify').kind).toBe('slack_notify')
    expect(kindMeta('isolate_host').nodeType).toBe('action')
    expect(makeNode('trigger', 1).data.trigger).toEqual({})
    expect(makeNode('condition', 2).data.kind).toBe('condition')
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
      { id: 'n1', type: 'trigger', kind: 'trigger', position: { x: 0, y: 0 } },
      { id: 'n2', type: 'action', kind: 'set_status', position: { x: 0, y: 0 } },
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

  it('auto-layouts a DSL into a trigger chain', () => {
    const { nodes, edges } = dslToFlow(
      { severity: ['critical'], kev: true },
      [
        { kind: 'set_status', params: { status: 'IN_PROGRESS' } },
        { kind: 'isolate_host', params: { target: '{{target}}' } },
      ],
    )
    expect(nodes[0].data.kind).toBe('trigger')
    expect(nodes[0].data.trigger).toEqual({ severity: ['critical'], kev: true })
    expect(nodes.map((n) => n.data.kind)).toEqual(['trigger', 'set_status', 'isolate_host'])
    expect(edges).toHaveLength(2)
    expect(edges[0].source).toBe('n1')
    expect(edges[0].target).toBe('n2')
  })

  it('round-trips DSL through the canvas including layout', () => {
    const trigger = { severity: ['high'], cooldown_seconds: 60 }
    const actions = [
      { kind: 'slack_notify', params: { url: 'https://hooks.slack.com/x', template: '{{title}}' } },
      { kind: 'page_oncall', params: { team: 'sec-oncall' } },
    ]
    const { nodes, edges } = dslToFlow(trigger, actions)
    const dsl = flowToDsl(nodes, edges)
    expect(dsl.actions).toEqual(actions)
    expect(dsl.trigger.severity).toEqual(['high'])
    expect(dsl.trigger.cooldown_seconds).toBe(60)
    expect(dsl.trigger._canvas.nodes).toHaveLength(3)
    expect(stripCanvas(dsl.trigger).severity).toEqual(['high'])
    expect(stripCanvas(dsl.trigger)._canvas).toBeUndefined()

    const restored = dslToFlow(dsl.trigger, dsl.actions)
    expect(restored.nodes.map((n) => n.id)).toEqual(nodes.map((n) => n.id))
    expect(restored.nodes[2].data.params).toEqual({ team: 'sec-oncall' })
  })

  it('falls back to auto-layout when stored canvas kinds drift from actions', () => {
    const trigger = {
      _canvas: {
        nodes: [
          { id: 'n1', kind: 'trigger', position: { x: 1, y: 1 } },
          { id: 'n2', kind: 'webhook', position: { x: 2, y: 2 } },
        ],
        edges: [{ source: 'n1', target: 'n2' }],
      },
    }
    const { nodes } = dslToFlow(trigger, [{ kind: 'set_status', params: { status: 'OPEN' } }])
    expect(nodes.map((n) => n.data.kind)).toEqual(['trigger', 'set_status'])
    expect(nodes[1].position.y).toBeGreaterThan(nodes[0].position.y)
  })

  it('linearizes branching by y-then-x and appends orphans', () => {
    const trigger = makeNode('trigger', 1, { x: 0, y: 0 })
    const left = makeNode('set_status', 2, { x: 0, y: 100 }, { params: { status: 'OPEN' } })
    const right = makeNode('page_oncall', 3, { x: 200, y: 100 })
    const orphan = makeNode('open_pr', 4, { x: 0, y: 400 })
    const edges = connect(connect([], 'n1', 'n3'), 'n1', 'n2')
    const dsl = flowToDsl([trigger, left, right, orphan], edges)
    expect(dsl.actions.map((a) => a.kind)).toEqual(['set_status', 'page_oncall', 'open_pr'])
    expect(dsl.issues.some((i) => i.code === 'orphans')).toBe(true)
  })

  it('skips visual-only condition/delay nodes when compiling DSL', () => {
    const trigger = makeNode('trigger', 1)
    const cond = makeNode('condition', 2, { x: 0, y: 80 })
    const act = makeNode('isolate_host', 3, { x: 0, y: 180 })
    const edges = connect(connect([], 'n1', 'n2'), 'n2', 'n3')
    const dsl = flowToDsl([trigger, cond, act], edges)
    expect(dsl.actions).toEqual([{ kind: 'isolate_host', params: act.data.params }])
    expect(dsl.issues.some((i) => i.code === 'visual_only')).toBe(true)
  })

  it('rejects connecting into the trigger or creating a cycle', () => {
    const nodes = [makeNode('trigger', 1), makeNode('set_status', 2), makeNode('webhook', 3)]
    let edges = connect([], 'n1', 'n2')
    expect(canConnect(nodes, edges, 'n2', 'n1')).toBe(false)
    expect(canConnect(nodes, edges, 'n2', 'n3')).toBe(true)
    edges = connect(edges, 'n2', 'n3')
    expect(wouldCreateCycle(edges, 'n3', 'n1')).toBe(true)
    expect(wouldCreateCycle(edges, 'n3', 'n2')).toBe(true)
    expect(graphHasCycle(nodes, connect(edges, 'n3', 'n1'))).toBe(true)
    expect(validatePlaybookGraph(nodes, edges).ok).toBe(true)
    expect(validatePlaybookGraph([], []).ok).toBe(false)
  })

  it('patches node data and allocates the next numeric id', () => {
    const nodes = [makeNode('trigger', 1), makeNode('set_status', 4)]
    expect(nextNumericId(nodes)).toBe(5)
    const patched = patchNode(nodes, 'n4', { params: { status: 'FIXED' } })
    expect(patched[1].data.params.status).toBe('FIXED')
    expect(nodes[1].data.params.status).toBe('IN_PROGRESS')
  })

  it('keeps logical keys stable across layout-only canvas blobs', () => {
    const a = { severity: ['low'] }
    const b = { severity: ['low'], _canvas: { nodes: [] } }
    expect(logicalPlaybookKey(a, [])).toBe(logicalPlaybookKey(b, []))
    expect(autoLayoutFlow(a, []).nodes[0].data.kind).toBe('trigger')
  })

  it('builds title keys and summaries', () => {
    expect(nodeTitleKey({ kind: 'isolate_host' })).toBe('playbooks.action.isolate_host')
    expect(nodeTitleKey({ nodeType: 'trigger', kind: 'trigger' })).toBe('playbooks.nodes.trigger')
    expect(summarizeTrigger({ severity: ['critical'], kev: true })).toContain('KEV')
    expect(summarizeAction('set_status', { status: 'OPEN' })).toBe('OPEN')
    expect(summarizeAction('webhook', { url: 'https://hooks.example.com/x' })).toBe('hooks.example.com')
  })
})
