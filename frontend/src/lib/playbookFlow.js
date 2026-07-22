/**
 * Pure graph helpers for the @xyflow playbook canvas — kept separate from the
 * ReactFlow rendering so the node/edge wiring logic is unit-testable without a
 * WebGL/layout environment. Ids are derived from a caller-supplied counter (no
 * RNG) so results are deterministic.
 */

export const NODE_LABEL = {
  trigger: 'Trigger',
  action: 'Action',
  condition: 'Condition',
  delay: 'Delay',
  notify: 'Notify',
}

/** Build a ReactFlow node of the given palette `type`. */
export function makeNode(type, id, position = { x: 0, y: 0 }) {
  return {
    id: `n${id}`,
    type: 'playbook',
    position: { x: Number(position.x) || 0, y: Number(position.y) || 0 },
    data: { label: NODE_LABEL[type] || type, nodeType: type },
  }
}

/** Add an edge source→target if it doesn't already exist. */
export function connect(edges, source, target) {
  if (!source || !target || source === target) return edges
  const id = `e-${source}-${target}`
  if ((edges || []).some((e) => e.id === id)) return edges
  return [...(edges || []), { id, source, target }]
}

/** Remove a node and any edges touching it. */
export function removeNode(nodes, edges, id) {
  return {
    nodes: (nodes || []).filter((n) => n.id !== id),
    edges: (edges || []).filter((e) => e.source !== id && e.target !== id),
  }
}

/** Serialize the canvas to a compact, persistable playbook graph. */
export function serializeGraph(nodes, edges) {
  return {
    nodes: (nodes || []).map((n) => ({ id: n.id, type: n.data?.nodeType, position: n.position })),
    edges: (edges || []).map((e) => ({ source: e.source, target: e.target })),
  }
}
