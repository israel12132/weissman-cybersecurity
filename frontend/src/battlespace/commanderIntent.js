/**
 * Commander's Intent — compute attack-path subgraph from perimeter to focus asset.
 */

export function buildAdjacency(edges) {
  const adj = new Map()
  const add = (a, b) => {
    if (!adj.has(a)) adj.set(a, new Set())
    adj.get(a).add(b)
  }
  for (const e of edges || []) {
    const s = String(e.source ?? e.from)
    const t = String(e.target ?? e.to)
    if (!s || !t) continue
    add(s, t)
    add(t, s)
  }
  return adj
}

export function findPerimeterNodes(nodes) {
  return (nodes || [])
    .filter((n) => n.internet_exposed || n.node_type === 'internet_gateway' || n.node_type === 'perimeter')
    .map((n) => String(n.id))
}

/** BFS from multiple seeds to target — returns all nodes on any shortest-layer path union. */
export function nodesReachableToTarget(seeds, targetId, adj) {
  const target = String(targetId)
  const relevant = new Set([target])
  if (!adj.size || !target) return relevant

  const dist = new Map()
  const queue = []
  for (const s of seeds) {
    const id = String(s)
    if (!adj.has(id) && id !== target) continue
    dist.set(id, 0)
    queue.push(id)
  }
  if (!queue.length) {
    for (const [id] of adj) {
      dist.set(id, 0)
      queue.push(id)
      break
    }
  }

  while (queue.length) {
    const cur = queue.shift()
    const d = dist.get(cur) ?? 0
    const neighbors = adj.get(cur)
    if (!neighbors) continue
    for (const nb of neighbors) {
      if (!dist.has(nb)) {
        dist.set(nb, d + 1)
        queue.push(nb)
      }
    }
  }

  // Target unreachable from any seed → fall back to the whole graph (every node
  // id in the adjacency map). `nodes` isn't in scope here; `adj` is the graph.
  if (!dist.has(target)) return new Set(adj.keys())

  const targetDist = dist.get(target)
  relevant.add(target)
  for (const [id, d] of dist) {
    if (d <= targetDist) relevant.add(id)
  }

  // Backtrack from target along decreasing distance
  const stack = [target]
  const visited = new Set([target])
  while (stack.length) {
    const cur = stack.pop()
    const curD = dist.get(cur)
    if (curD == null) continue
    for (const nb of adj.get(cur) || []) {
      if (visited.has(nb)) continue
      const nbD = dist.get(nb)
      if (nbD != null && nbD < curD) {
        relevant.add(nb)
        visited.add(nb)
        stack.push(nb)
      }
    }
  }

  for (const s of seeds) relevant.add(String(s))
  return relevant
}

export function pathsThroughNode(nodeId, attackPaths) {
  const id = Number(nodeId)
  const edgeKeys = new Set()
  const nodeIds = new Set()
  const paths = attackPaths?.paths || attackPaths || []
  for (const p of paths) {
    const steps = p.steps || []
    const onPath = steps.some((s) => Number(s.node_id) === id)
    if (!onPath) continue
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i]
      nodeIds.add(String(step.node_id))
      if (i > 0) {
        const prev = steps[i - 1]
        edgeKeys.add(`${prev.node_id}->${step.node_id}`)
      }
    }
  }
  return { nodeIds, edgeKeys }
}

export function computeIntentMask(focusId, nodes, edges, attackPaths) {
  if (focusId == null) {
    return {
      relevantNodes: null,
      relevantEdges: null,
      pathEdgeKeys: new Set(),
    }
  }

  const adj = buildAdjacency(edges)
  const perimeter = findPerimeterNodes(nodes)
  const { nodeIds: pathNodes, edgeKeys: pathEdgeKeys } = pathsThroughNode(focusId, attackPaths)
  const bfsNodes = nodesReachableToTarget(perimeter, focusId, adj)

  const relevantNodes = new Set([...bfsNodes, ...pathNodes, String(focusId)])
  const relevantEdges = new Set()

  for (const e of edges || []) {
    const s = String(e.source ?? e.from)
    const t = String(e.target ?? e.to)
    const key = `${s}->${t}`
    if (pathEdgeKeys.has(key) || (relevantNodes.has(s) && relevantNodes.has(t))) {
      relevantEdges.add(key)
    }
  }

  return { relevantNodes, relevantEdges, pathEdgeKeys }
}
