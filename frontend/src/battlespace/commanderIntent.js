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

/** BFS from multiple seeds to target — returns all nodes on any shortest-layer path union.
 * `allNodes` (optional) is the full node list used for the "target unreachable"
 * fallback so isolated nodes (no edges, absent from `adj`) are still included. */
export function nodesReachableToTarget(seeds, targetId, adj, allNodes = []) {
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

  // Target unreachable from any seed → fall back to the whole graph. Prefer the
  // full node list (includes isolated nodes with no edges); fall back to the
  // adjacency keys if no node list was supplied.
  if (!dist.has(target)) {
    const all = (allNodes || []).map((n) => String(n.id))
    return all.length ? new Set(all) : new Set(adj.keys())
  }

  // Backtrack from the target along strictly-decreasing BFS distance. This
  // yields the union of all shortest-layer paths from the seeds to the target
  // (a blanket `d <= targetDist` add would instead pull in the entire BFS ball
  // of that radius — nearly the whole graph — defeating the focus dimming).
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
  const bfsNodes = nodesReachableToTarget(perimeter, focusId, adj, nodes)

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
