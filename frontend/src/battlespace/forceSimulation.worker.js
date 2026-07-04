/**
 * Force-directed layout worker — keeps main thread liquid for WebGL render @ 60fps.
 */
const MAX_NODES = 6000
const MAX_EDGES = 60000

let nodes = []
let edges = []
let positions = null
let velocities = null
let idIndex = new Map()
let running = false
let tickId = null

function initState(n, e) {
  nodes = n.slice(0, MAX_NODES)
  edges = e.slice(0, MAX_EDGES)
  const count = nodes.length
  positions = new Float32Array(count * 2)
  velocities = new Float32Array(count * 2)
  idIndex = new Map(nodes.map((node, i) => [String(node.id), i]))
  for (let i = 0; i < count; i++) {
    positions[i * 2] = (Math.random() - 0.5) * 400
    positions[i * 2 + 1] = (Math.random() - 0.5) * 400
  }
}

function tick() {
  const count = nodes.length
  if (!count) return

  const repulsion = 80
  const attraction = 0.006
  const damping = 0.86
  const maxV = 6

  for (let i = 0; i < count; i++) {
    let fx = -positions[i * 2] * 0.002
    let fy = -positions[i * 2 + 1] * 0.002
    const px = positions[i * 2]
    const py = positions[i * 2 + 1]

    for (let j = i + 1; j < count; j++) {
      let dx = px - positions[j * 2]
      let dy = py - positions[j * 2 + 1]
      const d2 = dx * dx + dy * dy + 1
      const f = repulsion / d2
      const d = Math.sqrt(d2)
      dx /= d
      dy /= d
      fx += dx * f
      fy += dy * f
      velocities[j * 2] -= dx * f
      velocities[j * 2 + 1] -= dy * f
    }
    velocities[i * 2] += fx
    velocities[i * 2 + 1] += fy
  }

  for (const e of edges) {
    const si = idIndex.get(String(e.source ?? e.from))
    const ti = idIndex.get(String(e.target ?? e.to))
    if (si == null || ti == null) continue
    const dx = positions[ti * 2] - positions[si * 2]
    const dy = positions[ti * 2 + 1] - positions[si * 2 + 1]
    const dist = Math.sqrt(dx * dx + dy * dy) + 0.01
    const f = dist * attraction
    velocities[si * 2] += (dx / dist) * f
    velocities[si * 2 + 1] += (dy / dist) * f
    velocities[ti * 2] -= (dx / dist) * f
    velocities[ti * 2 + 1] -= (dy / dist) * f
  }

  for (let i = 0; i < count; i++) {
    const ix = i * 2
    velocities[ix] *= damping
    velocities[ix + 1] *= damping
    velocities[ix] = Math.max(-maxV, Math.min(maxV, velocities[ix]))
    velocities[ix + 1] = Math.max(-maxV, Math.min(maxV, velocities[ix + 1]))
    positions[ix] += velocities[ix]
    positions[ix + 1] += velocities[ix + 1]
  }
}

function loop() {
  if (!running) return
  tick()
  self.postMessage({ type: 'positions', positions: positions.slice() })
  tickId = setTimeout(loop, 16)
}

self.onmessage = (ev) => {
  const msg = ev.data
  if (msg.type === 'init') {
    running = false
    if (tickId) clearTimeout(tickId)
    initState(msg.nodes || [], msg.edges || [])
    self.postMessage({ type: 'positions', positions: positions.slice() })
  }
  if (msg.type === 'start') {
    running = true
    loop()
  }
  if (msg.type === 'stop') {
    running = false
    if (tickId) clearTimeout(tickId)
  }
}
