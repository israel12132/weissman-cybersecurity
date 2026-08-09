import { useEffect, useRef, useCallback, useMemo } from 'react'

const VERT = `#version 300 es
in vec2 a_pos;
in float a_size;
in vec4 a_color;
uniform vec2 u_resolution;
uniform vec2 u_pan;
uniform float u_zoom;
out vec4 v_color;
void main() {
  vec2 p = (a_pos + u_pan) * u_zoom;
  vec2 clip = p / u_resolution * 2.0 - 1.0;
  gl_Position = vec4(clip * vec2(1.0, -1.0), 0.0, 1.0);
  gl_PointSize = a_size * u_zoom;
  v_color = a_color;
}`

const FRAG = `#version 300 es
precision mediump float;
in vec4 v_color;
out vec4 outColor;
void main() {
  vec2 c = gl_PointCoord - 0.5;
  float d = dot(c, c);
  if (d > 0.25) discard;
  float glow = smoothstep(0.25, 0.0, d);
  outColor = vec4(v_color.rgb, v_color.a * glow);
}`

const LINE_VERT = `#version 300 es
in vec2 a_pos;
uniform vec2 u_resolution;
uniform vec2 u_pan;
uniform float u_zoom;
void main() {
  vec2 p = (a_pos + u_pan) * u_zoom;
  vec2 clip = p / u_resolution * 2.0 - 1.0;
  gl_Position = vec4(clip * vec2(1.0, -1.0), 0.0, 1.0);
}`

const LINE_FRAG = `#version 300 es
precision mediump float;
uniform vec4 u_color;
out vec4 outColor;
void main() { outColor = u_color; }`

function compileShader(gl, type, src) {
  const s = gl.createShader(type)
  gl.shaderSource(s, src)
  gl.compileShader(s)
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
    console.error(gl.getShaderInfoLog(s))
    gl.deleteShader(s)
    return null
  }
  return s
}

function linkProgram(gl, vs, fs) {
  if (!vs || !fs) return null
  const p = gl.createProgram()
  gl.attachShader(p, vs)
  gl.attachShader(p, fs)
  gl.linkProgram(p)
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
    console.error(gl.getProgramInfoLog(p))
    return null
  }
  return p
}

function nodeColor(node, mask, focusId) {
  const id = String(node.id)
  const dim = mask?.relevantNodes && !mask.relevantNodes.has(id)
  if (node.is_shadow) return [0.55, 0.35, 1.0, dim ? 0.15 : 0.75]
  if (node.compromised || node.node_type === 'finding') return [1.0, 0.2, 0.35, dim ? 0.12 : 0.95]
  if (String(focusId) === id) return [0.13, 0.95, 0.85, 1.0]
  if (node.crown_jewel) return [1.0, 0.75, 0.2, dim ? 0.1 : 0.9]
  if (node.internet_exposed) return [0.2, 0.75, 1.0, dim ? 0.1 : 0.85]
  if (node.is_choke_point) return [1.0, 0.45, 0.1, dim ? 0.1 : 0.8]
  const rs = Math.min(1, (node.risk_score || 0) / 100)
  return [0.3 + rs * 0.5, 0.5, 0.9 - rs * 0.3, dim ? 0.08 : 0.65]
}

export default function BattlespaceWebGL({
  nodes = [],
  edges = [],
  positions,
  intentMask,
  focusId,
  shadowNodes = [],
  shadowEdges = [],
  onNodePick,
  className = '',
}) {
  const canvasRef = useRef(null)
  const glRef = useRef(null)
  const programsRef = useRef({})
  const panRef = useRef({ x: 0, y: 0 })
  const zoomRef = useRef(1)
  const dragRef = useRef(null)
  const allNodes = useMemo(() => [...nodes, ...shadowNodes], [nodes, shadowNodes])
  // id → index lookup so the per-frame edge pass is O(edges) instead of
  // O(edges × nodes) findIndex scans.
  const nodeIndexById = useMemo(() => {
    const m = new Map()
    allNodes.forEach((n, i) => m.set(String(n.id), i))
    return m
  }, [allNodes])

  const render = useCallback(() => {
    const canvas = canvasRef.current
    const gl = glRef.current
    const prog = programsRef.current
    if (!canvas || !gl || !prog.points) return

    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    const w = canvas.clientWidth
    const h = canvas.clientHeight
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr
      canvas.height = h * dpr
      gl.viewport(0, 0, canvas.width, canvas.height)
    }

    gl.clearColor(0.02, 0.04, 0.08, 1)
    gl.clear(gl.COLOR_BUFFER_BIT)
    gl.enable(gl.BLEND)
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA)

    const pan = panRef.current
    const zoom = zoomRef.current

    // Edges (subset when intent active)
    const lineVerts = []
    const edgeList = [...edges, ...shadowEdges]
    const maxEdges = intentMask?.relevantEdges ? 50000 : 8000
    let edgeCount = 0
    for (const e of edgeList) {
      if (edgeCount >= maxEdges) break
      const s = String(e.source ?? e.from)
      const t = String(e.target ?? e.to)
      const key = `${s}->${t}`
      const isShadow = !!e.is_shadow
      if (intentMask?.relevantEdges && !intentMask.relevantEdges.has(key) && !isShadow) continue
      const si = nodeIndexById.get(s) ?? -1
      const ti = nodeIndexById.get(t) ?? -1
      if (si < 0 || ti < 0 || !positions) continue
      lineVerts.push(positions[si * 2], positions[si * 2 + 1], positions[ti * 2], positions[ti * 2 + 1])
      edgeCount++
    }

    if (lineVerts.length && prog.lines) {
      gl.useProgram(prog.lines)
      const buf = gl.createBuffer()
      gl.bindBuffer(gl.ARRAY_BUFFER, buf)
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(lineVerts), gl.DYNAMIC_DRAW)
      const loc = gl.getAttribLocation(prog.lines, 'a_pos')
      gl.enableVertexAttribArray(loc)
      gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0)
      gl.uniform2f(gl.getUniformLocation(prog.lines, 'u_resolution'), w * dpr, h * dpr)
      gl.uniform2f(gl.getUniformLocation(prog.lines, 'u_pan'), pan.x + w / 2, pan.y + h / 2)
      gl.uniform1f(gl.getUniformLocation(prog.lines, 'u_zoom'), zoom)
      gl.uniform4f(gl.getUniformLocation(prog.lines, 'u_color'), 0.15, 0.65, 0.85, 0.25)
      gl.drawArrays(gl.LINES, 0, lineVerts.length / 2)
      gl.deleteBuffer(buf)
    }

    // Nodes
    if (!positions?.length || !allNodes.length) return

    const count = allNodes.length
    const posBuf = new Float32Array(count * 2)
    const sizeBuf = new Float32Array(count)
    const colBuf = new Float32Array(count * 4)

    for (let i = 0; i < count; i++) {
      const n = allNodes[i]
      posBuf[i * 2] = positions[i * 2] ?? 0
      posBuf[i * 2 + 1] = positions[i * 2 + 1] ?? 0
      sizeBuf[i] = n.is_shadow ? 14 : n.crown_jewel ? 12 : 6 + Math.min(6, (n.risk_score || 0) / 20)
      const [r, g, b, a] = nodeColor(n, intentMask, focusId)
      colBuf[i * 4] = r
      colBuf[i * 4 + 1] = g
      colBuf[i * 4 + 2] = b
      colBuf[i * 4 + 3] = a
    }

    gl.useProgram(prog.points)
    const bind = (loc, data, size) => {
      const b = gl.createBuffer()
      gl.bindBuffer(gl.ARRAY_BUFFER, b)
      gl.bufferData(gl.ARRAY_BUFFER, data, gl.DYNAMIC_DRAW)
      gl.enableVertexAttribArray(loc)
      gl.vertexAttribPointer(loc, size, gl.FLOAT, false, 0, 0)
      return b
    }
    const locPos = gl.getAttribLocation(prog.points, 'a_pos')
    const locSize = gl.getAttribLocation(prog.points, 'a_size')
    const locCol = gl.getAttribLocation(prog.points, 'a_color')
    const b1 = bind(locPos, posBuf, 2)
    const b2 = bind(locSize, sizeBuf, 1)
    const b3 = bind(locCol, colBuf, 4)
    gl.uniform2f(gl.getUniformLocation(prog.points, 'u_resolution'), w * dpr, h * dpr)
    gl.uniform2f(gl.getUniformLocation(prog.points, 'u_pan'), pan.x + w / 2, pan.y + h / 2)
    gl.uniform1f(gl.getUniformLocation(prog.points, 'u_zoom'), zoom)
    gl.drawArrays(gl.POINTS, 0, count)
    ;[b1, b2, b3].forEach((b) => gl.deleteBuffer(b))
  }, [allNodes, nodeIndexById, edges, shadowEdges, positions, intentMask, focusId])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const gl = canvas.getContext('webgl2', { antialias: true, alpha: false })
    if (!gl) return
    glRef.current = gl
    const vs = compileShader(gl, gl.VERTEX_SHADER, VERT)
    const fs = compileShader(gl, gl.FRAGMENT_SHADER, FRAG)
    const lvs = compileShader(gl, gl.VERTEX_SHADER, LINE_VERT)
    const lfs = compileShader(gl, gl.FRAGMENT_SHADER, LINE_FRAG)
    programsRef.current = {
      points: linkProgram(gl, vs, fs),
      lines: linkProgram(gl, lvs, lfs),
    }
    // `points` is required by render() (it bails at `!prog.points`), so a failed
    // points program means GL is unusable — mark it so. A `lines`-only failure
    // still renders nodes, so keep glRef in that case.
    if (!programsRef.current.points) {
      glRef.current = null
    }
    return () => {
      gl.getExtension('WEBGL_lose_context')?.loseContext()
    }
  }, [])

  useEffect(() => {
    let raf
    const frame = () => {
      render()
      raf = requestAnimationFrame(frame)
    }
    raf = requestAnimationFrame(frame)
    return () => cancelAnimationFrame(raf)
  }, [render])

  const pickNode = useCallback((clientX, clientY) => {
    const canvas = canvasRef.current
    if (!canvas || !positions?.length) return
    const rect = canvas.getBoundingClientRect()
    const mx = clientX - rect.left
    const my = clientY - rect.top
    const pan = panRef.current
    const zoom = zoomRef.current
    let best = null
    let bestD = 20
    for (let i = 0; i < allNodes.length; i++) {
      const px = (positions[i * 2] + pan.x + rect.width / 2) * zoom
      const py = (positions[i * 2 + 1] + pan.y + rect.height / 2) * zoom
      const d = Math.hypot(px - mx, py - my)
      if (d < bestD) {
        bestD = d
        best = allNodes[i]
      }
    }
    return best
  }, [allNodes, positions])

  return (
    <canvas
      ref={canvasRef}
      className={`battlespace-canvas w-full h-full touch-none ${className}`}
      onWheel={(e) => {
        e.preventDefault()
        zoomRef.current = Math.max(0.2, Math.min(4, zoomRef.current * (e.deltaY > 0 ? 0.92 : 1.08)))
      }}
      onMouseDown={(e) => {
        dragRef.current = { x: e.clientX, y: e.clientY, pan: { ...panRef.current } }
      }}
      onMouseMove={(e) => {
        if (!dragRef.current) return
        panRef.current = {
          x: dragRef.current.pan.x + (e.clientX - dragRef.current.x),
          y: dragRef.current.pan.y + (e.clientY - dragRef.current.y),
        }
      }}
      onMouseUp={() => { dragRef.current = null }}
      onMouseLeave={() => { dragRef.current = null }}
      onClick={(e) => {
        const node = pickNode(e.clientX, e.clientY)
        if (node && onNodePick) onNodePick(node)
      }}
    />
  )
}
