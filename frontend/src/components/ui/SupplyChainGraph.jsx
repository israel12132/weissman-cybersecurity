import { useMemo } from 'react'

/**
 * Renders the reconstructed dependency graph from a supply-chain inventory finding.
 *
 * Expects (any subset of):
 *   - components: [{ package, ecosystem, version, reachability, evidence_kind }]
 *   - edges:      [[parent, child], ...]
 *   - direct:     [name, ...]
 *   - summary:    { nodes, edges, direct }
 *   - byReach:    { client_runtime, direct, transitive, declared }
 *
 * Layout is a deterministic layered diagram: one column per reachability tier,
 * nodes stacked within a tier, edges drawn as SVG curves between placed nodes.
 */

const TIERS = ['client_runtime', 'direct', 'transitive', 'declared']

const TIER_META = {
  client_runtime: { color: '#fb7185', label: 'client_runtime' },
  direct: { color: '#fbbf24', label: 'direct' },
  transitive: { color: '#38bdf8', label: 'transitive' },
  declared: { color: '#94a3b8', label: 'declared' },
}

const MAX_PER_TIER = 16
const NODE_W = 150
const NODE_H = 22
const ROW_GAP = 30
const COL_GAP = 210
const PAD_X = 16
const PAD_Y = 38

function truncate(s, n) {
  const str = String(s ?? '')
  return str.length > n ? `${str.slice(0, n - 1)}…` : str
}

export default function SupplyChainGraph({
  components = [],
  edges = [],
  direct = [],
  summary = null,
  byReach = null,
  t,
}) {
  const tr = (key, fallback) => {
    if (!t) return fallback
    const v = t(`components.findingDrawer.supplyChain.${key}`)
    return v === `components.findingDrawer.supplyChain.${key}` ? fallback : v
  }

  const model = useMemo(() => {
    const comps = Array.isArray(components) ? components : []
    const eds = Array.isArray(edges)
      ? edges.filter((e) => Array.isArray(e) && e.length === 2)
      : []
    const directSet = new Set((Array.isArray(direct) ? direct : []).map(String))
    const childSet = new Set(eds.map((e) => String(e[1])))

    const compMap = new Map()
    comps.forEach((c) => {
      if (c && c.package) compMap.set(String(c.package), c)
    })

    const tierOf = (name) => {
      const c = compMap.get(name)
      if (c?.reachability) return c.reachability
      if (directSet.has(name)) return 'direct'
      if (childSet.has(name)) return 'transitive'
      return 'declared'
    }

    const names = new Set()
    directSet.forEach((n) => names.add(n))
    eds.forEach((e) => {
      names.add(String(e[0]))
      names.add(String(e[1]))
    })
    comps.forEach((c) => {
      if (c?.package) names.add(String(c.package))
    })

    const perTier = { client_runtime: [], direct: [], transitive: [], declared: [] }
    names.forEach((n) => {
      const tier = tierOf(n)
      ;(perTier[tier] ?? perTier.declared).push(n)
    })
    TIERS.forEach((tier) => perTier[tier].sort())

    const pos = new Map()
    const shown = {}
    TIERS.forEach((tier, ti) => {
      const list = perTier[tier]
      shown[tier] = { total: list.length, visible: Math.min(list.length, MAX_PER_TIER) }
      list.slice(0, MAX_PER_TIER).forEach((n, ri) => {
        pos.set(n, { x: PAD_X + ti * COL_GAP, y: PAD_Y + ri * ROW_GAP, tier })
      })
    })

    const placedEdges = eds.filter((e) => pos.has(String(e[0])) && pos.has(String(e[1])))

    const maxRows = Math.max(
      1,
      ...TIERS.map((tier) => Math.min(perTier[tier].length, MAX_PER_TIER)),
    )
    const width = PAD_X * 2 + (TIERS.length - 1) * COL_GAP + NODE_W
    const height = PAD_Y + maxRows * ROW_GAP + 10

    const activeTiers = TIERS.filter((tier) => perTier[tier].length > 0)

    return { pos, placedEdges, width, height, shown, compMap, activeTiers, perTier }
  }, [components, edges, direct])

  const hasGraph = model.pos.size > 0

  return (
    <div className="space-y-3">
      {/* Summary chips */}
      <div className="flex flex-wrap gap-1.5">
        {summary && (
          <>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-[var(--border-strong)] text-[var(--text-tertiary)]">
              {summary.nodes ?? 0} {tr('nodes', 'nodes')}
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-[var(--border-strong)] text-[var(--text-tertiary)]">
              {summary.edges ?? 0} {tr('edges', 'edges')}
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-amber-500/30 text-amber-300/90">
              {summary.direct ?? 0} {tr('directCount', 'direct')}
            </span>
          </>
        )}
        {byReach &&
          TIERS.filter((tier) => byReach[tier]).map((tier) => (
            <span
              key={tier}
              className="text-[10px] font-mono px-2 py-0.5 rounded border"
              style={{
                color: TIER_META[tier].color,
                borderColor: `${TIER_META[tier].color}55`,
              }}
            >
              {tr(tier, TIER_META[tier].label)}: {byReach[tier]}
            </span>
          ))}
      </div>

      {/* SVG node-link diagram */}
      {hasGraph && (
        <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] overflow-auto custom-scroll max-h-[420px]">
          <svg
            width={model.width}
            height={model.height}
            viewBox={`0 0 ${model.width} ${model.height}`}
            className="block min-w-full"
            role="img"
            aria-label={tr('dependencyGraph', 'Dependency graph')}
          >
            {/* tier headers */}
            {model.activeTiers.map((tier) => {
              const sample = model.perTier[tier][0]
              const x = sample ? model.pos.get(sample)?.x : null
              if (x == null) return null
              return (
                <text
                  key={`hdr-${tier}`}
                  x={x}
                  y={20}
                  className="font-mono"
                  fontSize="9"
                  fill={TIER_META[tier].color}
                  style={{ textTransform: 'uppercase', letterSpacing: '0.1em' }}
                >
                  {tr(tier, TIER_META[tier].label)}
                </text>
              )
            })}

            {/* edges */}
            <g opacity="0.5">
              {model.placedEdges.map((e, i) => {
                const a = model.pos.get(String(e[0]))
                const b = model.pos.get(String(e[1]))
                if (!a || !b) return null
                const x1 = a.x + NODE_W
                const y1 = a.y + NODE_H / 2
                const x2 = b.x
                const y2 = b.y + NODE_H / 2
                const mx = (x1 + x2) / 2
                return (
                  <path
                    key={`e-${i}`}
                    d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
                    fill="none"
                    stroke="#64748b"
                    strokeWidth="1"
                  />
                )
              })}
            </g>

            {/* nodes */}
            {[...model.pos.entries()].map(([name, p]) => {
              const meta = TIER_META[p.tier] ?? TIER_META.declared
              const c = model.compMap.get(name)
              const ver = c?.version
              return (
                <g key={`n-${name}`}>
                  <rect
                    x={p.x}
                    y={p.y}
                    width={NODE_W}
                    height={NODE_H}
                    rx="5"
                    fill={`${meta.color}1f`}
                    stroke={`${meta.color}99`}
                    strokeWidth="1"
                  />
                  <text
                    x={p.x + 8}
                    y={p.y + NODE_H / 2 + 3}
                    fontSize="10"
                    className="font-mono"
                    fill="#e2e8f0"
                  >
                    {truncate(name, ver ? 16 : 22)}
                    {ver ? (
                      <tspan fill={meta.color} opacity="0.85">
                        {' '}
                        @{truncate(ver, 8)}
                      </tspan>
                    ) : null}
                  </text>
                </g>
              )
            })}
          </svg>
        </div>
      )}

      {/* Truncation note */}
      {Object.entries(model.shown).some(([, s]) => s.total > s.visible) && (
        <p className="text-[10px] font-mono text-[var(--text-muted)]">
          {tr('graphTruncated', 'Graph truncated for display')} —{' '}
          {TIERS.filter((tier) => model.shown[tier]?.total > model.shown[tier]?.visible)
            .map((tier) => `${tr(tier, tier)} ${model.shown[tier].visible}/${model.shown[tier].total}`)
            .join(', ')}
        </p>
      )}
    </div>
  )
}
