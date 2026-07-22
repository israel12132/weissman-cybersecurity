import { forwardRef } from 'react'
import { cn } from '../../lib/cn'

/** Equirectangular projection of lat/lon into the 360×180 viewBox. */
function project(lat, lon) {
  return { x: Number(lon) + 180, y: 90 - Number(lat) }
}

function intensityClass(intensity) {
  const v = Number(intensity) || 0
  if (v >= 0.75) return 'text-severity-critical'
  if (v >= 0.5) return 'text-severity-high'
  if (v >= 0.25) return 'text-severity-medium'
  return 'text-severity-info'
}

/**
 * SwarmMap — a live global activity map with a threat heatmap and connection
 * arcs. A dependency-light equirectangular SVG (graticule background, no country
 * shapes needed) so it renders and tests everywhere; layer it over a geo map if
 * desired. Points are keyboard-selectable.
 *
 * @param {Array<{id:string,lat:number,lon:number,intensity?:number,label?:string}>} points
 * @param {Array<{from:{lat:number,lon:number},to:{lat:number,lon:number}}>} [arcs]
 * @param {number} [height=280] @param {(point:object)=>void} [onPointClick]
 * @param {string} [title='Global activity']
 */
const SwarmMap = forwardRef(function SwarmMap(
  { points = [], arcs = [], height = 280, onPointClick, title = 'Global activity', className, ...props },
  ref,
) {
  const gratLon = [30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330]
  const gratLat = [30, 60, 90, 120, 150]

  return (
    <div ref={ref} className={cn('w-full', className)} {...props}>
      <svg
        viewBox="0 0 360 180"
        role="img"
        aria-label={title}
        preserveAspectRatio="xMidYMid meet"
        className="w-full rounded-xl border border-border-default bg-bg-1"
        style={{ height }}
      >
        {/* Graticule */}
        <g className="text-border-subtle" stroke="currentColor" strokeWidth="0.3">
          {gratLon.map((x) => (
            <line key={`v${x}`} x1={x} y1="0" x2={x} y2="180" />
          ))}
          {gratLat.map((y) => (
            <line key={`h${y}`} x1="0" y1={y} x2="360" y2={y} />
          ))}
        </g>

        {/* Connection arcs */}
        <g className="text-accent-cyan" stroke="currentColor" fill="none" strokeWidth="0.5" opacity="0.6">
          {arcs.map((arc, i) => {
            const a = project(arc.from.lat, arc.from.lon)
            const b = project(arc.to.lat, arc.to.lon)
            const mx = (a.x + b.x) / 2
            const my = Math.min(a.y, b.y) - Math.hypot(b.x - a.x, b.y - a.y) * 0.25
            return <path key={i} d={`M${a.x},${a.y} Q${mx},${my} ${b.x},${b.y}`} />
          })}
        </g>

        {/* Heat points */}
        {points.map((p) => {
          const { x, y } = project(p.lat, p.lon)
          const r = 1.5 + (Number(p.intensity) || 0) * 4
          const cls = intensityClass(p.intensity)
          const label = `${p.label || p.id} (${Math.round((Number(p.intensity) || 0) * 100)}%)`
          const dot = (
            <g className={cls}>
              <circle cx={x} cy={y} r={r * 2} fill="currentColor" opacity="0.18" className="animate-pulse-subtle" />
              <circle cx={x} cy={y} r={r} fill="currentColor" />
            </g>
          )
          return onPointClick ? (
            <g
              key={p.id}
              role="button"
              tabIndex={0}
              aria-label={label}
              className="cursor-pointer focus-visible:outline-none"
              onClick={() => onPointClick(p)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  onPointClick(p)
                }
              }}
            >
              {dot}
            </g>
          ) : (
            <g key={p.id} role="img" aria-label={label}>
              {dot}
            </g>
          )
        })}
      </svg>
    </div>
  )
})

SwarmMap.displayName = 'SwarmMap'

export default SwarmMap
export { SwarmMap }
