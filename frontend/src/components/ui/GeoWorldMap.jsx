// Shared world-map primitives. This is the ONLY place the app renders a geographic
// map, implemented directly on d3-geo (which react-simple-maps was itself a thin
// wrapper over) so the app carries no React-major-version-pinned map dependency.
//
// The world topology is vendored via the `world-atlas` dependency (no external CDN,
// works offline, keeps cdn.jsdelivr.net out of the CSP connect-src).
//
// Geometry matches react-simple-maps' defaults so the rendered output is unchanged:
//   * an 800x600 viewBox, projection translated to its centre and scaled by
//     `projectionScale` (rsm's `projectionConfig.scale`);
//   * a pan/zoom group transform of `translate(W/2 - k·cx, H/2 - k·cy) scale(k)`,
//     where [cx, cy] is the projected `center` and k is `zoom` — i.e. the projected
//     centre is placed at the viewport middle and scaled, identical to rsm's
//     ZoomableGroup;
//   * markers positioned with `translate(projection([lng, lat]))` and lines drawn as
//     GeoJSON `LineString`s through `geoPath`, so they follow great-circle arcs — the
//     same geodesic curve rsm's <Line> produced.
import { createContext, useContext, useMemo } from 'react'
import { geoEqualEarth, geoMercator, geoPath } from 'd3-geo'
import { feature } from 'topojson-client'
import worldTopology from 'world-atlas/countries-110m.json'

const WIDTH = 800
const HEIGHT = 600

const PROJECTIONS = {
  geoEqualEarth,
  geoMercator,
}

// One-time conversion of the vendored topology into GeoJSON country features.
const WORLD_FEATURES = feature(worldTopology, worldTopology.objects.countries).features

const MapContext = createContext(null)

/** A marker anchored at [lng, lat]; children are SVG rendered at that projected point. */
export function GeoMarker({ coordinates, children, ...rest }) {
  const ctx = useContext(MapContext)
  const point = ctx?.projection(coordinates)
  if (!point || !Number.isFinite(point[0]) || !Number.isFinite(point[1])) return null
  return (
    <g transform={`translate(${point[0]}, ${point[1]})`} {...rest}>
      {children}
    </g>
  )
}

/** A poly-line through a list of [lng, lat] coordinates (great-circle interpolated). */
export function GeoLine({ coordinates, stroke, strokeWidth, strokeDasharray, strokeOpacity }) {
  const ctx = useContext(MapContext)
  const d = ctx?.path({ type: 'LineString', coordinates })
  if (!d) return null
  return (
    <path
      d={d}
      fill="none"
      stroke={stroke}
      strokeWidth={strokeWidth}
      strokeDasharray={strokeDasharray}
      strokeOpacity={strokeOpacity}
    />
  )
}

/**
 * The world map shell: renders the country geographies and a pan/zoom group.
 * `center` is [lng, lat]; markers/lines are passed as children (GeoMarker / GeoLine).
 */
export default function GeoWorldMap({
  projection = 'geoEqualEarth',
  projectionScale = 160,
  center = [0, 0],
  zoom = 1,
  // minZoom / maxZoom are accepted for API compatibility with the previous
  // react-simple-maps wrapper; the current views drive center/zoom by prop, so
  // they are unused here (no interactive clamp needed).
  minZoom,
  maxZoom,
  geographyFill,
  geographyStroke,
  geographyStrokeWidth = 0.4,
  geographyStyle,
  style,
  className,
  children,
}) {
  void minZoom
  void maxZoom

  const { proj, path, countryPaths } = useMemo(() => {
    const factory = PROJECTIONS[projection] || geoEqualEarth
    const proj = factory()
      .translate([WIDTH / 2, HEIGHT / 2])
      .scale(projectionScale)
    const path = geoPath(proj)
    const countryPaths = WORLD_FEATURES.map((f) => path(f))
    return { proj, path, countryPaths }
  }, [projection, projectionScale])

  const projectedCenter = proj(center) || [WIDTH / 2, HEIGHT / 2]
  const k = zoom || 1
  const tx = WIDTH / 2 - k * projectedCenter[0]
  const ty = HEIGHT / 2 - k * projectedCenter[1]
  const ctxValue = useMemo(() => ({ projection: proj, path }), [proj, path])

  return (
    <svg
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      preserveAspectRatio="xMidYMid meet"
      style={style}
      className={className}
    >
      <MapContext.Provider value={ctxValue}>
        <g transform={`translate(${tx}, ${ty}) scale(${k})`}>
          {countryPaths.map((d, i) =>
            d ? (
              <path
                key={i}
                d={d}
                fill={geographyFill}
                stroke={geographyStroke}
                strokeWidth={geographyStrokeWidth}
                style={geographyStyle}
              />
            ) : null,
          )}
          {children}
        </g>
      </MapContext.Provider>
    </svg>
  )
}
