// Shared world-map primitives. This file is the ONLY place the app touches a
// geographic-map rendering library, so the underlying engine can be swapped in one
// spot. It currently wraps react-simple-maps; GeoMarker / GeoLine are thin
// pass-throughs so callers never import the map library directly.
//
// The world topology is vendored via the `world-atlas` dependency (no external CDN,
// works offline, keeps cdn.jsdelivr.net out of the CSP connect-src).
import {
  ComposableMap,
  Geographies,
  Geography,
  ZoomableGroup,
  Marker,
  Line,
} from 'react-simple-maps'
import worldGeography from 'world-atlas/countries-110m.json'

/** A marker anchored at [lng, lat]; children are SVG rendered at that projected point. */
export function GeoMarker({ coordinates, children, ...rest }) {
  return (
    <Marker coordinates={coordinates} {...rest}>
      {children}
    </Marker>
  )
}

/** A poly-line through a list of [lng, lat] coordinates. */
export function GeoLine({ coordinates, stroke, strokeWidth, strokeDasharray, strokeOpacity }) {
  return (
    <Line
      coordinates={coordinates}
      stroke={stroke}
      strokeWidth={strokeWidth}
      strokeDasharray={strokeDasharray}
      strokeOpacity={strokeOpacity}
      fill="none"
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
  const zoomProps = {}
  if (minZoom != null) zoomProps.minZoom = minZoom
  if (maxZoom != null) zoomProps.maxZoom = maxZoom
  return (
    <ComposableMap
      projection={projection}
      projectionConfig={{ scale: projectionScale }}
      style={style}
      className={className}
    >
      <ZoomableGroup center={center} zoom={zoom} {...zoomProps}>
        <Geographies geography={worldGeography}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill={geographyFill}
                stroke={geographyStroke}
                strokeWidth={geographyStrokeWidth}
                style={geographyStyle}
              />
            ))
          }
        </Geographies>
        {children}
      </ZoomableGroup>
    </ComposableMap>
  )
}
