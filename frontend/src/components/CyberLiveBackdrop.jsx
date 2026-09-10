/**
 * Live cyber backdrop for pre-auth surfaces (login / status).
 *
 * Nine composited layers — aurora parallax, a scrolling telemetry lattice, a perspective horizon
 * floor, two speeds of packet rain, a scan sweep, a radar rotation, drifting motes, and a luminance
 * swell — over static grain and vignette. Every animated layer loops seamlessly by construction:
 * tiled layers translate exactly one background period, and drifting layers end on the transform
 * they started from (the radar's 360deg rotation is the same frame it began on). Nothing restarts
 * from a different position, so there is no visible cut when a cycle wraps; see
 * `src/styles/cyber-live-backdrop.css` for the two allowed shapes and why.
 *
 * All motion is CSS on the compositor (transform / opacity), so there is no canvas, no rAF loop, no
 * asset to download, and no work at all while the tab is hidden. `prefers-reduced-motion` is honored
 * globally by index.css, which lands this on the composed still image.
 */
export default function CyberLiveBackdrop({ className = '' }) {
  return (
    <div className={`wm-cyber-backdrop ${className}`.trim()} aria-hidden data-testid="cyber-live-backdrop">
      <div className="wm-cbg-aurora wm-cbg-aurora--cyan" />
      <div className="wm-cbg-aurora wm-cbg-aurora--indigo" />
      <div className="wm-cbg-aurora wm-cbg-aurora--teal" />
      <div className="wm-cbg-grid" />
      <div className="wm-cbg-floor">
        <div className="wm-cbg-floor-plane" />
      </div>
      <div className="wm-cbg-rain wm-cbg-rain--far" />
      <div className="wm-cbg-rain wm-cbg-rain--near" />
      <div className="wm-cbg-sweep" />
      <div className="wm-cbg-radar" />
      <div className="wm-cbg-motes" />
      <div className="wm-cbg-breath" />
      <div className="wm-cbg-grain" />
      <div className="wm-cbg-vignette" />
    </div>
  )
}
