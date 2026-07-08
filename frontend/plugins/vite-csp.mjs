/**
 * Injects a Content-Security-Policy meta tag into index.html at build time.
 *
 * Only applied for production builds — Vite's dev server relies on inline
 * scripts, `eval`, and a websocket for HMR, which a strict `script-src 'self'`
 * would break. The production bundle has no inline scripts (the only entry is
 * an external module), so `'self'` is safe there.
 *
 * Directive notes:
 *  - script-src 'self'            → bundled assets only; blocks injected <script>.
 *  - style-src 'self' 'unsafe-inline' → the app uses React inline `style={{}}`
 *    and libraries (framer-motion, recharts) that inject <style>; inline styles
 *    cannot execute script, so this does not reintroduce an XSS sink.
 *  - font-src 'self'              → fonts are self-hosted under /fonts.
 *  - img-src 'self' data: blob:   → charts/maps, favicon SVG, generated blobs.
 *  - connect-src 'self' https: wss: ws: → the API origin is configurable at
 *    runtime (VITE_API_BASE_URL / window.__WEISSMAN_API_BASE__) and the app
 *    opens websockets, so the network scheme allow-list is intentionally broad
 *    while still blocking non-network exfiltration schemes.
 *  - worker-src 'self' blob:      → the battlespace force-simulation web worker.
 *  - object-src 'none', base-uri 'self', form-action 'self' → hardening.
 *
 * `frame-ancestors` and report directives are ignored in a <meta> CSP; set
 * those as real response headers at the deploy/proxy layer for clickjacking
 * protection and violation reporting.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data: blob:",
  "connect-src 'self' https: wss: ws:",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ')

export default function cspPlugin() {
  return {
    name: 'weissman-csp',
    apply: 'build',
    transformIndexHtml() {
      return [
        {
          tag: 'meta',
          attrs: { 'http-equiv': 'Content-Security-Policy', content: CSP },
          injectTo: 'head-prepend',
        },
      ]
    },
  }
}
