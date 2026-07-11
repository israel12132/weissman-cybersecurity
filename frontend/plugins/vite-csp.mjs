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
  // Pinned to same-origin + the one CDN the choropleth map topojson is fetched
  // from (cdn.jsdelivr.net). NOT the broad `https:` scheme — that would let an
  // injected script exfiltrate to any host, defeating the CSP for a security app.
  "connect-src 'self' https://cdn.jsdelivr.net wss: ws:",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ')

/**
 * Security response headers that can only take effect as real HTTP headers
 * (not <meta>). Applied to the dev + preview servers so they're testable here;
 * production should set the same set (plus CSP) at the proxy/CDN layer.
 */
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
}

function securityHeaderMiddleware() {
  return (_req, res, next) => {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v)
    next()
  }
}

export default function cspPlugin() {
  return {
    name: 'weissman-csp',
    // CSP <meta> is injected only for production builds — dev relies on inline
    // scripts/eval for HMR which a strict script-src would break.
    transformIndexHtml: {
      order: 'pre',
      handler(_html, ctx) {
        if (ctx?.server) return [] // dev server: skip the strict CSP meta
        return [
          {
            tag: 'meta',
            attrs: { 'http-equiv': 'Content-Security-Policy', content: CSP },
            injectTo: 'head-prepend',
          },
        ]
      },
    },
    configureServer(server) {
      server.middlewares.use(securityHeaderMiddleware())
    },
    configurePreviewServer(server) {
      server.middlewares.use(securityHeaderMiddleware())
    },
  }
}
