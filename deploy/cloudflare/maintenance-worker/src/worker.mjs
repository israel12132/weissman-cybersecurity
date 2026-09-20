/*
 * Weissman maintenance Worker — the Cloudflare edge layer of the continuity page.
 *
 * Why an edge Worker at all: nginx, Caddy and the Kubernetes default backend can only
 * answer while the machine that runs them is up. When the whole host is off (power,
 * reboot, hosting maintenance, a dead uplink) Cloudflare shows its own 521/522 page.
 * This Worker runs on Cloudflare's edge in front of the origin and answers with the
 * branded page instead, so a visitor never sees a Cloudflare or browser error.
 *
 * Automatic by design — nothing to switch on:
 *   - every request is handed to the origin exactly as it arrived (fetch(request));
 *   - a healthy answer is returned as the very same Response object: nothing is
 *     buffered or rewritten, so streaming, caching and large downloads behave as if
 *     the Worker were not there;
 *   - the page appears only when the origin cannot answer: fetch() throws, the origin
 *     answers 502/503/504, or Cloudflare reports 52x/530 (origin refused, timed out,
 *     TLS failed, DNS failed — the statuses it would otherwise render as its own error
 *     page). An answer that already carries X-Weissman-Maintenance was branded by a
 *     layer behind us (nginx / Caddy / ingress) and is passed through untouched;
 *   - the page's own script (/maintenance/maintenance.js) and api.json are served from
 *     this bundle while the origin is failing, because the page needs them and the
 *     origin cannot provide them. The script must be a genuine 200: browsers refuse
 *     to run a script that arrives with a 5xx status;
 *   - the visitor's page polls /api/health; the first genuine 200 from the origin
 *     passes straight through and the page reloads the original URL. The way back
 *     is automatic too.
 *
 * Announced windows (optional extra, off by default): MAINTENANCE_MODE = "on" answers
 * every request with the page without contacting the origin, and MAINTENANCE_REASON /
 * MAINTENANCE_UNTIL feed the "Planned maintenance" block through /maintenance/status.json.
 * Nothing depends on it; see README.md.
 *
 * Contract shared with the other layers (deploy/maintenance/README.md): HTTP 503 +
 * Retry-After: 30 + Cache-Control: no-store + X-Weissman-Maintenance: 1, the Hebrew
 * page under /he, JSON for /api/, /hooks/ and Accept: application/json, JSON for every
 * method other than GET/HEAD (a POST never gets HTML), no body on HEAD, and a CSP that
 * allows exactly what the page uses: one same-origin script, the inline <style>, data:
 * fonts and favicon, fetch to /api/health.
 *
 * Zero dependencies; the assets come from ../assets.generated.mjs, written by
 * `node deploy/maintenance/build.mjs` (never edited by hand).
 */

import { HTML_EN, HTML_HE, MAINTENANCE_JS, API_JSON } from '../assets.generated.mjs';

export const MAINTENANCE_HEADER = 'X-Weissman-Maintenance';
export const RETRY_AFTER_SECONDS = 30;

// Origin answers that mean "the origin cannot serve this right now". 502/503/504 come
// from a gateway or the app itself; 520–526 and 530 are Cloudflare's own verdicts on a
// failed origin connection, which a Worker's fetch() reports as a normal Response
// rather than an exception. 527 (Railgun) is retired and never produced any more.
export const ORIGIN_FAILURE_STATUSES = Object.freeze([502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 530]);
const FAILURE = new Set(ORIGIN_FAILURE_STATUSES);

export const SCRIPT_PATH = '/maintenance/maintenance.js';
export const STATUS_PATH = '/maintenance/status.json';

// Same policy as the Caddy and Kubernetes layers: the page is the only thing this
// response can contain, so the policy names exactly its needs and nothing more.
export const CONTENT_SECURITY_POLICY =
  "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; " +
  "font-src data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

// Defence-in-depth headers the origin normally adds (deploy/nginx-security-headers.inc).
// While the origin is failing this Worker is the only source of them.
const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy': CONTENT_SECURITY_POLICY,
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=(), midi=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'X-Robots-Tag': 'noindex, nofollow',
});

// Every branded answer: machines read a temporary failure (uptime monitors, crawlers,
// the Command Center's isMaintenanceResponse), nothing keeps a copy, and the layers in
// front of us — there are none, but the header contract is the same everywhere — read
// "already branded".
const MAINTENANCE_HEADERS = Object.freeze({
  'Retry-After': String(RETRY_AFTER_SECONDS),
  'Cache-Control': 'no-store',
  [MAINTENANCE_HEADER]: '1',
  'Vary': 'Accept, Accept-Language',
});

const HE_PATH = /^\/he(?:\/|$)/;
const JSON_PATH = /^\/(?:api|hooks)(?:\/|$)/;

/** MAINTENANCE_MODE is a string variable in wrangler.toml; only "on" (any case) announces a window. */
export function isMaintenanceMode(env) {
  const v = env && env.MAINTENANCE_MODE;
  return typeof v === 'string' && v.trim().toLowerCase() === 'on';
}

/**
 * Accept-Language → Hebrew?  The list is honoured in the visitor's order of preference
 * (q-values, ties keep the listed order): "he", "he-IL,en;q=0.8" and "en;q=0.5,he" are
 * Hebrew; "en-US,en;q=0.9,he;q=0.8" prefers English and gets it. "iw" is the legacy
 * tag for Hebrew that some platforms still send.
 */
export function acceptsHebrew(acceptLanguage) {
  if (typeof acceptLanguage !== 'string' || !acceptLanguage) { return false; }
  let best = null;
  for (const part of acceptLanguage.split(',')) {
    const [tagRaw, ...params] = part.split(';');
    const tag = tagRaw.trim().toLowerCase();
    if (!tag || tag === '*') { continue; }
    let q = 1;
    for (const p of params) {
      const m = /^\s*q\s*=\s*([0-9.]+)\s*$/.exec(p);
      if (m) { q = Number(m[1]); if (!Number.isFinite(q)) { q = 0; } }
    }
    if (q <= 0) { continue; }
    const primary = tag.split('-')[0];
    const lang = (primary === 'he' || primary === 'iw') ? 'he' : (primary === 'en' ? 'en' : null);
    if (lang && (best === null || q > best.q)) { best = { lang, q }; }
  }
  return best !== null && best.lang === 'he';
}

/** Locale of the page to serve: the /he path prefix wins, then Accept-Language. */
export function localeFor(request, pathname) {
  if (HE_PATH.test(pathname)) { return 'he'; }
  return acceptsHebrew(request.headers.get('Accept-Language')) ? 'he' : 'en';
}

/** API-shaped request: /api/…, /hooks/…, or a client that asked for JSON. */
export function wantsJson(request, pathname) {
  if (JSON_PATH.test(pathname)) { return true; }
  const accept = request.headers.get('Accept') || '';
  return accept.toLowerCase().includes('application/json');
}

/**
 * The status.json body for an announced window, or null when none is announced.
 * The page shows the reason (collapsed, capped at 240 characters) and a localized
 * "expected back by"; an unparsable MAINTENANCE_UNTIL becomes null rather than a wrong
 * time, and the value is re-emitted as ISO-8601 UTC so the page never guesses a zone.
 */
export function plannedStatus(env) {
  if (!isMaintenanceMode(env)) { return null; }
  const reasonRaw = typeof env.MAINTENANCE_REASON === 'string' ? env.MAINTENANCE_REASON : '';
  const reason = reasonRaw.replace(/\s+/g, ' ').trim().slice(0, 240) || null;
  let until = null;
  const untilRaw = typeof env.MAINTENANCE_UNTIL === 'string' ? env.MAINTENANCE_UNTIL.trim() : '';
  if (untilRaw) {
    const ms = Date.parse(untilRaw);
    if (Number.isFinite(ms)) { until = new Date(ms).toISOString(); }
  }
  return { mode: 'planned', reason, until };
}

/** True when the origin's answer must be replaced by the page. */
export function isOriginFailure(response) {
  return FAILURE.has(response.status) && !response.headers.has(MAINTENANCE_HEADER);
}

function build(request, status, body, contentType, extraHeaders, statusText) {
  const headers = new Headers();
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) { headers.set(k, v); }
  for (const [k, v] of Object.entries(extraHeaders)) { headers.set(k, v); }
  headers.set('Content-Type', contentType);
  // HEAD gets the same status and headers and no body (RFC 9110 §9.3.2).
  const head = request.method.toUpperCase() === 'HEAD';
  return new Response(head ? null : body, statusText ? { status, statusText, headers } : { status, headers });
}

/**
 * The answer given in place of a failing origin (or for every request while a window
 * is announced). Decided in this order:
 *   1. anything other than GET/HEAD → JSON 503 (an HTML page is meaningless to a client
 *      that just POSTed, and must never be mistaken for a successful upload);
 *   2. /maintenance/maintenance.js → the script, 200;
 *   3. /maintenance/status.json → the announced window (200) or 404 = nothing announced;
 *   4. API-shaped request → api.json, 503;
 *   5. otherwise the page in the visitor's locale, 503.
 */
export function maintenanceResponse(request, env) {
  const method = request.method.toUpperCase();
  const pathname = new URL(request.url).pathname;
  const json = 'application/json; charset=utf-8';

  if (method !== 'GET' && method !== 'HEAD') {
    return build(request, 503, API_JSON, json, MAINTENANCE_HEADERS, 'Service Unavailable');
  }
  if (pathname === SCRIPT_PATH) {
    return build(request, 200, MAINTENANCE_JS, 'application/javascript; charset=utf-8', { 'Cache-Control': 'no-cache' });
  }
  if (pathname === STATUS_PATH) {
    const planned = plannedStatus(env);
    return planned
      ? build(request, 200, JSON.stringify(planned) + '\n', json, { 'Cache-Control': 'no-store' })
      : build(request, 404, '{"mode":"ok"}\n', json, { 'Cache-Control': 'no-store' }, 'Not Found');
  }
  if (wantsJson(request, pathname)) {
    return build(request, 503, API_JSON, json, MAINTENANCE_HEADERS, 'Service Unavailable');
  }
  const html = localeFor(request, pathname) === 'he' ? HTML_HE : HTML_EN;
  return build(request, 503, html, 'text/html; charset=utf-8', MAINTENANCE_HEADERS, 'Service Unavailable');
}

/**
 * The whole decision for one request. Exported (and pure with respect to the global
 * fetch) so the tests can drive it with a mocked origin.
 */
export async function handleRequest(request, env = {}) {
  // A WebSocket (or any Upgrade) handshake cannot be answered with a page: the client
  // expects a 101 or nothing. Hand it to the origin and return whatever comes back.
  if (request.headers.get('Upgrade')) {
    return fetch(request);
  }

  if (isMaintenanceMode(env)) {
    return maintenanceResponse(request, env);
  }

  let response;
  try {
    response = await fetch(request);
  } catch (err) {
    // Cloudflare normally reports a dead origin as a 52x Response; an exception here
    // is the rarer internal failure. Same answer for the visitor.
    return maintenanceResponse(request, env);
  }

  return isOriginFailure(response) ? maintenanceResponse(request, env) : response;
}

export default {
  fetch(request, env, ctx) {
    // If this Worker ever throws, Cloudflare proxies the request to the origin as though
    // the Worker did not exist instead of rendering a Cloudflare 1101 page — the visitor
    // is never worse off for the Worker being there.
    if (ctx && typeof ctx.passThroughOnException === 'function') { ctx.passThroughOnException(); }
    return handleRequest(request, env || {});
  },
};
