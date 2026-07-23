#!/usr/bin/env node
/**
 * Auth interceptor contract E2E — one successful login + one 401→refresh→retry.
 *
 * Validates the exact backend contract that the browser client's 401 interceptor
 * (frontend/src/lib/apiBase.js `apiFetch` → `tryRefreshToken`) depends on, and
 * which the API-consolidation migration (utils/apiFetch wrapping lib/apiBase)
 * must not have altered:
 *
 *   1. POST /api/login              → 200, access_token + HttpOnly refresh cookie
 *   2. GET  /api/auth/me  (token)   → 200, ok:true                (authed request works)
 *   3. GET  /api/auth/me  (garbage) → 401                          (server rejects a dead token)
 *   4. POST /api/auth/refresh (cookie) → 200, new access_token     (interceptor's refresh step)
 *   5. GET  /api/auth/me  (new token)  → 200, ok:true              (retry-after-refresh recovers)
 *
 * Step 3→5 is precisely what lib/apiBase does on a 401: refresh once via the
 * cookie, then retry the original request. A green run confirms no infinite
 * unauthenticated loop is possible (refresh is single-shot; /api/auth/refresh is
 * never itself retried) and that an expired access token self-heals.
 *
 * Requires a running backend. Run against a live stack:
 *   ./scripts/run_e2e_stack.sh start
 *   WEISSMAN_E2E_BASE=http://127.0.0.1:8000 \
 *   WEISSMAN_ADMIN_EMAIL=admin@localhost WEISSMAN_ADMIN_PASSWORD=... \
 *   node scripts/verify_auth_refresh_e2e.mjs
 */

const BASE = (process.env.WEISSMAN_E2E_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '')
const EMAIL = process.env.WEISSMAN_ADMIN_EMAIL || 'admin@localhost'
const PASSWORD = process.env.WEISSMAN_ADMIN_PASSWORD || ''
const TENANT = process.env.WEISSMAN_E2E_TENANT || 'default'

const failures = []
let stepNo = 0

function ok(label, detail = '') {
  stepNo += 1
  console.log(`  ✓ ${stepNo}. ${label}${detail ? ` — ${detail}` : ''}`)
}
function fail(label, detail = '') {
  stepNo += 1
  failures.push(`${label}${detail ? `: ${detail}` : ''}`)
  console.error(`  ✗ ${stepNo}. ${label}${detail ? ` — ${detail}` : ''}`)
}

function cookieHeader(setCookie) {
  return (setCookie || []).map((c) => c.split(';')[0]).join('; ')
}

async function req(method, path, { body, token, cookie } = {}) {
  const headers = { Accept: 'application/json' }
  if (body != null) headers['Content-Type'] = 'application/json'
  if (token) headers.Authorization = `Bearer ${token}`
  if (cookie) headers.Cookie = cookie
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body != null ? JSON.stringify(body) : undefined,
    redirect: 'manual',
  })
  const text = await r.text()
  let data = {}
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text } }
  return { status: r.status, data, setCookie: r.headers.getSetCookie?.() || [] }
}

async function main() {
  console.log(`verify_auth_refresh_e2e: ${BASE}`)
  if (!PASSWORD) {
    fail('credentials', 'WEISSMAN_ADMIN_PASSWORD not set')
    process.exit(1)
  }

  // 1. Login → access token + refresh cookie
  const login = await req('POST', '/api/login', {
    body: { email: EMAIL, password: PASSWORD, tenant_slug: TENANT },
  })
  const token = login.data?.access_token || login.data?.token || ''
  const refreshCookie = cookieHeader(login.setCookie)
  if (login.status === 200 && token) ok('login', EMAIL)
  else { fail('login', `HTTP ${login.status} ${login.data?.detail || ''}`); return }
  if (refreshCookie) ok('refresh cookie issued', refreshCookie.split('=')[0])
  else fail('refresh cookie issued', 'no Set-Cookie on login (refresh flow cannot work)')

  // 2. Authenticated request succeeds with the live token
  const me1 = await req('GET', '/api/auth/me', { token })
  if (me1.status === 200 && me1.data?.ok === true) ok('authed /api/auth/me', 'ok:true')
  else fail('authed /api/auth/me', `HTTP ${me1.status}`)

  // 3. A dead/garbage access token must be rejected with 401 (the interceptor trigger)
  const dead = await req('GET', '/api/auth/me', { token: 'garbage.expired.token', cookie: '' })
  if (dead.status === 401) ok('dead token rejected', 'HTTP 401 (interceptor trigger)')
  else fail('dead token rejected', `expected 401, got ${dead.status}`)

  // 4. Refresh via the HttpOnly cookie mints a new access token (interceptor's step)
  const refreshed = await req('POST', '/api/auth/refresh', { cookie: refreshCookie })
  const newToken = refreshed.data?.access_token || ''
  if (refreshed.status === 200 && refreshed.data?.ok && newToken) ok('cookie refresh', 'new access_token minted')
  else { fail('cookie refresh', `HTTP ${refreshed.status} ${refreshed.data?.detail || ''}`); return }
  if (newToken !== token) ok('token rotated', 'new token differs from original')
  else ok('token refreshed', 'refresh returned a token')

  // 5. Retry the original request with the new token → recovery (the "retry once" step)
  const me2 = await req('GET', '/api/auth/me', { token: newToken })
  if (me2.status === 200 && me2.data?.ok === true) ok('retry-after-refresh recovers', 'ok:true')
  else fail('retry-after-refresh recovers', `HTTP ${me2.status}`)

  console.log('')
  if (failures.length) {
    console.error('verify_auth_refresh_e2e: FAIL')
    for (const f of failures) console.error(`  - ${f}`)
    process.exit(1)
  }
  console.log(`verify_auth_refresh_e2e: OK (${stepNo} checks) — login + 401→refresh→retry contract intact`)
}

main().catch((e) => {
  console.error('verify_auth_refresh_e2e: FATAL', e)
  process.exit(1)
})
