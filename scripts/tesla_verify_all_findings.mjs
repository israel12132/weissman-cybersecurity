#!/usr/bin/env node
/** Live-verify every Tesla finding without a verdict yet. */
import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const LOG = process.env.TESLA_VERIFY_LOG || '/tmp/weissman-tesla-verify-all.jsonl'
const BASE = (process.env.WEISSMAN_E2E_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '')
const CLIENT_ID = 4
const VALID_VERDICTS = new Set([
  'CONFIRMED',
  'LIKELY_VALID',
  'INCONCLUSIVE',
  'NOISE',
  'FALSE_POSITIVE',
  'VERIFY_TIMEOUT',
])

function loadDotEnv() {
  const p = path.join(root, '.env')
  if (!fs.existsSync(p)) return
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const t = line.trim()
    if (!t || t.startsWith('#')) continue
    const i = t.indexOf('=')
    if (i < 1) continue
    const k = t.slice(0, i)
    const v = t.slice(i + 1)
    if (process.env[k] == null || process.env[k] === '') process.env[k] = v
  }
}
loadDotEnv()

function log(row) {
  fs.appendFileSync(LOG, `${JSON.stringify({ ts: new Date().toISOString(), ...row })}\n`)
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

async function req(method, urlPath, { body, token, timeoutMs = 60_000 } = {}) {
  const headers = { Accept: 'application/json' }
  if (body != null) headers['Content-Type'] = 'application/json'
  if (token) headers.Authorization = `Bearer ${token}`
  const r = await fetch(`${BASE}${urlPath}`, {
    method,
    headers,
    body: body != null ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  })
  const data = await r.json().catch(() => ({}))
  return { status: r.status, data }
}

async function safeReq(label, fn) {
  try {
    return await fn()
  } catch (e) {
    return { error: String(e?.message || e), label }
  }
}

async function login() {
  const loginRes = await req('POST', '/api/login', {
    body: {
      email: process.env.WEISSMAN_ADMIN_EMAIL,
      password: process.env.WEISSMAN_ADMIN_PASSWORD,
      tenant_slug: 'default',
    },
    timeoutMs: 30_000,
  })
  const token = loginRes.data?.access_token
  if (loginRes.status !== 200 || !token) {
    throw new Error(`login failed HTTP ${loginRes.status}`)
  }
  return token
}

function hasValidVerdict(f) {
  const v = f.live_verdict || f.live_verification?.verdict
  return v && VALID_VERDICTS.has(String(v))
}

async function verifyFinding(id, token, deep = false) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const vr = await req('POST', `/api/findings/${id}/verify`, {
        token,
        body: { deep },
        timeoutMs: 120_000,
      })
      if (vr.status === 401 || vr.status === 403) {
        token = await login()
        continue
      }
      if (vr.status === 429) {
        await sleep(3000 * (attempt + 1))
        continue
      }
      if (vr.status >= 500) {
        await sleep(2000 * (attempt + 1))
        continue
      }
      const verdict = vr.data?.verdict
      if (verdict && VALID_VERDICTS.has(String(verdict))) {
        return { token, verdict, confidence: vr.data?.confidence, http: vr.status }
      }
      if (vr.status === 200 && verdict) {
        return { token, verdict, confidence: vr.data?.confidence, http: vr.status }
      }
      if (attempt < 2) await sleep(2000)
    } catch (e) {
      if (attempt === 2) {
        return { token, verdict: 'VERIFY_TIMEOUT', error: String(e?.message || e) }
      }
      await sleep(3000)
    }
  }
  return { token, verdict: 'VERIFY_TIMEOUT', error: 'exhausted retries' }
}

async function main() {
  let token = await login()

  let offset = 0
  const limit = 100
  let verified = 0
  let skipped = 0
  let retried = 0
  const verdicts = {}

  while (true) {
    const listRes = await safeReq('list', () =>
      req('GET', `/api/findings?client_id=${CLIENT_ID}&limit=${limit}&offset=${offset}`, {
        token,
        timeoutMs: 45_000,
      }),
    )
    if (listRes?.error) {
      console.error('\nlist failed:', listRes.error)
      log({ phase: 'list_error', offset, error: listRes.error })
      await sleep(5000)
      token = await login()
      continue
    }
    if (listRes.status === 401) {
      token = await login()
      continue
    }
    const rows = listRes.data?.findings || []
    if (!rows.length) break

    for (const f of rows) {
      const id = f.raw_id || f.id
      if (hasValidVerdict(f)) {
        skipped++
        const v = f.live_verdict || f.live_verification?.verdict
        verdicts[v] = (verdicts[v] || 0) + 1
        continue
      }
      const out = await verifyFinding(id, token, false)
      token = out.token
      if (out.error && out.verdict === 'VERIFY_TIMEOUT') retried++
      const v = out.verdict || 'VERIFY_TIMEOUT'
      verdicts[v] = (verdicts[v] || 0) + 1
      verified++
      log({
        id,
        title: (f.title || '').slice(0, 100),
        verdict: v,
        confidence: out.confidence,
        error: out.error,
      })
      process.stdout.write(
        `\rverified=${verified} skipped=${skipped} timeouts=${verdicts.VERIFY_TIMEOUT || 0}`,
      )
      await sleep(400)
    }
    offset += limit
    if (rows.length < limit) break
  }

  console.log('\nTesla verify-all done:', { verified, skipped, retried, verdicts })
  log({ phase: 'summary', verified, skipped, retried, verdicts })
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
