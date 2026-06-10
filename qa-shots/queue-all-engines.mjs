#!/usr/bin/env node
/**
 * Queue ALL production engines against testphp.vulnweb.com (client 3).
 * Uses /api/engines list + POST /api/command-center/scan per engine.
 */
const BASE = process.env.WEISSMAN_BASE || 'http://localhost'
const EMAIL = process.env.WEISSMAN_EMAIL || 'admin@localhost'
const PASSWORD = process.env.WEISSMAN_PASSWORD || 'QaTest2026!'
const CLIENT_ID = Number(process.env.WEISSMAN_CLIENT_ID || 3)
const TARGET = process.env.WEISSMAN_TARGET || 'https://testphp.vulnweb.com'
const DELAY_MS = Number(process.env.WEISSMAN_ENGINE_DELAY_MS || 200)

async function login() {
  const r = await fetch(`${BASE}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD, tenant_slug: 'default' }),
  })
  const j = await r.json()
  if (!j.access_token) throw new Error('login failed: ' + JSON.stringify(j))
  return j.access_token
}

async function main() {
  const token = await login()
  const h = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }

  const engRes = await fetch(`${BASE}/api/engines/production`, { headers: h })
  const body = await engRes.json()
  const ids = Array.isArray(body?.production)
    ? body.production
    : Array.isArray(body)
      ? body.map((e) => (typeof e === 'string' ? e : e.id)).filter(Boolean)
      : []
  if (!ids.length) throw new Error('no engines from /api/engines')

  console.log(`Queuing ${ids.length} production engines → ${TARGET} (client ${CLIENT_ID})`)

  let queued = 0
  let skipped = 0
  const errors = []

  for (const engine of ids) {
    const r = await fetch(`${BASE}/api/command-center/scan`, {
      method: 'POST',
      headers: h,
      body: JSON.stringify({ engine, target: TARGET, client_id: CLIENT_ID }),
    })
    const j = await r.json().catch(() => ({}))
    if (r.status === 202 || j.job_id) {
      queued++
      if (queued % 25 === 0) console.log(`  … ${queued} queued`)
    } else {
      skipped++
      if (errors.length < 10) errors.push({ engine, status: r.status, detail: j.detail || j.code })
    }
    await new Promise((res) => setTimeout(res, DELAY_MS))
  }

  console.log(`Done: queued=${queued} skipped=${skipped}`)
  if (errors.length) console.log('Sample skips:', errors)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
