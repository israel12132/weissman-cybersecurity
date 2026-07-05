#!/usr/bin/env node
import fs from 'node:fs'

const base = process.env.WEISSMAN_BASE
const token = process.env.WEISSMAN_TOKEN
const out = process.env.OUT_FILE
const ids = (process.env.CRITICAL_IDS || '').split(',').map(Number).filter(Boolean)

if (!base || !token || !out || !ids.length) {
  console.error('WEISSMAN_BASE, WEISSMAN_TOKEN, OUT_FILE, CRITICAL_IDS required')
  process.exit(1)
}

const result = { verified_at: new Date().toISOString(), findings: [] }
for (const id of ids) {
  const r = await fetch(`${base}/api/findings/${id}/verify`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ deep: false }),
  })
  const body = await r.json().catch(() => ({}))
  result.findings.push({ id, http_status: r.status, ...body })
}
fs.writeFileSync(out, JSON.stringify(result, null, 2))
