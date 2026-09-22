#!/usr/bin/env node
/**
 * verify_env_secrets.mjs — validate a Weissman .env WITHOUT ever printing secret values.
 *
 * Checks presence, length, and format for every known key, flags values that are still
 * the .env.example placeholder or an obvious weak default, and exits non-zero if any
 * REQUIRED key fails. It prints only booleans / lengths / PASS·WARN·FAIL — never a value.
 *
 *   node scripts/verify_env_secrets.mjs                 # validates ./.env
 *   node scripts/verify_env_secrets.mjs /path/to/.env   # validates a specific file
 *
 * Safe to run on a production host: nothing leaves the process, no secret is echoed.
 */
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const target = process.argv[2] || join(ROOT, '.env')

function parseEnv(text) {
  const out = {}
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim()
    if (!s || s.startsWith('#')) continue
    const eq = s.indexOf('=')
    if (eq < 0) continue
    const k = s.slice(0, eq).trim().replace(/^export\s+/, '')
    let v = s.slice(eq + 1).trim()
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1)
    out[k] = v
  }
  return out
}

// Placeholder values shipped in .env.example — a real .env must not still use them.
const examples = existsSync(join(ROOT, '.env.example'))
  ? parseEnv(readFileSync(join(ROOT, '.env.example'), 'utf8'))
  : {}
const WEAK = new Set(['changeme', 'change-me', 'password', 'secret', 'admin', 'test', 'example', 'placeholder', 'your-secret-here'])

const RULES = [
  // key, required, checkFn(v) -> null | 'reason'
  ['DATABASE_URL', true, (v) => (/^postgres(ql)?:\/\/.+@.+\/.+/.test(v) ? null : 'not a postgres://user@host/db URL')],
  ['REDIS_URL', true, (v) => (/^rediss?:\/\/.+/.test(v) ? null : 'not a redis:// URL')],
  ['WEISSMAN_JWT_SECRET', true, (v) => (v.length >= 48 ? null : `must be ≥48 chars (is ${v.length})`)],
  ['WEISSMAN_ADMIN_EMAIL', true, (v) => (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v) ? null : 'not a valid email')],
  ['WEISSMAN_ADMIN_PASSWORD', true, (v) => (v.length >= 12 ? null : `should be ≥12 chars (is ${v.length})`)],
  ['WEISSMAN_JOB_ORCHESTRATOR_SECRET', false, (v) => (v.length >= 32 ? null : `must be ≥32 chars or job signing disables (is ${v.length})`)],
  ['WEISSMAN_METRICS_TOKEN', false, (v) => (v.length >= 32 ? null : `must be ≥32 chars (is ${v.length})`)],
  ['WEISSMAN_MIGRATE_URL', false, (v) => (/^postgres(ql)?:\/\//.test(v) ? null : 'not a postgres:// URL')],
  ['WEISSMAN_AUTH_DATABASE_URL', false, (v) => (/^postgres(ql)?:\/\//.test(v) ? null : 'not a postgres:// URL')],
  ['WEISSMAN_INTEL_DATABASE_URL', false, (v) => (/^postgres(ql)?:\/\//.test(v) ? null : 'not a postgres:// URL')],
  ['WEISSMAN_ANALYTICS_DATABASE_URL', false, (v) => (/^postgres(ql)?:\/\//.test(v) ? null : 'not a postgres:// URL')],
  ['WEISSMAN_WORKER_DATABASE_URL', false, (v) => (/^postgres(ql)?:\/\//.test(v) ? null : 'not a postgres:// URL')],
  ['WEISSMAN_READ_ONLY_DATABASE_URL', false, (v) => (/^postgres(ql)?:\/\//.test(v) ? null : 'not a postgres:// URL')],
  ['WEISSMAN_ADMIN_BCRYPT', false, (v) => (/^\$2[aby]\$\d\d\$/.test(v) ? null : 'not a bcrypt hash')],
  ['WEISSMAN_MASTER_BOOTSTRAP_BCRYPT', false, (v) => (/^\$2[aby]\$\d\d\$/.test(v) ? null : 'not a bcrypt hash')],
  ['WEISSMAN_CF_API_TOKEN', false, (v) => (v.length >= 30 ? null : `Cloudflare token looks short (is ${v.length})`)],
  ['WEISSMAN_CF_ZONE_ID', false, (v) => (/^[0-9a-f]{32}$/i.test(v) ? null : 'Cloudflare zone id should be 32 hex chars')],
  ['WEISSMAN_OAST_API_KEY', false, (v) => (v.length >= 16 ? null : `should be ≥16 chars (is ${v.length})`)],
  ['WEISSMAN_OAST_BASE_DOMAIN', false, (v) => (/\./.test(v) ? null : 'not a domain')],
  ['WEISSMAN_COOKIE_SECURE', false, (v) => (/^(true|false|1|0)$/i.test(v) ? null : 'expected true/false')],
  ['WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD', false, (v) => (/^(false|0)$/i.test(v) ? null : 'PROD RISK: should be false/unset in production')],
  ['WEISSMAN_AGENT_TLS_PIN_SHA256', false, (v) => (/^[0-9a-f]{64}$/i.test(v) ? null : 'expected 64 hex chars (sha256)')],
]

if (!existsSync(target)) {
  console.error(`\n✖ No .env found at ${target}`)
  console.error('  Pass the path explicitly:  node scripts/verify_env_secrets.mjs /etc/weissman/.env\n')
  process.exit(2)
}

const env = parseEnv(readFileSync(target, 'utf8'))
const pad = (s, n) => String(s).padEnd(n)
let failures = 0
let warnings = 0

console.log(`\n  Weissman .env validation — ${target}`)
console.log('  (values are never printed; only presence · length · format)\n')
console.log('  ' + pad('KEY', 38) + pad('REQ', 6) + pad('PRESENT', 9) + pad('LEN', 6) + 'RESULT')
console.log('  ' + '─'.repeat(86))

for (const [key, required, check] of RULES) {
  const present = key in env && env[key].length > 0
  const v = present ? env[key] : ''
  let result, tag
  if (!present) {
    if (required) { result = 'MISSING (required)'; tag = 'FAIL'; failures++ }
    else { result = 'not set (optional)'; tag = '·' }
  } else if (examples[key] !== undefined && v === examples[key]) {
    result = 'still the .env.example placeholder'; tag = required ? 'FAIL' : 'WARN'
    if (required) failures++; else warnings++
  } else if (WEAK.has(v.toLowerCase())) {
    result = 'weak / common value'; tag = 'FAIL'; failures++
  } else {
    const reason = check(v)
    if (reason) { result = reason; tag = /PROD RISK|short/i.test(reason) && !required ? 'WARN' : 'FAIL'; if (tag === 'FAIL') failures++; else warnings++ }
    else { result = 'ok'; tag = 'PASS' }
  }
  const mark = tag === 'PASS' ? '✓ PASS' : tag === 'FAIL' ? '✗ FAIL' : tag === 'WARN' ? '! WARN' : '  —'
  console.log('  ' + pad(key, 38) + pad(required ? 'yes' : 'opt', 6) + pad(present ? 'yes' : 'no', 9) + pad(present ? v.length : '', 6) + mark + '  ' + result)
}

console.log('  ' + '─'.repeat(86))
console.log(`  ${failures} failing · ${warnings} warnings\n`)
if (failures > 0) {
  console.error('✖ Fix the FAIL rows before production. Regenerate strong secrets, e.g.:')
  console.error('    openssl rand -base64 48   # WEISSMAN_JWT_SECRET (≥48)')
  console.error('    openssl rand -base64 32   # orchestrator / metrics (≥32)\n')
  process.exit(1)
}
console.log('✓ All required keys present and valid.\n')
