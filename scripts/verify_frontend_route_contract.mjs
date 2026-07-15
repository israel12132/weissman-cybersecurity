#!/usr/bin/env node
// verify_frontend_route_contract.mjs — fail if the frontend references an
// `/api/...` path that no backend route serves. Prevents the class of drift where
// a renamed/removed endpoint silently 404s only the client.
//
//   node scripts/verify_frontend_route_contract.mjs
//
// Matching is segment-aware and param-agnostic: backend `:id` and frontend
// `${...}` / `:id` both normalize to a wildcard segment. A frontend path is OK if
// it equals a backend route OR is a segment-prefix of one (base paths built by
// string concatenation) OR a backend route is a segment-prefix of it (client
// appends a dynamic sub-path/query at runtime).

import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// Frontend base paths that are completed dynamically at runtime (concatenation
// with a computed suffix). Matched as prefixes; listed here to document intent.
const DYNAMIC_PREFIX_ALLOW = ['/api/'];

function sh(cmd) {
  return execSync(cmd, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

// Split into path segments, normalizing any param/interpolation to '*'.
function segs(p) {
  return p
    .replace(/\?.*$/, '') // drop query
    .replace(/#.*$/, '')
    .replace(/\/+$/, '') // drop trailing slash
    .split('/')
    .filter(Boolean)
    .map((s) => (/^:|\$\{|^\*$/.test(s) || s.includes('${') ? '*' : s));
}

// Does `a` (segments) match `b` (segments) treating '*' as a wildcard segment,
// allowing either to be a prefix of the other.
function segMatch(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] === '*' || b[i] === '*') continue;
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// --- backend routes ---
const routeFiles = sh(
  "grep -rl '\\.route(' fingerprint_engine/src/http 2>/dev/null || true"
)
  .split('\n')
  .filter(Boolean);
const backend = [];
for (const f of routeFiles) {
  const txt = readFileSync(join(ROOT, f), 'utf8');
  for (const m of txt.matchAll(/\.route\(\s*"([^"]+)"/g)) {
    if (m[1].startsWith('/api/') || m[1].startsWith('/ws/')) backend.push(segs(m[1]));
  }
}

// --- frontend /api references ---
// Only call-argument positions: `apiFetch('/api/..')`, `fetch(`/api/..`)`, etc.
// This deliberately excludes example/target paths that live in arrays
// (`['/api/me', ...]`) or placeholder props (`placeholder:'/api/env'`) inside the
// security-lab UIs — those are scan inputs, not calls to our own backend.
const feRaw = sh(
  "grep -rhoE --exclude='*.test.*' --exclude='*.spec.*' \"\\(\\s*['\\\"\\`]/api/[a-zA-Z0-9_./:$?{}-]+\" frontend/src 2>/dev/null | sort -u || true"
)
  .split('\n')
  .filter(Boolean)
  .map((s) => s.replace(/^\(\s*['"`]/, ''));

const unique = [...new Set(feRaw)];
const missing = [];
for (const raw of unique) {
  const p = segs(raw);
  if (p.length <= 1) continue; // just "/api" — dynamic base, skip
  if (DYNAMIC_PREFIX_ALLOW.some((pre) => raw === pre || raw.startsWith(pre) && p.length === 1)) {
    continue;
  }
  const ok = backend.some((r) => segMatch(p, r));
  if (!ok) missing.push(raw);
}

console.log(
  `Frontend↔backend route contract: ${unique.length} frontend /api refs vs ${backend.length} backend routes.`
);
if (missing.length) {
  console.error(`\n❌ ${missing.length} frontend /api path(s) have no matching backend route:`);
  for (const m of missing) console.error(`   ${m}`);
  console.error('\nEither the endpoint was renamed/removed, or add the route. (Params are wildcarded.)');
  process.exit(1);
}
console.log('✅ every frontend /api reference resolves to a registered route.');
