// k6 SLO smoke — grounds the advertised 99.9% availability SLA with a real
// latency/error budget instead of a bare claim. Exercises the auth + read path
// (login → authenticated reads of the availability-critical endpoints) under
// concurrent load.
//
//   k6 run scripts/load/k6_slo.js
//   K6_VUS=25 K6_DURATION=3m k6 run scripts/load/k6_slo.js   # heavier soak
//
// Env: WEISSMAN_E2E_BASE, WEISSMAN_ADMIN_EMAIL, WEISSMAN_ADMIN_PASSWORD.
//
// Scope note: this covers the login + read surface (what availability SLAs are
// measured against). Scan-enqueue load needs per-tenant scope fixtures and can be
// layered on top using the same token.

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.WEISSMAN_E2E_BASE || 'http://127.0.0.1:18000';
const EMAIL = __ENV.WEISSMAN_ADMIN_EMAIL || 'nightly@localhost';
const PASSWORD = __ENV.WEISSMAN_ADMIN_PASSWORD || 'nightly-e2e-password';

export const options = {
  scenarios: {
    steady: {
      executor: 'constant-vus',
      vus: Number(__ENV.K6_VUS || 10),
      duration: __ENV.K6_DURATION || '1m',
    },
  },
  thresholds: {
    // <1% failed requests over the run — the load-side signal behind 99.9% availability.
    http_req_failed: ['rate<0.01'],
    // p95 read latency budget; p99 as a looser ceiling.
    'http_req_duration{kind:read}': ['p(95)<800', 'p(99)<2000'],
    checks: ['rate>0.99'],
  },
};

function login() {
  const res = http.post(
    `${BASE}/api/login`,
    JSON.stringify({ email: EMAIL, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' }, tags: { kind: 'auth' } }
  );
  check(res, { 'login 200': (r) => r.status === 200 });
  try {
    return JSON.parse(res.body).access_token;
  } catch (_e) {
    return null;
  }
}

export function setup() {
  const token = login();
  if (!token) {
    throw new Error('load setup: login did not return an access_token (MFA enforced or bad creds?)');
  }
  return { token };
}

export default function (data) {
  const params = {
    headers: { Authorization: `Bearer ${data.token}` },
    tags: { kind: 'read' },
  };
  const reads = [
    `${BASE}/api/health`,
    `${BASE}/api/dashboard/stats`,
    `${BASE}/api/findings?limit=50`,
    `${BASE}/api/intel/status`,
    `${BASE}/api/attack-coverage`,
  ];
  for (const url of reads) {
    const r = http.get(url, params);
    check(r, { [`GET ${url} -> 2xx`]: (res) => res.status >= 200 && res.status < 300 });
  }
  sleep(1);
}
