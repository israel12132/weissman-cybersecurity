#!/usr/bin/env node
/**
 * SOAR playbook E2E contract (dry-run + adapter registry).
 *
 * Usage:
 *   WEISSMAN_SMOKE_BASE_URL=http://127.0.0.1:18000 \
 *   WEISSMAN_SMOKE_LOGIN_EMAIL=admin@localhost \
 *   WEISSMAN_SMOKE_LOGIN_PASSWORD=changeme \
 *     node scripts/verify_soar_playbook_e2e.mjs
 */

const BASE = process.env.WEISSMAN_SMOKE_BASE_URL || 'http://127.0.0.1:18000';
const EMAIL = process.env.WEISSMAN_SMOKE_LOGIN_EMAIL || process.env.WEISSMAN_ADMIN_EMAIL || 'admin@localhost';
const PASSWORD = process.env.WEISSMAN_SMOKE_LOGIN_PASSWORD || process.env.WEISSMAN_ADMIN_PASSWORD || 'changeme';

const REQUIRED_ADAPTERS = [
  'aws_ec2',
  'azure_vm',
  'crowdstrike_falcon',
  'github',
  'pagerduty',
  'opsgenie',
  'slack',
  'servicenow',
];

async function api(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, options);
  const rawText = await response.text();
  let body = rawText;
  try {
    body = rawText ? JSON.parse(rawText) : null;
  } catch {
    /* keep text */
  }
  if (!response.ok) {
    throw new Error(`${path} HTTP ${response.status}: ${typeof body === 'string' ? body : JSON.stringify(body)}`);
  }
  return body;
}

async function login() {
  const res = await api('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const token = res.access_token || res.token;
  if (!token) {
    throw new Error('login did not return access_token');
  }
  return token;
}

async function main() {
  const token = await login();
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const integ = await api('/api/integrations', { headers });
  const adapters = integ.soar_adapters || [];
  const missing = REQUIRED_ADAPTERS.filter((a) => !adapters.includes(a));
  if (missing.length) {
    throw new Error(`Missing SOAR adapters in registry: ${missing.join(', ')}`);
  }
  console.log(`SOAR adapters OK (${adapters.length} registered)`);

  const fire = await api('/api/playbooks/fire', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      dry_run: true,
      event: {
        kind: 'finding_persisted',
        tenant_id: 1,
        client_id: 1,
        finding_id: 1,
        title: 'SOAR E2E contract probe',
        severity: 'critical',
        source: 'soar_e2e',
        target: 'i-test123456789',
        status: 'OPEN',
        cvss: 9.8,
        epss: 0.9,
        kev: true,
        kev_known_ransomware: false,
        internet_exposed: true,
      },
    }),
  });

  if (!fire.ok) {
    throw new Error(`playbook fire failed: ${JSON.stringify(fire)}`);
  }
  console.log('Playbook dry-run fire OK', fire.results?.length ?? 0, 'results');
  console.log('SOAR E2E contract passed (full isolate→verify→revert: cargo test -p fingerprint_engine --test soar_playbook_e2e)');
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
