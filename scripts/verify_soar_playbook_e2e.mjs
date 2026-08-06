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

import { retryLogin } from './lib/scan_intake.mjs';

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

// Status-preserving fetch. `api` below throws on any non-2xx, which is the right default for this
// contract's assertions but destroys the one thing a shed response is for: its status and
// Retry-After hint. Callers that must distinguish "shed, retry" from "genuinely failed" go through
// this instead and decide for themselves.
async function apiRaw(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, options);
  const rawText = await response.text();
  let body = rawText;
  try {
    body = rawText ? JSON.parse(rawText) : null;
  } catch {
    /* keep text */
  }
  return { response, body };
}

async function api(path, options = {}) {
  const { response, body } = await apiRaw(path, options);
  if (!response.ok) {
    throw new Error(`${path} HTTP ${response.status}: ${typeof body === 'string' ? body : JSON.stringify(body)}`);
  }
  return body;
}

async function login() {
  const { response, body: res } = await retryLogin(
    () => apiRaw('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
    }),
    { statusOf: (r) => r?.response?.status, retryAfterOf: (r) => r?.body?.retry_after_seconds },
  );
  if (!response.ok) {
    throw new Error(`/api/login HTTP ${response.status}: ${typeof res === 'string' ? res : JSON.stringify(res)}`);
  }
  const token = res.access_token || res.token;
  if (!token) {
    throw new Error('login did not return access_token');
  }
  // The SOAR engine records an execution row whose client_id is a FK to clients(id)
  // (see 20260627150000_soar_action_engine.sql). Firing with a hard-coded id that was
  // never seeded violates that FK, so fire against the *actual* tenant/client ids.
  const tenantId = res.tenant_id;
  if (!tenantId) {
    throw new Error('login did not return tenant_id');
  }
  return { token, tenantId };
}

// Hermetic seed: create the client the playbook fire will reference so the SOAR
// execution's client_id foreign key resolves. Returns the created id.
async function ensureClient(headers) {
  const created = await api('/api/clients', {
    method: 'POST',
    headers,
    body: JSON.stringify({ name: 'SOAR E2E contract probe client' }),
  });
  const clientId = created.id ?? created.client_id;
  if (!clientId) {
    throw new Error(`client create did not return an id: ${JSON.stringify(created)}`);
  }
  return clientId;
}

async function main() {
  const { token, tenantId } = await login();
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const integ = await api('/api/integrations', { headers });
  const adapters = integ.soar_adapters || [];
  const missing = REQUIRED_ADAPTERS.filter((a) => !adapters.includes(a));
  if (missing.length) {
    throw new Error(`Missing SOAR adapters in registry: ${missing.join(', ')}`);
  }
  console.log(`SOAR adapters OK (${adapters.length} registered)`);

  // Seed the tenant/client BEFORE firing so the execution record's client_id FK is
  // satisfied — the check is fully hermetic (no hard-coded id=1).
  const clientId = await ensureClient(headers);
  console.log(`Seeded probe client id=${clientId} (tenant ${tenantId}) for hermetic SOAR fire`);

  const fire = await api('/api/playbooks/fire', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      dry_run: true,
      event: {
        kind: 'finding_persisted',
        tenant_id: tenantId,
        client_id: clientId,
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
