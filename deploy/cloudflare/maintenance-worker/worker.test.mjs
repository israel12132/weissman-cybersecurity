/*
 * Tests for the Weissman maintenance Worker. Zero dependencies: node:test with a mocked
 * global fetch standing in for the origin. Run with
 *   node --test deploy/cloudflare/maintenance-worker/worker.test.mjs
 * (or the glob 'deploy/cloudflare/maintenance-worker/*.test.mjs').
 */

import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import worker, {
  handleRequest,
  maintenanceResponse,
  acceptsHebrew,
  plannedStatus,
  isOriginFailure,
  ORIGIN_FAILURE_STATUSES,
  MAINTENANCE_HEADER,
  CONTENT_SECURITY_POLICY,
} from './src/worker.mjs';
import { HTML_EN, HTML_HE, MAINTENANCE_JS, API_JSON } from './assets.generated.mjs';

const ORIGIN = 'https://weissman.io';
const realFetch = globalThis.fetch;

/** Installs an origin stand-in; returns the list of Requests the Worker sent to it. */
function mockOrigin(impl) {
  const calls = [];
  globalThis.fetch = async (input, init) => {
    calls.push({ input, init });
    return impl(input, init);
  };
  return calls;
}

const originUp = () => new Response('{"ok":true}', { status: 200, headers: { 'Content-Type': 'application/json' } });
const originStatus = (status, headers = {}) => () => new Response(`origin ${status}`, { status, headers });
const originThrows = () => { throw new TypeError('fetch failed: connection refused'); };

const req = (path, init = {}) => new Request(ORIGIN + path, init);

function assertBranded(res, { status = 503 } = {}) {
  assert.equal(res.status, status);
  assert.equal(res.headers.get('Retry-After'), '30');
  assert.equal(res.headers.get('Cache-Control'), 'no-store');
  assert.equal(res.headers.get(MAINTENANCE_HEADER), '1');
  assert.equal(res.headers.get('X-Content-Type-Options'), 'nosniff');
  assert.equal(res.headers.get('X-Frame-Options'), 'DENY');
  assert.equal(res.headers.get('X-Robots-Tag'), 'noindex, nofollow');
  assert.equal(res.headers.get('Content-Security-Policy'), CONTENT_SECURITY_POLICY);
}

afterEach(() => { globalThis.fetch = realFetch; });

describe('pass-through', () => {
  test('a healthy origin answer is returned as the very same Response object', async () => {
    const origin = originUp();
    const calls = mockOrigin(() => origin);
    const request = req('/dashboard?x=1');
    const res = await handleRequest(request, {});
    assert.equal(res, origin, 'same object — nothing buffered or copied');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].input, request, 'the original Request object is what reaches the origin');
    assert.equal(res.bodyUsed, false);
  });

  test('a 200 keeps every header the origin set (nothing rewritten)', async () => {
    const origin = new Response('x', { status: 200, headers: { 'Cache-Control': 'public, max-age=600', 'X-Custom': 'kept' } });
    mockOrigin(() => origin);
    const res = await handleRequest(req('/assets/app.js'), {});
    assert.equal(res.headers.get('Cache-Control'), 'public, max-age=600');
    assert.equal(res.headers.get('X-Custom'), 'kept');
    assert.equal(res.headers.has(MAINTENANCE_HEADER), false);
  });

  test('an origin 503 that already carries X-Weissman-Maintenance passes through unchanged', async () => {
    const origin = new Response('<html>branded by nginx</html>', {
      status: 503, headers: { 'Content-Type': 'text/html', [MAINTENANCE_HEADER]: '1', 'Retry-After': '30' },
    });
    mockOrigin(() => origin);
    const res = await handleRequest(req('/'), {});
    assert.equal(res, origin);
    assert.equal(await res.text(), '<html>branded by nginx</html>');
  });

  test('404 and 500 from the origin are application answers, not outages', async () => {
    for (const status of [400, 401, 404, 429, 500, 501]) {
      const origin = originStatus(status)();
      mockOrigin(() => origin);
      const res = await handleRequest(req('/anything'), {});
      assert.equal(res, origin, `status ${status} must pass through`);
    }
  });

  test('a request carrying an Upgrade header goes straight to fetch(request), never intercepted', async () => {
    // A 502 that would normally be replaced by the page — but a WebSocket handshake
    // cannot be answered with HTML, so the origin's answer is returned as-is.
    const origin = originStatus(502)();
    const calls = mockOrigin(() => origin);
    const request = req('/ws/events', { headers: { Upgrade: 'websocket', Connection: 'Upgrade' } });
    const res = await handleRequest(request, {});
    assert.equal(res, origin);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].input, request);
  });

  test('an Upgrade request bypasses even an announced window', async () => {
    // (undici cannot construct a 101; the Worker returns whatever fetch() yields, so any
    // distinct object proves the hand-off.)
    const origin = new Response(null, { status: 200, headers: { 'X-Origin': 'handshake' } });
    const calls = mockOrigin(() => origin);
    const res = await handleRequest(req('/ws/events', { headers: { Upgrade: 'websocket' } }), { MAINTENANCE_MODE: 'on' });
    assert.equal(res, origin);
    assert.equal(calls.length, 1);
  });
});

describe('origin failure → branded page', () => {
  test('origin 502 → 503 branded English HTML with the contract headers', async () => {
    mockOrigin(originStatus(502));
    const res = await handleRequest(req('/'), {});
    assertBranded(res);
    assert.equal(res.headers.get('Content-Type'), 'text/html; charset=utf-8');
    assert.equal(res.headers.get('Vary'), 'Accept, Accept-Language');
    const body = await res.text();
    assert.equal(body, HTML_EN);
    assert.match(body, /<html lang="en" dir="ltr"/);
    assert.match(body, /<script defer src="\/maintenance\/maintenance\.js">/);
    assert.ok(body.includes('weissmancybersecurity@gmail.com'));
  });

  test('every origin-failure status without the header is intercepted', async () => {
    assert.deepEqual([...ORIGIN_FAILURE_STATUSES], [502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 530]);
    for (const status of ORIGIN_FAILURE_STATUSES) {
      mockOrigin(originStatus(status));
      const res = await handleRequest(req('/pricing'), {});
      assertBranded(res);
      assert.equal(await res.text(), HTML_EN, `status ${status}`);
    }
  });

  test('isOriginFailure: header presence is what distinguishes "already branded"', () => {
    assert.equal(isOriginFailure(new Response(null, { status: 503 })), true);
    assert.equal(isOriginFailure(new Response(null, { status: 503, headers: { 'x-weissman-maintenance': '1' } })), false);
    assert.equal(isOriginFailure(new Response(null, { status: 200 })), false);
    assert.equal(isOriginFailure(new Response(null, { status: 500 })), false);
  });

  test('fetch() throwing → 503 branded HTML', async () => {
    mockOrigin(originThrows);
    const res = await handleRequest(req('/'), {});
    assertBranded(res);
    assert.equal(await res.text(), HTML_EN);
  });

  test('the CSP permits exactly what the page uses', () => {
    const csp = CONTENT_SECURITY_POLICY;
    assert.match(csp, /(^|; )style-src 'unsafe-inline'(;|$)/, 'inline <style>');
    assert.match(csp, /(^|; )font-src data:(;|$)/, 'data: fonts');
    assert.match(csp, /(^|; )img-src data:(;|$)/, 'data: favicon');
    assert.match(csp, /(^|; )script-src 'self'(;|$)/, 'the one same-origin script');
    assert.match(csp, /(^|; )connect-src 'self'(;|$)/, 'fetch /api/health');
    assert.match(csp, /(^|; )form-action 'self'(;|$)/, 'the GET retry form');
    assert.match(csp, /(^|; )frame-ancestors 'none'(;|$)/);
    assert.doesNotMatch(csp, /unsafe-eval|unsafe-inline'[^;]*;?\s*script/, 'no inline or dynamic script');
  });
});

describe('locale', () => {
  test('/he/ → Hebrew page', async () => {
    mockOrigin(originStatus(502));
    for (const path of ['/he/', '/he', '/he/pricing', '/he?x=1']) {
      const res = await handleRequest(req(path), {});
      assertBranded(res);
      const body = await res.text();
      assert.equal(body, HTML_HE, path);
      assert.match(body, /<html lang="he" dir="rtl"/);
    }
  });

  test('/hello is not /he', async () => {
    mockOrigin(originStatus(502));
    assert.equal(await (await handleRequest(req('/hello'), {})).text(), HTML_EN);
    assert.equal(await (await handleRequest(req('/health'), {})).text(), HTML_EN);
  });

  test('Accept-Language: he → Hebrew page', async () => {
    mockOrigin(originThrows);
    const res = await handleRequest(req('/', { headers: { 'Accept-Language': 'he' } }), {});
    assertBranded(res);
    assert.equal(await res.text(), HTML_HE);
  });

  test('Accept-Language is honoured in order of preference', () => {
    assert.equal(acceptsHebrew('he'), true);
    assert.equal(acceptsHebrew('he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7'), true);
    assert.equal(acceptsHebrew('iw'), true, 'legacy Hebrew tag');
    assert.equal(acceptsHebrew('en;q=0.5,he'), true);
    assert.equal(acceptsHebrew('fr,he;q=0.8'), true, 'Hebrew is the only supported language listed');
    assert.equal(acceptsHebrew('en-US,en;q=0.9,he;q=0.8'), false, 'English preferred');
    assert.equal(acceptsHebrew('en,he'), false, 'tie keeps the listed order');
    assert.equal(acceptsHebrew('he;q=0,en'), false, 'q=0 excludes');
    assert.equal(acceptsHebrew('fr-FR,de'), false);
    assert.equal(acceptsHebrew('*'), false);
    assert.equal(acceptsHebrew(''), false);
    assert.equal(acceptsHebrew(null), false);
  });

  test('the path prefix wins over Accept-Language', async () => {
    mockOrigin(originStatus(504));
    const he = await handleRequest(req('/he/', { headers: { 'Accept-Language': 'en' } }), {});
    assert.equal(await he.text(), HTML_HE);
    const en = await handleRequest(req('/', { headers: { 'Accept-Language': 'en-US,en;q=0.9,he;q=0.8' } }), {});
    assert.equal(await en.text(), HTML_EN);
  });
});

describe('JSON answers', () => {
  test('/api/x → api.json 503', async () => {
    mockOrigin(originStatus(502));
    const res = await handleRequest(req('/api/x'), {});
    assertBranded(res);
    assert.equal(res.headers.get('Content-Type'), 'application/json; charset=utf-8');
    const body = await res.text();
    assert.equal(body, API_JSON);
    const parsed = JSON.parse(body);
    assert.equal(parsed.status, 'maintenance');
    assert.equal(parsed.code, 503);
    assert.equal(parsed.retry_after_seconds, 30);
    assert.equal(parsed.contact, 'weissmancybersecurity@gmail.com');
  });

  test('/api/health (what the page polls) → JSON 503 while the origin is failing', async () => {
    mockOrigin(originStatus(521));
    const res = await handleRequest(req('/api/health', { headers: { Accept: 'application/json' } }), {});
    assertBranded(res);
    assert.equal(await res.text(), API_JSON);
  });

  test('/hooks/… and /api (no slash) are API-shaped; /apix is not', async () => {
    mockOrigin(originStatus(502));
    assert.equal(await (await handleRequest(req('/hooks/github'), {})).text(), API_JSON);
    assert.equal(await (await handleRequest(req('/api'), {})).text(), API_JSON);
    assert.equal(await (await handleRequest(req('/apix'), {})).text(), HTML_EN);
  });

  test('Accept: application/json → JSON regardless of path', async () => {
    mockOrigin(originThrows);
    const res = await handleRequest(req('/dashboard', { headers: { Accept: 'application/json, text/plain;q=0.9' } }), {});
    assert.equal(res.headers.get('Content-Type'), 'application/json; charset=utf-8');
    assert.equal(await res.text(), API_JSON);
  });

  test('POST → JSON 503, never HTML', async () => {
    mockOrigin(originStatus(502));
    const res = await handleRequest(req('/api/login', {
      method: 'POST', body: '{"email":"x"}', headers: { 'Content-Type': 'application/json', Accept: 'text/html' },
    }), {});
    assertBranded(res);
    assert.equal(res.headers.get('Content-Type'), 'application/json; charset=utf-8');
    assert.equal(await res.text(), API_JSON);
  });

  test('every non-GET/HEAD method gets JSON, even for the page path and the script path', async () => {
    mockOrigin(originThrows);
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
      for (const path of ['/', '/he/', '/maintenance/maintenance.js', '/maintenance/status.json']) {
        const init = { method };
        if (method !== 'OPTIONS' && method !== 'DELETE') { init.body = 'x'; }
        const res = await handleRequest(req(path, init), {});
        assert.equal(res.status, 503, `${method} ${path}`);
        assert.equal(res.headers.get('Content-Type'), 'application/json; charset=utf-8', `${method} ${path}`);
        assert.equal(await res.text(), API_JSON, `${method} ${path}`);
      }
    }
  });

  test('a healthy POST passes through untouched', async () => {
    const origin = new Response('{"ok":true}', { status: 201 });
    const calls = mockOrigin(() => origin);
    const request = req('/api/login', { method: 'POST', body: 'x' });
    const res = await handleRequest(request, {});
    assert.equal(res, origin);
    assert.equal(calls[0].input, request);
  });
});

describe('HEAD', () => {
  test('HEAD → 503 with the contract headers and an empty body', async () => {
    mockOrigin(originStatus(502));
    const res = await handleRequest(req('/', { method: 'HEAD' }), {});
    assertBranded(res);
    assert.equal(res.headers.get('Content-Type'), 'text/html; charset=utf-8');
    assert.equal(res.body, null);
    assert.equal(await res.text(), '');
  });

  test('HEAD for the script and for JSON also carries no body', async () => {
    mockOrigin(originThrows);
    const js = await handleRequest(req('/maintenance/maintenance.js', { method: 'HEAD' }), {});
    assert.equal(js.status, 200);
    assert.equal(js.headers.get('Content-Type'), 'application/javascript; charset=utf-8');
    assert.equal(await js.text(), '');
    const api = await handleRequest(req('/api/health', { method: 'HEAD' }), {});
    assert.equal(api.status, 503);
    assert.equal(await api.text(), '');
  });
});

describe('assets served by the Worker while the origin fails', () => {
  test('/maintenance/maintenance.js → 200 JavaScript, byte-identical to the built script', async () => {
    mockOrigin(originStatus(502));
    const res = await handleRequest(req('/maintenance/maintenance.js'), {});
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('Content-Type'), 'application/javascript; charset=utf-8');
    assert.equal(res.headers.get('X-Content-Type-Options'), 'nosniff');
    assert.equal(res.headers.get('Cache-Control'), 'no-cache');
    assert.equal(res.headers.has('Retry-After'), false, 'a 200 is not a maintenance answer');
    assert.equal(res.headers.has(MAINTENANCE_HEADER), false);
    assert.equal(await res.text(), MAINTENANCE_JS);
  });

  test('the script is served on fetch() exceptions too (the machine-off case)', async () => {
    mockOrigin(originThrows);
    const res = await handleRequest(req('/maintenance/maintenance.js'), {});
    assert.equal(res.status, 200);
    assert.equal(await res.text(), MAINTENANCE_JS);
  });

  test("a healthy origin's own copy of the script passes through", async () => {
    const origin = new Response('/* origin copy */', { status: 200, headers: { 'Content-Type': 'application/javascript' } });
    mockOrigin(() => origin);
    const res = await handleRequest(req('/maintenance/maintenance.js'), {});
    assert.equal(res, origin);
  });

  test('/maintenance/status.json → 404 "nothing announced" when no window is set', async () => {
    mockOrigin(originStatus(502));
    const res = await handleRequest(req('/maintenance/status.json'), {});
    assert.equal(res.status, 404);
    assert.equal(res.headers.get('Content-Type'), 'application/json; charset=utf-8');
    assert.equal(res.headers.get('Cache-Control'), 'no-store');
    assert.deepEqual(JSON.parse(await res.text()), { mode: 'ok' });
  });

  test('generated assets are what the page expects', () => {
    assert.match(HTML_EN, /^<!DOCTYPE html>/);
    assert.match(HTML_HE, /^<!DOCTYPE html>/);
    assert.equal((HTML_EN.match(/<script/g) || []).length, 1, 'exactly one script tag (CSP: no inline script)');
    assert.equal((HTML_HE.match(/<script/g) || []).length, 1);
    assert.doesNotMatch(HTML_EN, /\son[a-z]+=/i, 'no inline event handlers');
    assert.ok(MAINTENANCE_JS.includes("'/api/health'"), 'the script polls /api/health');
    assert.ok(MAINTENANCE_JS.includes("'/maintenance/status.json'"), 'the script reads status.json');
    const emails = (HTML_EN + HTML_HE + MAINTENANCE_JS + API_JSON).match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g) || [];
    assert.deepEqual([...new Set(emails)], ['weissmancybersecurity@gmail.com'], 'one contact address only');
  });
});

describe('announced window (MAINTENANCE_MODE)', () => {
  test('MAINTENANCE_MODE=on short-circuits: the origin is never called', async () => {
    const calls = mockOrigin(originUp);
    const env = { MAINTENANCE_MODE: 'on', MAINTENANCE_REASON: 'Database migration', MAINTENANCE_UNTIL: '2026-09-27T04:00:00+03:00' };
    const res = await handleRequest(req('/dashboard'), env);
    assertBranded(res);
    assert.equal(await res.text(), HTML_EN);
    assert.equal(calls.length, 0, 'fetch must not be called');

    const he = await handleRequest(req('/he/'), env);
    assert.equal(await he.text(), HTML_HE);
    const api = await handleRequest(req('/api/health'), env);
    assert.equal(api.status, 503);
    assert.equal(await api.text(), API_JSON);
    assert.equal(calls.length, 0);
  });

  test('status.json describes the window (reason + ISO until) while announced', async () => {
    const calls = mockOrigin(originUp);
    const env = { MAINTENANCE_MODE: 'on', MAINTENANCE_REASON: '  Database   migration\n and gateway rollout ', MAINTENANCE_UNTIL: '2026-09-27T04:00:00+03:00' };
    const res = await handleRequest(req('/maintenance/status.json'), env);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('Content-Type'), 'application/json; charset=utf-8');
    assert.equal(res.headers.get('Cache-Control'), 'no-store');
    assert.deepEqual(JSON.parse(await res.text()), {
      mode: 'planned',
      reason: 'Database migration and gateway rollout',
      until: '2026-09-27T01:00:00.000Z',
    });
    assert.equal(calls.length, 0);
    const js = await handleRequest(req('/maintenance/maintenance.js'), env);
    assert.equal(js.status, 200);
    assert.equal(await js.text(), MAINTENANCE_JS);
  });

  test('plannedStatus: empty reason and unparsable until become null; long reasons are capped', () => {
    assert.equal(plannedStatus({}), null);
    assert.equal(plannedStatus({ MAINTENANCE_MODE: 'off' }), null);
    assert.equal(plannedStatus({ MAINTENANCE_MODE: '' }), null);
    assert.equal(plannedStatus({ MAINTENANCE_MODE: 'true' }), null, 'only "on" announces');
    assert.deepEqual(plannedStatus({ MAINTENANCE_MODE: 'on' }), { mode: 'planned', reason: null, until: null });
    assert.deepEqual(plannedStatus({ MAINTENANCE_MODE: ' ON ', MAINTENANCE_REASON: '   ', MAINTENANCE_UNTIL: 'next sunday' }),
      { mode: 'planned', reason: null, until: null });
    assert.equal(plannedStatus({ MAINTENANCE_MODE: 'on', MAINTENANCE_REASON: 'x'.repeat(300) }).reason.length, 240);
  });

  test('MAINTENANCE_MODE=off (the default) → normal pass-through', async () => {
    const origin = originUp();
    const calls = mockOrigin(() => origin);
    const res = await handleRequest(req('/'), { MAINTENANCE_MODE: 'off', MAINTENANCE_REASON: '', MAINTENANCE_UNTIL: '' });
    assert.equal(res, origin);
    assert.equal(calls.length, 1);
  });
});

describe('module entry point', () => {
  test('default export fetch(request, env, ctx) opts into pass-through on exceptions and delegates', async () => {
    const origin = originUp();
    mockOrigin(() => origin);
    let passThrough = 0;
    const ctx = { passThroughOnException() { passThrough += 1; }, waitUntil() {} };
    const res = await worker.fetch(req('/'), { MAINTENANCE_MODE: 'off' }, ctx);
    assert.equal(res, origin);
    assert.equal(passThrough, 1);
  });

  test('default export tolerates a missing env and ctx', async () => {
    mockOrigin(originStatus(502));
    const res = await worker.fetch(req('/'), undefined, undefined);
    assertBranded(res);
  });

  test('maintenanceResponse never caches at the edge: every answer is no-store or no-cache', () => {
    const env = { MAINTENANCE_MODE: 'on' };
    for (const path of ['/', '/he/', '/api/x', '/maintenance/status.json', '/maintenance/maintenance.js']) {
      const cc = maintenanceResponse(req(path), env).headers.get('Cache-Control');
      assert.ok(cc === 'no-store' || cc === 'no-cache', `${path}: ${cc}`);
    }
  });
});
