/*
 * Weissman maintenance page — live availability check.
 *
 * Why this is an external file: the gateway CSP is `script-src 'self'` with no
 * nonces, so the maintenance HTML cannot carry an inline <script>. Everything
 * dynamic lives here, and the page must already read as complete before this
 * runs (or if it never runs — the <noscript> meta refresh covers that case).
 *
 * What it does:
 *   - polls GET /api/health (no-store, no credentials) with jittered backoff
 *     5 s → 60 s and reloads the ORIGINAL URL on the first genuine 200: the page
 *     is served in place of whatever the visitor asked for, so a plain reload
 *     returns them exactly where they were going;
 *   - a 200 counts only when it carries no X-Weissman-Maintenance header AND is
 *     not text/html — a branded 503 from our own edge, an "Always Online" copy
 *     or a captive-portal page must never trigger a reload;
 *   - a sessionStorage guard refuses to reload again within 15 s, so a flapping
 *     origin cannot bounce the visitor between the app and this page;
 *   - shows "last checked" (clock time, page locale) and a "next check"
 *     countdown, plus a "Check again" control that probes immediately;
 *   - optionally reads /maintenance/status.json (404 is normal) and, when
 *     mode === "planned", sets data-mode="planned" on <html> (the eyebrow swap
 *     and accent recolouring are CSS-driven) and reveals the reason and a
 *     localized "expected back by" (Israel time + UTC). Rows without data stay
 *     hidden; an ETA that has already passed is never shown — the live line
 *     says the update is running longer than scheduled instead;
 *   - honours prefers-reduced-motion (countdown steps every 5 s instead of
 *     every second), navigator.onLine / online / offline and tab visibility;
 *   - writes text only (textContent), never markup, and never throws: every
 *     entry point is wrapped so a broken browser API degrades to the static page.
 *
 * All user-facing strings come from data-l10n-* attributes on #maint-live, so
 * the same file serves the English and Hebrew pages (and the Command Center
 * variant). Stable id contract: deploy/maintenance/README.md (Design contract).
 */
(function () {
  'use strict';

  var doc = document;
  var win = window;
  var root = doc.documentElement;

  function byId(id) {
    try { return doc.getElementById(id); } catch (e) { return null; }
  }

  var live = byId('maint-live');
  var stateEl = byId('maint-state');
  var lastEl = byId('maint-last-checked');
  var countdownEl = byId('maint-countdown');
  var retryBtn = byId('maint-retry');
  var retryForm = byId('maint-retry-form');
  var plannedEl = byId('maint-planned');
  var reasonRow = byId('maint-reason-row');
  var reasonEl = byId('maint-reason');
  var untilRow = byId('maint-until-row');
  var untilEl = byId('maint-until');

  if (!live || !stateEl || typeof win.fetch !== 'function') { return; }

  var HEALTH_URL = '/api/health';
  var STATUS_URL = '/maintenance/status.json';
  var MIN_DELAY = 5000;
  var MAX_DELAY = 60000;
  var GROWTH = 1.6;
  var JITTER = 0.2;             // ±20 %, so a fleet of tabs does not stampede the origin
  var REQUEST_TIMEOUT = 8000;
  var STATUS_EVERY = 4;         // re-read status.json every Nth health check (a window may be declared mid-way)
  var RELOAD_GUARD_MS = 15000;  // reloaded moments ago and still here → the origin is flapping
  var RELOAD_KEY = 'weissman-maint-reload';

  var locale = (root.getAttribute('lang') || 'en');
  var delay = MIN_DELAY;
  var checks = 0;
  var checking = false;
  var restored = false;
  var offline = false;
  var overdue = false;
  var dueAt = 0;
  var pollTimer = null;
  var tickTimer = null;
  var lastText = { state: null, countdown: null };
  var lastAnnounced = null;

  var reducedMotion = false;
  try {
    var mq = win.matchMedia && win.matchMedia('(prefers-reduced-motion: reduce)');
    reducedMotion = !!(mq && mq.matches);
    if (mq && typeof mq.addEventListener === 'function') {
      mq.addEventListener('change', function (ev) { reducedMotion = !!ev.matches; });
    }
  } catch (e) { /* matchMedia missing — treat as full motion */ }

  function t(key, fallback, n) {
    var s = null;
    try { s = live.getAttribute('data-l10n-' + key); } catch (e) { /* ignore */ }
    if (!s) { s = fallback; }
    return n === undefined ? s : s.replace('{n}', String(n));
  }

  function setText(el, text, slot) {
    if (!el) { return; }
    if (slot && lastText[slot] === text) { return; }   // avoid needless DOM churn / screen-reader chatter
    if (slot) { lastText[slot] = text; }
    try { el.textContent = text; } catch (e) { /* ignore */ }
  }

  function setAttr(el, name, value) {
    if (!el) { return; }
    try {
      if (value === null) { el.removeAttribute(name); } else { el.setAttribute(name, value); }
    } catch (e) { /* ignore */ }
  }

  function setHidden(el, hidden) {
    if (!el) { return; }
    try { el.hidden = !!hidden; } catch (e) { /* ignore */ }
  }

  // The live line is the page's one `role="status"` region. Screen readers must hear a
  // REAL change of state — still updating, restored, offline, overrun — and not the
  // transient "Checking…" wording, which would otherwise be read twice every 5–60 s for
  // the whole outage (checking → pending → checking …). A transient state, and a repeat
  // of the sentence already announced, are written with the region switched off; the
  // attribute is set before the text so assistive tech sees it in that order.
  function setState(name, text, announce) {
    var quiet = !announce || lastAnnounced === text;
    setAttr(live, 'data-state', name);
    setAttr(stateEl, 'aria-live', quiet ? 'off' : 'polite');
    setText(stateEl, text, 'state');
    if (!quiet) { lastAnnounced = text; }
  }

  function setBusy(on) {
    if (!retryBtn) { return; }
    try { retryBtn.disabled = !!on; } catch (e) { /* ignore */ }
    setAttr(retryBtn, 'aria-busy', on ? 'true' : 'false');
  }

  function pendingMessage() {
    return overdue
      ? t('overdue', 'The update is taking longer than scheduled; this page keeps re-checking.')
      : t('pending', 'Update still in progress — this page re-checks automatically.');
  }

  function clockTime(date) {
    try {
      return new Intl.DateTimeFormat(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).format(date);
    } catch (e) {
      var p = function (v) { return (v < 10 ? '0' : '') + v; };
      return p(date.getHours()) + ':' + p(date.getMinutes()) + ':' + p(date.getSeconds());
    }
  }

  function jittered(ms) {
    var spread = ms * JITTER;
    return Math.round(ms - spread + Math.random() * spread * 2);
  }

  function clearTimers() {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
  }

  function countdownText(remaining) {
    if (remaining <= 1) { return t('next-one', 'in 1 s'); }
    if (remaining === 2) {
      // Hebrew has a dual form ("שתי שניות"); English pages simply omit the key.
      var two = null;
      try { two = live.getAttribute('data-l10n-next-two'); } catch (e) { two = null; }
      if (two) { return two; }
    }
    return t('next', 'in {n} s', remaining);
  }

  function renderCountdown() {
    if (!countdownEl || restored) { return; }
    if (checking) { setText(countdownEl, t('now', 'now'), 'countdown'); return; }
    if (offline) { setText(countdownEl, '—', 'countdown'); return; }
    var remaining = Math.max(0, Math.ceil((dueAt - Date.now()) / 1000));
    setText(countdownEl, countdownText(remaining), 'countdown');
  }

  function schedule(ms) {
    clearTimers();
    if (restored || offline) { return; }
    dueAt = Date.now() + ms;
    pollTimer = setTimeout(function () { check(false); }, ms);
    renderCountdown();
    // The countdown is text, not motion, but under reduced motion it steps
    // every 5 s so nothing on the page appears to animate.
    // A 1 s tick regardless of prefers-reduced-motion: the countdown is a text update, not an
    // animation, and a 5 s redraw showed a stale "in N s" four seconds out of five.
    tickTimer = setInterval(renderCountdown, 1000);
  }

  function fetchWithTimeout(url) {
    var init = {
      method: 'GET',
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'follow',
      headers: { 'Accept': 'application/json' }
    };
    var ctrl = null;
    try { if (typeof win.AbortController === 'function') { ctrl = new win.AbortController(); } } catch (e) { ctrl = null; }
    if (ctrl) { init.signal = ctrl.signal; }
    var timer = setTimeout(function () { try { if (ctrl) { ctrl.abort(); } } catch (e) { /* ignore */ } }, REQUEST_TIMEOUT);
    var p;
    try { p = win.fetch(url, init); } catch (e) { p = Promise.reject(e); }
    return p.then(function (res) { clearTimeout(timer); return res; }, function (err) { clearTimeout(timer); throw err; });
  }

  function reloadedRecently() {
    var last = 0;
    try { last = Number(win.sessionStorage.getItem(RELOAD_KEY) || 0); } catch (e) { last = 0; }
    return last > 0 && Date.now() - last < RELOAD_GUARD_MS;
  }

  function onRestored() {
    if (reloadedRecently()) {
      // Health answered 200, but this page was reloaded seconds ago and is
      // still being served: the origin is settling. Wait out a full guard
      // interval instead of bouncing the visitor back and forth.
      setState('pending', pendingMessage(), true);
      delay = RELOAD_GUARD_MS;
      schedule(RELOAD_GUARD_MS);
      return;
    }
    try { win.sessionStorage.setItem(RELOAD_KEY, String(Date.now())); } catch (e) { /* ignore */ }
    restored = true;
    clearTimers();
    setState('up', t('up', 'Update complete — returning you to Weissman…'), true);
    if (countdownEl) { setText(countdownEl, t('now', 'now'), 'countdown'); }
    setBusy(true);
    // Short pause so the "restored" state is perceivable, then reload the
    // original URL (this page was served in its place, so location is intact).
    setTimeout(function () {
      try { win.location.reload(); } catch (e) { /* ignore */ }
    }, reducedMotion ? 300 : 700);
  }

  function onStillPending() {
    setState('pending', pendingMessage(), true);
    delay = Math.min(MAX_DELAY, Math.round(delay * GROWTH));
    schedule(jittered(delay));
  }

  function check(manual) {
    if (checking || restored) { return; }
    if (offline && !manual) { return; }
    checking = true;
    checks += 1;
    clearTimers();
    setState('checking', t('checking', 'Checking service availability…'), false);
    renderCountdown();
    setBusy(true);

    if (manual) { delay = MIN_DELAY; }   // a person asked: restart the schedule from the fast end
    if (checks > 1 && checks % STATUS_EVERY === 0) { loadPlannedWindow(); }

    var finish = function (up) {
      checking = false;
      setBusy(false);
      if (lastEl) { setText(lastEl, clockTime(new Date())); }
      if (up) { onRestored(); } else { onStillPending(); }
    };

    fetchWithTimeout(HEALTH_URL).then(function (res) {
      // Only a genuine 200 counts. Our own branded 503, a proxy's 502, an
      // edge "Always Online" copy or a captive-portal HTML 200 are all
      // "still updating" from the visitor's point of view.
      var ct = '';
      try { ct = String(res.headers.get('content-type') || ''); } catch (e) { ct = ''; }
      var branded = false;
      try { branded = res.headers.has('x-weissman-maintenance'); } catch (e) { branded = false; }
      finish(res.status === 200 && !branded && ct.toLowerCase().indexOf('text/html') === -1);
    }, function () {
      finish(false);
    }).then(null, function () {
      // finish() itself failed (should not happen) — never leave the button stuck.
      checking = false;
      setBusy(false);
      schedule(jittered(delay));
    });
  }

  // ---- planned window (optional /maintenance/status.json) ------------------

  function formatUntil(d) {
    var il, utc;
    try {
      il = new Intl.DateTimeFormat(locale, {
        weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'Asia/Jerusalem'
      }).format(d);
      utc = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC' }).format(d);
    } catch (e) {
      return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    }
    // U+2068/U+2069 isolate the Latin "HH:MM UTC" run so it keeps its order
    // inside Hebrew text; the NBSP keeps the time and "UTC" on one line.
    return il + ' ' + t('tz-il', 'Israel time') + ' (⁨' + utc + ' UTC⁩)';
  }

  function showPlanned(info) {
    setAttr(root, 'data-mode', 'planned');

    var reason = (info && typeof info.reason === 'string') ? info.reason.replace(/\s+/g, ' ').trim().slice(0, 240) : '';
    setText(reasonEl, reason);
    setHidden(reasonRow, !reason);

    // Never display an ETA that has already passed: an expired window is not a
    // promise we can keep. The live line switches to the "longer than
    // scheduled" wording instead, and amber is reserved for exactly that state.
    var untilText = '';
    var untilIso = null;
    var wasOverdue = overdue;
    overdue = false;
    if (info && typeof info.until === 'string' && info.until) {
      var d = new Date(info.until);
      if (!isNaN(d.getTime())) {
        if (d.getTime() > Date.now()) {
          untilText = formatUntil(d);
          untilIso = d.toISOString();
        } else {
          overdue = true;
        }
      }
    }
    setText(untilEl, untilText);
    setAttr(untilEl, 'datetime', untilIso);
    setHidden(untilRow, !untilText);
    setAttr(root, 'data-overdue', overdue ? '1' : null);
    if (overdue !== wasOverdue && !checking && !restored && !offline) { setState('pending', pendingMessage(), true); }

    // A heading-only block says nothing: hide the whole section when both rows are empty.
    setHidden(plannedEl, !(reason || untilText));
  }

  function hidePlanned() {
    setHidden(plannedEl, true);
    setAttr(root, 'data-mode', null);
    setAttr(root, 'data-overdue', null);
    if (overdue) {
      overdue = false;
      if (!checking && !restored && !offline) { setState('pending', pendingMessage(), true); }
    }
  }

  function loadPlannedWindow() {
    if (!plannedEl) { return; }
    fetchWithTimeout(STATUS_URL).then(function (res) {
      if (res.status !== 200) { return null; }
      return res.json().then(function (j) { return j; }, function () { return null; });
    }, function () { return null; }).then(function (info) {
      if (info && typeof info === 'object' && info.mode === 'planned') { showPlanned(info); } else { hidePlanned(); }
    }).then(null, function () { /* status.json is optional; 404 is the normal answer */ });
  }

  // ---- wiring ----------------------------------------------------------------

  function goOffline() {
    offline = true;
    clearTimers();
    setState('offline', t('offline', 'Your device appears to be offline. Checks resume when the connection returns.'), true);
    renderCountdown();
  }

  function goOnline() {
    if (!offline) { return; }
    offline = false;
    delay = MIN_DELAY;
    check(false);
  }

  try {
    if (retryForm) {
      retryForm.addEventListener('submit', function (ev) {
        try { ev.preventDefault(); } catch (e) { /* ignore */ }
        if (offline) { offline = false; }
        check(true);
      });
    } else if (retryBtn) {
      retryBtn.addEventListener('click', function (ev) {
        try { ev.preventDefault(); } catch (e) { /* ignore */ }
        check(true);
      });
    }
    win.addEventListener('offline', goOffline);
    win.addEventListener('online', goOnline);
    doc.addEventListener('visibilitychange', function () {
      // A tab that was in the background may have a stale schedule: check as
      // soon as it is looked at again, if the next check is already due.
      if (doc.visibilityState === 'visible' && !checking && !restored && !offline && Date.now() >= dueAt - 250) {
        check(false);
      }
    });
  } catch (e) { /* listeners are a convenience, not a requirement */ }

  try {
    setAttr(root, 'data-js', '1');
    if (typeof navigator !== 'undefined' && navigator.onLine === false) {
      goOffline();
    } else {
      // First probe after a short beat so the static page paints first.
      schedule(jittered(MIN_DELAY));
    }
    loadPlannedWindow();
  } catch (e) { /* fall back to the static page + <noscript> refresh */ }
})();
