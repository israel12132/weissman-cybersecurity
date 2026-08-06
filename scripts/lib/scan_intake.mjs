// Shared shed-aware retry for the live E2E suite: scan-intake POSTs and the logins that precede
// them.
//
// The platform transiently sheds NEW scan intake with two distinct, self-protecting codes, both
// advertising Retry-After / `retry_after_seconds` precisely so a correct client backs off and
// retries instead of failing the contract:
//   * 503 `load_shed`    — self-heal recovery, engaged when the DB pool or async backlog crosses its
//                          critical threshold; auto-clears on a TTL as the platform drains.
//   * 429 `rate_limited` — per-tenant / per-IP burst limit (all live E2E traffic rides one IP, so a
//                          legitimate burst trips a limit no real distributed client ever hits).
//
// A live E2E driving many scans through 127.0.0.1 legitimately trips these; honoring the server's
// documented back-off is correct client behaviour, NOT a way to weaken the protection. Callers poll
// each job to completion before the next, so the backlog drains between scans and one short wait
// almost always lands healthy. Honor the server's own hint (capped) rather than a blind fixed sleep.

const RETRIES = Number(process.env.WEISSMAN_SCAN_INTAKE_RETRIES || 6)
// Ceiling on a single honored back-off. It must stay ABOVE every Retry-After the server actually
// sends, or "honor the hint" is silently defeated: at 20s the login limiter's documented 60s hint
// (http/login_rate_limit.rs, `retry_after_secs = 60`) was truncated to a third of the requested
// wait, so retries burned out inside one quota window instead of riding it out. 75s clears the 60s
// login hint and the 15s load-shed hint with margin. This raises only the CEILING — the healthy
// path still waits exactly what the server asked for, so it costs nothing when nothing is shed.
const WAIT_CAP_MS = 75000
// Ceiling on the CUMULATIVE back-off across one call's retries. WAIT_CAP_MS bounds a SINGLE wait;
// without this, six retries against a repeated 60s hint would sit here for six minutes of CI time
// before returning the shed response the caller was always going to act on. One honored 60s wait
// clears the login limiter's quota window, so allowing one is what this needs to permit. It does
// not touch the burst case: six 1.5s fallback waits total 9s, far inside the budget.
const WAIT_TOTAL_BUDGET_MS = 90000
const SHED_CODES = new Set([429, 503])

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// Run one request via `attempt`, retrying while the platform sheds it (429/503).
//   attempt       () => Promise<nativeResponse>  — performs one request, returns the script's own shape
//   opts.label    string   — log label (engine / scenario) for the back-off line
//   opts.what     string   — what was shed, for the log line (default 'scan intake')
//   opts.retries  number   — max retries (default WEISSMAN_SCAN_INTAKE_RETRIES or 6)
//   opts.statusOf (r) => number  — extract the HTTP status (default r.status)
//   opts.retryAfterOf (r) => number|string  — extract the seconds hint (default r.data.retry_after_seconds)
// Returns the final native response unchanged (non-shed status, or the last shed after exhausting
// retries — the caller still makes the final accept/fail decision on it).
export async function retryShed(attempt, opts = {}) {
  const { label = 'scan', what = 'scan intake', retries = RETRIES } = opts
  const statusOf = opts.statusOf || ((r) => r?.status)
  const retryAfterOf = opts.retryAfterOf || ((r) => r?.data?.retry_after_seconds)
  let res = await attempt()
  let spentMs = 0
  for (let i = 1; i <= retries && SHED_CODES.has(statusOf(res)); i += 1) {
    const hint = Number(retryAfterOf(res))
    const waitMs = Number.isFinite(hint) && hint > 0
      ? Math.min(hint * 1000, WAIT_CAP_MS)
      : Math.min(1500 * i, WAIT_CAP_MS)
    if (spentMs + waitMs > WAIT_TOTAL_BUDGET_MS) break
    spentMs += waitMs
    console.log(
      `  … ${label}: ${what} shed (HTTP ${statusOf(res)}); backing off ${Math.round(waitMs / 1000)}s ` +
        `(retry ${i}/${retries})`,
    )
    await sleep(waitMs)
    res = await attempt()
  }
  return res
}

// Scan-intake POSTs. Unchanged behaviour and log wording; retryShed carries the loop.
export async function retryScanIntake(attempt, opts = {}) {
  return retryShed(attempt, { ...opts, what: 'scan intake' })
}

// Logins.
//
// Every live E2E step authenticates before it does anything, and they all ride one IP, so the
// per-IP login limiter (http/login_rate_limit.rs) legitimately trips partway through a CI job that
// chains many of these steps back to back. Until this existed the limiter's 429 was simply read as
// "wrong password": each script's login helper treated any non-200 as fatal and exited immediately,
// so a shed login failed the whole contract in about a second while the server was actively telling
// the client to wait 60s and try again. Honoring that hint here is the same correctness argument as
// for scan intake — the limiter still protects the server, the client just stops misreporting a
// back-off as an authentication failure.
export async function retryLogin(attempt, opts = {}) {
  return retryShed(attempt, { label: 'auth', ...opts, what: 'login' })
}
