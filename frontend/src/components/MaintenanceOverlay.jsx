import { useCallback, useEffect, useRef, useState } from 'react'
import { apiUrl } from '../lib/apiBase'

/**
 * MaintenanceOverlay — the in-app counterpart of the branded continuity page
 * (deploy/maintenance, Command Center variant = public/offline.html).
 *
 * Raised by MaintenanceProvider when an API call comes back as the gateway's
 * branded 502/503/504 (see lib/apiBase isMaintenanceResponse). It covers the
 * whole viewport so a half-broken screen full of failed queries is never what
 * the operator sees, then probes GET /api/health until the origin answers a
 * genuine 200 and hands control back via `onRestored`.
 *
 * Contract (mirrors deploy/maintenance/src/maintenance.js so both layers behave
 * identically):
 *  - probe: cache 'no-store', credentials 'omit' (the probe must never carry a
 *    session and must never be answered from a cache), Accept: application/json,
 *    8 s abort timeout;
 *  - "up" ONLY when status === 200 AND no X-Weissman-Maintenance header AND the
 *    body is not text/html (a branded 200 or a captive portal both stay pending);
 *  - backoff 5 s → ×1.6 → capped at 30 s, "Retry now" resets it to 5 s;
 *  - every timer is owned by refs and cleared on unmount; the component never
 *    sets state after unmount and never uses innerHTML.
 *
 * Copy is English-only by design: the Command Center has no Hebrew variant.
 */

export const HEALTH_PATH = '/api/health'
export const CONTACT_EMAIL = 'weissmancybersecurity@gmail.com'
const FIRST_DELAY_S = 5
const MAX_DELAY_S = 30
const BACKOFF_FACTOR = 1.6
const PROBE_TIMEOUT_MS = 8_000

const nextDelay = (current) => Math.min(MAX_DELAY_S, Math.round(current * BACKOFF_FACTOR))

const clockFormat = (() => {
  try {
    return new Intl.DateTimeFormat('en-GB', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    })
  } catch {
    return null
  }
})()

function formatClock(date) {
  if (clockFormat) {
    try {
      return clockFormat.format(date)
    } catch {
      /* fall through to the manual format */
    }
  }
  const pad = (n) => String(n).padStart(2, '0')
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

/** A response counts as "restored" only when it is a genuine, unbranded 200. */
export function isHealthyResponse(response) {
  if (!response || response.status !== 200) return false
  let branded = null
  let contentType = ''
  try {
    branded = response.headers?.get?.('x-weissman-maintenance') ?? null
    contentType = String(response.headers?.get?.('content-type') || '')
  } catch {
    /* headers unreadable → treat as not restored */
    return false
  }
  if (branded != null) return false
  return !/text\/html/i.test(contentType)
}

function ShieldMark({ className }) {
  // deploy/public/favicon.svg, inline so the mark renders with the origin down.
  return (
    <svg
      className={className}
      viewBox="0 0 64 64"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient
          id="maint-shield-g"
          x1="0"
          y1="0"
          x2="64"
          y2="64"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0" stopColor="#22d3ee" />
          <stop offset="1" stopColor="#0ea5e9" />
        </linearGradient>
      </defs>
      <path
        d="M32 4 L58 12 V32 C58 48 32 60 32 60 C32 60 6 48 6 32 V12 Z"
        fill="url(#maint-shield-g)"
        stroke="#0e7490"
        strokeWidth="1.5"
      />
      <path
        d="M16 28 L25 42 L34 22 L43 42 L52 24"
        stroke="#020617"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  )
}

export default function MaintenanceOverlay({ status = 503, retryAfter = 30, onRestored }) {
  const [phase, setPhase] = useState('pending') // pending | checking | up
  const [lastChecked, setLastChecked] = useState(null) // Date | null
  const [secondsLeft, setSecondsLeft] = useState(FIRST_DELAY_S)

  const mountedRef = useRef(true)
  const timerRef = useRef(null) // countdown interval
  const probeRef = useRef(null) // in-flight AbortController
  const delayRef = useRef(FIRST_DELAY_S)
  const dialogRef = useRef(null)
  const onRestoredRef = useRef(onRestored)
  useEffect(() => {
    onRestoredRef.current = onRestored
  }, [onRestored])

  const clearCountdown = useCallback(() => {
    if (timerRef.current != null) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
  }, [])

  // schedule → probe → schedule is a cycle; the ref breaks it so both callbacks
  // stay stable across renders instead of re-creating each other.
  const probeFnRef = useRef(null)

  const schedule = useCallback((seconds) => {
    clearCountdown()
    if (!mountedRef.current) return
    let remaining = Math.max(1, Math.round(seconds))
    setSecondsLeft(remaining)
    timerRef.current = setInterval(() => {
      if (!mountedRef.current) return clearCountdown()
      remaining -= 1
      if (remaining <= 0) {
        clearCountdown()
        setSecondsLeft(0)
        probeFnRef.current?.()
        return
      }
      setSecondsLeft(remaining)
    }, 1000)
  }, [clearCountdown])

  const probe = useCallback(async () => {
    if (!mountedRef.current || probeRef.current) return
    clearCountdown()
    const controller = typeof AbortController === 'function' ? new AbortController() : null
    probeRef.current = controller || { abort() {} }
    const abortTimer = controller ? setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS) : null
    setPhase('checking')
    let healthy = false
    try {
      const res = await fetch(apiUrl(HEALTH_PATH), {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: { Accept: 'application/json' },
        signal: controller ? controller.signal : undefined,
      })
      healthy = isHealthyResponse(res)
    } catch {
      healthy = false
    } finally {
      if (abortTimer != null) clearTimeout(abortTimer)
      probeRef.current = null
    }
    if (!mountedRef.current) return
    setLastChecked(new Date())
    if (healthy) {
      setPhase('up')
      try {
        onRestoredRef.current?.()
      } catch {
        /* the provider owns what happens next; never leave the overlay stuck */
      }
      return
    }
    setPhase('pending')
    delayRef.current = nextDelay(delayRef.current)
    schedule(delayRef.current)
  }, [schedule, clearCountdown])
  useEffect(() => {
    probeFnRef.current = probe
  }, [probe])

  const retryNow = useCallback(() => {
    delayRef.current = FIRST_DELAY_S
    void probe()
  }, [probe])

  useEffect(() => {
    mountedRef.current = true
    delayRef.current = FIRST_DELAY_S
    schedule(FIRST_DELAY_S)
    // Move focus onto the dialog so screen readers announce it; no focus trap —
    // there is nothing else interactive on screen while the overlay is up.
    try {
      dialogRef.current?.focus({ preventScroll: true })
    } catch {
      /* focus can throw on detached nodes in some test environments */
    }
    // Coming back online is a strong hint the origin may answer: probe at once.
    const onOnline = () => void probe()
    window.addEventListener('online', onOnline)
    return () => {
      mountedRef.current = false
      clearCountdown()
      window.removeEventListener('online', onOnline)
      try {
        probeRef.current?.abort()
      } catch {
        /* ignore */
      }
      probeRef.current = null
    }
  }, [probe, schedule, clearCountdown])

  const stateSentence =
    phase === 'checking'
      ? 'Checking service availability…'
      : phase === 'up'
        ? 'Update complete — resuming your session…'
        : 'Update in progress — this screen re‑checks automatically.'

  const nextCheckText =
    phase === 'checking' ? 'now' : phase === 'up' ? '—' : `in ${secondsLeft} s`

  const dotClass =
    phase === 'up'
      ? 'bg-emerald-400 shadow-[0_0_0_6px_rgba(52,211,153,0.16)]'
      : 'bg-cyan-400 shadow-[0_0_0_6px_rgba(34,211,238,0.16)]'

  return (
    <div
      ref={dialogRef}
      role="alertdialog"
      aria-labelledby="maint-overlay-headline"
      aria-describedby="maint-overlay-lede"
      tabIndex={-1}
      data-testid="maintenance-overlay"
      data-phase={phase}
      className="fixed inset-0 z-[1000] overflow-y-auto bg-slate-950 text-slate-200 font-sans antialiased outline-none"
      style={{
        backgroundImage:
          'radial-gradient(60rem 30rem at 50% -8rem, rgba(34,211,238,0.10), transparent 70%)',
      }}
    >
      <div className="mx-auto flex min-h-full w-full max-w-2xl flex-col px-4 py-6 sm:px-8">
        <header className="flex items-center gap-3" dir="ltr">
          <ShieldMark className="h-8 w-8 shrink-0 drop-shadow-[0_0_10px_rgba(34,211,238,0.32)]" />
          <div className="leading-none">
            <div className="font-holo text-[0.82rem] font-bold tracking-[0.24em] text-slate-200">
              WEISSMAN
            </div>
            <div className="mt-1 font-mono text-[11px] tracking-[0.28em] text-slate-500">
              COMMAND CENTER
            </div>
          </div>
        </header>

        <main className="flex flex-1 flex-col justify-center py-10">
          <p className="mb-3 flex items-center gap-2 font-mono text-[0.74rem] uppercase tracking-[0.18em] text-cyan-400">
            <span
              className="inline-block h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_0_4px_rgba(34,211,238,0.16)]"
              aria-hidden="true"
            />
            Scheduled update
          </p>
          <h1
            id="maint-overlay-headline"
            className="text-3xl font-semibold leading-tight text-slate-100 sm:text-4xl"
            style={{ textWrap: 'balance' }}
          >
            Command Center is being updated.
          </h1>
          <p id="maint-overlay-lede" className="mt-4 max-w-xl text-base leading-relaxed text-slate-400">
            Your session resumes automatically once the update completes. Security monitoring and
            scanning operations continue as planned throughout, and no action is required on your
            side.
          </p>

          <section
            aria-labelledby="maint-overlay-card-title"
            className="mt-8 rounded-[14px] border border-slate-200/10 bg-slate-900 p-5 shadow-[0_18px_50px_rgba(0,0,0,0.35)] sm:p-6"
          >
            <h2
              id="maint-overlay-card-title"
              className="font-mono text-[0.7rem] uppercase tracking-[0.18em] text-slate-500"
            >
              Service availability
            </h2>
            <div className="mt-4 flex items-start gap-3">
              <span
                className={`mt-1.5 inline-block h-2.5 w-2.5 shrink-0 rounded-full ${dotClass} ${
                  phase === 'checking' ? 'animate-pulse' : ''
                }`}
                aria-hidden="true"
              />
              <p role="status" aria-live="polite" className="text-sm leading-relaxed text-slate-200">
                {stateSentence}
              </p>
            </div>

            <dl className="mt-5 grid grid-cols-2 gap-4 font-mono text-sm tabular-nums">
              <div>
                <dt className="text-[0.7rem] uppercase tracking-[0.18em] text-slate-500">Last checked</dt>
                <dd className="mt-1 text-slate-200" data-testid="maintenance-last-checked">
                  {lastChecked ? formatClock(lastChecked) : 'when this screen appeared'}
                </dd>
              </div>
              <div>
                <dt className="text-[0.7rem] uppercase tracking-[0.18em] text-slate-500">Next check</dt>
                <dd className="mt-1 text-slate-200" data-testid="maintenance-next-check">
                  {nextCheckText}
                </dd>
              </div>
            </dl>

            <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
              <button
                type="button"
                onClick={retryNow}
                disabled={phase === 'checking'}
                aria-busy={phase === 'checking' ? 'true' : 'false'}
                aria-describedby="maint-overlay-retry-hint"
                className="inline-flex h-[2.65rem] items-center justify-center rounded-[10px] bg-cyan-400 px-5 text-sm font-semibold text-slate-950 transition hover:brightness-110 active:scale-[0.98] disabled:cursor-progress disabled:opacity-60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-400"
              >
                Retry now
              </button>
              <a
                href="/status"
                className="inline-flex h-[2.65rem] items-center justify-center rounded-[10px] border border-slate-200/20 px-5 text-sm font-medium text-slate-200 transition hover:border-slate-200/40 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-400"
              >
                Status updates
              </a>
              <span id="maint-overlay-retry-hint" className="text-xs text-slate-500">
                Checks availability now.
              </span>
            </div>
          </section>

          <p className="mt-6 flex items-start gap-2 text-sm leading-relaxed text-slate-400">
            <svg
              className="mt-0.5 h-[18px] w-[18px] shrink-0 text-emerald-400"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
              focusable="false"
            >
              <path d="M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
            All data, scheduled scans and queued jobs are preserved; in-flight work resumes
            automatically.
          </p>

          <dl className="mt-8 border-y border-slate-200/10 py-4">
            <dt className="text-base text-slate-200">Need assistance or want to report something?</dt>
            <dd className="mt-1 font-mono text-sm">
              <a
                href={`mailto:${CONTACT_EMAIL}`}
                className="text-cyan-400 underline-offset-4 hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-400"
              >
                {CONTACT_EMAIL}
              </a>
            </dd>
          </dl>
        </main>

        <footer className="flex flex-col gap-2 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <span>© 2026 Weissman Cybersecurity Ltd. · Tel Aviv‑Yafo</span>
          <span className="whitespace-nowrap font-mono text-[0.72rem]" dir="ltr">
            HTTP {status} · Retry-After: {retryAfter} s
          </span>
        </footer>
      </div>
    </div>
  )
}
