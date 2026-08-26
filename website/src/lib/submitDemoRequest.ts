/**
 * Demo / contact submission adapter.
 *
 * Endpoint: POST /api/public/demo-request
 * Wire-up: fingerprint_engine::demo_request (SMTP via WEISSMAN_SMTP_*).
 *
 * The UI must never claim success unless the server returns 2xx.
 * 503 means SMTP is not configured on this deployment — show the mailto fallback.
 */

export type DemoPayload = {
  name: string
  email: string
  company: string
  role: string
  message: string
}

export type DemoResult =
  | { ok: true; detail: string }
  | { ok: false; status: number; detail: string; mailto?: string }

const MAILTO = 'mailto:sales@weissman.io?subject=Weissman%20Demo%20Request'

export async function submitDemoRequest(payload: DemoPayload): Promise<DemoResult> {
  try {
    const res = await fetch('/api/public/demo-request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const data = (await res.json().catch(() => ({}))) as { detail?: string }
    if (res.ok) {
      return { ok: true, detail: data.detail || 'Request received. We will reply from sales@weissman.io.' }
    }
    if (res.status === 503) {
      return {
        ok: false,
        status: 503,
        detail:
          data.detail ||
          'This deployment is not configured to accept demo requests over email. Use sales@weissman.io instead.',
        mailto: MAILTO,
      }
    }
    return {
      ok: false,
      status: res.status,
      detail: data.detail || 'The request could not be sent. Try again or email sales@weissman.io.',
      mailto: MAILTO,
    }
  } catch {
    return {
      ok: false,
      status: 0,
      detail: 'Network error. The form was not submitted. Email sales@weissman.io or retry.',
      mailto: MAILTO,
    }
  }
}
