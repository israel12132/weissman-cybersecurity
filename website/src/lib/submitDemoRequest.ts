/**
 * Demo / contact submission adapter.
 *
 * Endpoint: POST /api/public/demo-request
 * Wire-up: fingerprint_engine::demo_request (SMTP via WEISSMAN_SMTP_*).
 *
 * The UI must never claim success unless the server returns 2xx.
 * 503 means SMTP is not configured on this deployment — show the mailto fallback.
 */

import { company } from '../content/site'

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

function salesMailto() {
  return `mailto:${company.emails.sales}?subject=Weissman%20Demo%20Request`
}

export async function submitDemoRequest(payload: DemoPayload): Promise<DemoResult> {
  const mailto = salesMailto()
  try {
    const res = await fetch('/api/public/demo-request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const data = (await res.json().catch(() => ({}))) as { detail?: string }
    if (res.ok) {
      return { ok: true, detail: data.detail || `Request received. We will reply from ${company.emails.sales}.` }
    }
    if (res.status === 503) {
      return {
        ok: false,
        status: 503,
        detail:
          data.detail ||
          `This deployment is not configured to accept demo requests over email. Use ${company.emails.sales} instead.`,
        mailto,
      }
    }
    return {
      ok: false,
      status: res.status,
      detail: data.detail || `The request could not be sent. Try again or email ${company.emails.sales}.`,
      mailto,
    }
  } catch {
    return {
      ok: false,
      status: 0,
      detail: `Network error. The form was not submitted. Email ${company.emails.sales} or retry.`,
      mailto,
    }
  }
}
