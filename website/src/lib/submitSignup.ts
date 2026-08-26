export type SignupPayload = {
  workspace_name: string
  email: string
  password: string
  accept_terms: boolean
}

export type SignupResult =
  | { ok: true; detail: string; verifyUrl?: string }
  | { ok: false; status: number; detail: string }

export async function submitSignup(payload: SignupPayload): Promise<SignupResult> {
  try {
    const res = await fetch('/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const data = (await res.json().catch(() => ({}))) as { detail?: string; verify_url?: string }
    if (res.status === 202 || res.ok) {
      return { ok: true, detail: data.detail || 'Check your inbox to confirm your workspace.', verifyUrl: data.verify_url }
    }
    if (res.status === 503) {
      return {
        ok: false,
        status: 503,
        detail: data.detail || 'Self-serve signup is not enabled on this deployment. Contact sales@weissman.io.',
      }
    }
    return {
      ok: false,
      status: res.status,
      detail: data.detail || 'Something went wrong. Try again.',
    }
  } catch {
    return { ok: false, status: 0, detail: 'Network error — the workspace was not created. Please try again.' }
  }
}
