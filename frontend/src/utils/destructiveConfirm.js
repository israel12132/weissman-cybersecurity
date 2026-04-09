const KEY = 'weissman_destructive_confirm'

/** Merge JSON headers with optional human-in-the-loop token (must match server WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET). */
export function destructiveHeaders(base = {}) {
  const out = { ...base }
  try {
    if (typeof window !== 'undefined') {
      const t = sessionStorage.getItem(KEY)
      if (t) out['X-Weissman-Destructive-Confirm'] = t
    }
  } catch (_) {
    /* ignore */
  }
  return out
}

export function loadDestructiveConfirmToken() {
  try {
    return typeof window !== 'undefined' ? sessionStorage.getItem(KEY) || '' : ''
  } catch (_) {
    return ''
  }
}

export function saveDestructiveConfirmToken(value) {
  try {
    if (typeof window === 'undefined') return
    const v = (value || '').trim()
    if (v) sessionStorage.setItem(KEY, v)
    else sessionStorage.removeItem(KEY)
  } catch (_) {
    /* ignore */
  }
}
