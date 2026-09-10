const KEY = 'weissman_destructive_confirm'
const DUAL_KEY = 'weissman_dual_approve'

function readSession(key) {
  try {
    return typeof window !== 'undefined' ? sessionStorage.getItem(key) || '' : ''
  } catch {
    return ''
  }
}

function writeSession(key, value) {
  try {
    if (typeof window === 'undefined') return
    const v = (value || '').trim()
    if (v) sessionStorage.setItem(key, v)
    else sessionStorage.removeItem(key)
  } catch {
    /* ignore */
  }
}

function resolvedTokens(confirmToken, dualToken) {
  const confirm = (confirmToken || '').trim() || readSession(KEY)
  const dual = (dualToken || '').trim() || readSession(DUAL_KEY)
  return { confirm, dual }
}

/** Merge JSON headers with optional human-in-the-loop token (must match server WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET). */
export function destructiveHeaders(base = {}) {
  const out = { ...base }
  const t = readSession(KEY)
  if (t) out['X-Weissman-Destructive-Confirm'] = t
  return out
}

/** Dual-control headers for SOAR HITL / signed agent kill (confirm + second operator). */
export function dualControlHeaders(confirmToken, dualToken, base = {}) {
  const out = { ...base }
  const { confirm, dual } = resolvedTokens(confirmToken, dualToken)
  if (confirm) out['X-Weissman-Destructive-Confirm'] = confirm
  if (dual) out['X-Weissman-Dual-Approve'] = dual
  return out
}

/**
 * JSON-body dual-control tokens. The public nginx gateway blanks inbound
 * X-Weissman-Destructive-Confirm / X-Weissman-Dual-Approve so Command Center
 * must send these fields; the API accepts header OR body.
 */
export function dualControlBody(confirmToken, dualToken, extra = {}) {
  const out = { ...extra }
  const { confirm, dual } = resolvedTokens(confirmToken, dualToken)
  if (confirm) out.destructive_confirm = confirm
  if (dual) out.dual_approve = dual
  return out
}

export function loadDestructiveConfirmToken() {
  return readSession(KEY)
}

export function saveDestructiveConfirmToken(value) {
  writeSession(KEY, value)
}

export function loadDualApproveToken() {
  return readSession(DUAL_KEY)
}

export function saveDualApproveToken(value) {
  writeSession(DUAL_KEY, value)
}

export function persistDualControlTokens(confirmToken, dualToken, remember) {
  if (!remember) return
  saveDestructiveConfirmToken(confirmToken)
  saveDualApproveToken(dualToken)
}
