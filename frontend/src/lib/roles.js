/**
 * RBAC role ladder — single source of truth for the frontend.
 *
 * Mirrors the backend ladder `viewer → analyst → operator → admin → ceo`
 * plus the `superadmin` override. This is defense-in-depth for the UI: the
 * backend still enforces every privileged call with a 403. Route guards and
 * nav gating both consume `roleRank`/`hasRole` so they can never drift apart.
 */

/** Ordered low→high. Index is intentionally not the rank — use ROLE_RANK. */
export const ROLE_LADDER = ['viewer', 'analyst', 'operator', 'admin', 'ceo', 'superadmin']

/** @type {Record<string, number>} role → numeric rank (higher = more privilege). */
export const ROLE_RANK = ROLE_LADDER.reduce((acc, role, i) => {
  acc[role] = i + 1
  return acc
}, {})

/**
 * Resolve the effective role of a session.
 * `is_superadmin` always wins regardless of the stored role string.
 * @param {{ role?: string, is_superadmin?: boolean, ok?: boolean } | null | undefined} session
 * @returns {string} a role from ROLE_LADDER, or 'viewer' when unknown
 */
export function effectiveRole(session) {
  if (!session || session.ok === false) return 'viewer'
  if (session.is_superadmin === true) return 'superadmin'
  const r = (session.role || '').toString().trim().toLowerCase()
  return ROLE_RANK[r] ? r : 'viewer'
}

/**
 * Numeric rank of a session's effective role.
 * @param {object|null|undefined} session
 * @returns {number}
 */
export function sessionRoleRank(session) {
  return ROLE_RANK[effectiveRole(session)] || 0
}

/**
 * Does the session meet or exceed `minRole`?
 * @param {object|null|undefined} session
 * @param {string} minRole one of ROLE_LADDER (unknown/empty → allowed)
 * @returns {boolean}
 */
export function sessionHasRole(session, minRole) {
  if (!minRole) return true
  const min = ROLE_RANK[(minRole || '').toString().trim().toLowerCase()]
  if (!min) return true // unknown gate → don't lock users out on a typo
  return sessionRoleRank(session) >= min
}
