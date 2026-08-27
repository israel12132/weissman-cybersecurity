/**
 * Customer-client isolation policy — mirrors `fingerprint_engine/src/client_isolation.rs`.
 *
 * Owner (CEO / superadmin): sees every client, may create and delete.
 * Staff (unscoped humans): sees every client, cannot create or delete.
 * Portal (`role=client` + `assigned_client_id`): locked to one customer; engines
 * auto-aim; no client picker at login.
 *
 * Server flags on `/api/auth/me` win when present so the UI cannot drift.
 */

function normRole(session) {
  return String(session?.role || '')
    .trim()
    .toLowerCase()
}

export function assignedClientId(session) {
  const raw = session?.assigned_client_id
  const n = Number(raw)
  return Number.isFinite(n) && n > 0 ? n : null
}

/** Allowed customer ids for this session (single assigned client, or explicit list). */
export function allowedClientIds(session) {
  const raw = session?.allowed_client_ids
  if (Array.isArray(raw) && raw.length) {
    return [...new Set(raw.map((id) => Number(id)).filter((n) => Number.isFinite(n) && n > 0))]
  }
  const one = assignedClientId(session)
  return one != null ? [one] : []
}

/**
 * Hide every client picker when the session is locked to one customer, or when
 * the visible catalog is a single auto-bound client (no choice to present).
 */
export function shouldHideClientPicker(session, clients = []) {
  // Server flag is authoritative. Portal lock = true; staff impersonation = false
  // so the control is a scope-switcher (new JWT), never a client_id spoof picker.
  if (session?.client_picker_hidden === true) return true
  if (session?.can_scope_switch === true) return false
  if (session?.client_picker_hidden === false && session?.can_scope_switch === false) {
    const allowed = allowedClientIds(session)
    if (allowed.length === 1) return true
  }
  const allowed = allowedClientIds(session)
  if (allowed.length === 1) return true
  if (isClientUser(session) && allowed.length <= 1) return true
  // A single visible customer is auto-bound — never render a one-option dropdown.
  // Length 0 is "catalog still loading" for staff: keep the control, do not flash unbound.
  if (Array.isArray(clients) && clients.length === 1 && session?.can_scope_switch !== true) return true
  return false
}

export function canScopeSwitch(session) {
  if (session?.can_scope_switch === true) return true
  if (session?.can_scope_switch === false) return false
  if (isClientUser(session)) return false
  return isStaffUser(session)
}

/** Restrict a catalog to the session's allowed customers. Empty allowed = tenant-wide.
 * Staff with can_scope_switch see every grantable customer (scope-targets), not
 * only the JWT cid they currently impersonate.
 */
export function filterVisibleClients(session, clients = []) {
  const list = Array.isArray(clients) ? clients : []
  if (session?.can_scope_switch === true) return list
  const allowed = allowedClientIds(session)
  if (!allowed.length) return list
  const set = new Set(allowed.map(String))
  return list.filter((c) => set.has(String(c?.id)))
}

/** Effective bound id: assigned client, else the only visible catalog row. */
export function boundClientId(session, clients = [], current = null) {
  if (session?.can_scope_switch === true) {
    const assigned = assignedClientId(session)
    if (assigned != null) return assigned
    if (current != null && current !== '') {
      const n = Number(current)
      if (Number.isFinite(n) && n > 0) return n
    }
    return null
  }
  const allowed = allowedClientIds(session)
  if (allowed.length === 1) return allowed[0]
  const visible = filterVisibleClients(session, clients)
  if (visible.length === 1) {
    const n = Number(visible[0].id)
    return Number.isFinite(n) && n > 0 ? n : current
  }
  if (current != null && current !== '') {
    const n = Number(current)
    if (Number.isFinite(n) && n > 0) {
      if (!allowed.length || allowed.includes(n)) return n
    }
  }
  return allowed[0] ?? null
}

export function isClientUser(session) {
  if (!session || session.ok === false) return false
  if (session.is_client_user === true) return true
  if (session.is_client_user === false) return false
  if (session.impersonating === true || session.can_scope_switch === true) return false
  if (session.is_staff === true) return false
  return normRole(session) === 'client'
}

export function isPlatformOwner(session) {
  if (!session || session.ok === false) return false
  if (isClientUser(session)) return false
  if (session.is_owner === true) return true
  if (session.is_superadmin === true) return true
  return normRole(session) === 'ceo'
}

export function isStaffUser(session) {
  if (!session || session.ok === false) return false
  if (session.is_staff === true) return !isClientUser(session)
  return !isClientUser(session)
}

export function canCreateClients(session) {
  if (session?.can_create_clients === true) return true
  if (session?.can_create_clients === false) return false
  return isPlatformOwner(session)
}

export function canDeleteClients(session) {
  if (session?.can_delete_clients === true) return true
  if (session?.can_delete_clients === false) return false
  return isPlatformOwner(session)
}

/** Routes a customer-portal session must never open. */
export const PORTAL_BLOCKED_PREFIXES = [
  '/admin',
  '/ceo',
  '/ceo-vault',
  '/supreme-nerve-center',
  '/system-config',
  '/sso-config',
  '/clients/new',
  '/billing',
  '/engine-management',
  '/audit-log',
]

export function isPortalBlockedPath(to) {
  const p = String(to || '').replace(/\/$/, '') || '/'
  return PORTAL_BLOCKED_PREFIXES.some((prefix) => p === prefix || p.startsWith(`${prefix}/`))
}

export function sessionIdentityLabel(session, t) {
  if (session?.impersonating === true) {
    return t('profile.impersonating')
  }
  if (isPlatformOwner(session)) return t('profile.owner')
  if (isClientUser(session)) return t('profile.client_portal')
  if (isStaffUser(session)) return t('profile.staff')
  return normRole(session) || t('profile.signed_in')
}
