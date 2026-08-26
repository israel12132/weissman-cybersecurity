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

export function isClientUser(session) {
  if (!session || session.ok === false) return false
  if (session.is_client_user === true) return true
  if (assignedClientId(session)) return true
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
  if (isPlatformOwner(session)) return t('profile.owner')
  if (isClientUser(session)) return t('profile.client_portal')
  if (isStaffUser(session)) return t('profile.staff')
  return normRole(session) || t('profile.signed_in')
}
