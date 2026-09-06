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

function clientRecordId(client) {
  const n = Number(client?.id ?? client?.client_id)
  return Number.isFinite(n) && n > 0 ? n : null
}

/**
 * Server `allowed_client_ids` from GET /api/auth/me wins.
 * Portal / impersonation: a one-element allow-list.
 * Staff / owner: `null` means unrestricted (the API already scopes SQL).
 */
export function allowedClientIds(session) {
  const raw = session?.allowed_client_ids ?? session?.capabilities?.allowed_client_ids
  if (Array.isArray(raw)) {
    return raw.map((v) => Number(v)).filter((n) => Number.isFinite(n) && n > 0)
  }
  const assigned = assignedClientId(session)
  return assigned ? [assigned] : null
}

export function filterVisibleClients(session, clients) {
  const list = Array.isArray(clients) ? clients : []
  const allowed = allowedClientIds(session)
  // `null` = unrestricted staff/owner. `[]` = scoped session with no id — fail closed.
  if (allowed === null) return list
  const allow = new Set(allowed)
  return list.filter((c) => {
    const id = clientRecordId(c)
    return id != null && allow.has(id)
  })
}

export function shouldHideClientPicker(session, visibleClients) {
  if (session?.client_picker_hidden === true) return true
  if (isClientUser(session)) return true
  const allowed = allowedClientIds(session)
  if (Array.isArray(allowed) && allowed.length <= 1) return true
  if (Array.isArray(visibleClients) && visibleClients.length <= 1) return true
  return false
}

/**
 * Force the bound customer id. Portal / impersonation never trusts a spoofed
 * `requested` value — same fail-closed overwrite as `force_json_client_id`.
 */
export function boundClientId(session, visibleClients, requested) {
  const allowed = allowedClientIds(session)
  const requestedId = Number(requested)
  const requestedOk = Number.isFinite(requestedId) && requestedId > 0 ? requestedId : null

  if (Array.isArray(allowed)) {
    if (allowed.length === 0) return null
    if (allowed.length === 1) return allowed[0]
    if (requestedOk && allowed.includes(requestedOk)) return requestedOk
    return allowed[0]
  }

  if (requestedOk) return requestedOk
  const vis = Array.isArray(visibleClients) ? visibleClients : []
  if (vis.length === 1) return clientRecordId(vis[0])
  return null
}
