import { describe, it, expect } from 'vitest'
import {
  assignedClientId,
  isClientUser,
  isPlatformOwner,
  isStaffUser,
  canCreateClients,
  canDeleteClients,
  isPortalBlockedPath,
} from './clientScope.js'

const owner = { ok: true, role: 'ceo', is_owner: true, can_create_clients: true, can_delete_clients: true }
const ownerRole = { ok: true, role: 'owner', is_owner: true, can_create_clients: true, can_delete_clients: true }
const superadmin = { ok: true, role: 'admin', is_superadmin: true, is_owner: true, can_create_clients: true, can_delete_clients: true }
// Admin and above are the only tenant-wide "staff".
const staff = { ok: true, role: 'admin', is_staff: true, can_create_clients: false, can_delete_clients: false }
// A below-admin human bound to one client.
const scopedOperator = {
  ok: true,
  role: 'operator',
  assigned_client_id: 4,
  is_client_user: true,
  can_create_clients: false,
  can_delete_clients: false,
}
// A below-admin human with no assignment — sees nothing.
const unassignedAnalyst = { ok: true, role: 'analyst', is_client_user: true }
const portal = {
  ok: true,
  role: 'client',
  assigned_client_id: 7,
  is_client_user: true,
  can_create_clients: false,
  can_delete_clients: false,
}

describe('clientScope policy', () => {
  it('treats ceo, owner and superadmin as owner', () => {
    expect(isPlatformOwner(owner)).toBe(true)
    expect(isPlatformOwner(ownerRole)).toBe(true)
    expect(isPlatformOwner(superadmin)).toBe(true)
    expect(isPlatformOwner(staff)).toBe(false)
    expect(isPlatformOwner(scopedOperator)).toBe(false)
    expect(isPlatformOwner(portal)).toBe(false)
  })

  it('locks portal users to assigned_client_id', () => {
    expect(isClientUser(portal)).toBe(true)
    expect(assignedClientId(portal)).toBe(7)
    expect(isClientUser(staff)).toBe(false)
    expect(assignedClientId(staff)).toBe(null)
  })

  it('confines every below-admin human to a client', () => {
    expect(isClientUser(scopedOperator)).toBe(true)
    expect(assignedClientId(scopedOperator)).toBe(4)
    expect(isClientUser(unassignedAnalyst)).toBe(true)
    expect(isStaffUser(scopedOperator)).toBe(false)
    expect(isStaffUser(unassignedAnalyst)).toBe(false)
    // Local fallback (no server flags) still scopes a below-admin role.
    expect(isClientUser({ ok: true, role: 'operator' })).toBe(true)
    expect(isClientUser({ ok: true, role: 'admin' })).toBe(false)
  })

  it('only the owner may create or delete clients', () => {
    expect(canCreateClients(owner)).toBe(true)
    expect(canDeleteClients(owner)).toBe(true)
    expect(canCreateClients(ownerRole)).toBe(true)
    expect(canCreateClients(superadmin)).toBe(true)
    expect(canDeleteClients(staff)).toBe(false)
    expect(canCreateClients(staff)).toBe(false)
    expect(canDeleteClients(portal)).toBe(false)
    expect(canCreateClients(portal)).toBe(false)
  })

  it('staff (admin and above) remain tenant-wide', () => {
    expect(isStaffUser(staff)).toBe(true)
    expect(isStaffUser(owner)).toBe(true)
    expect(isStaffUser(ownerRole)).toBe(true)
    expect(isStaffUser(portal)).toBe(false)
  })

  it('hides tenant-admin surfaces from portal sessions', () => {
    expect(isPortalBlockedPath('/admin')).toBe(true)
    expect(isPortalBlockedPath('/clients/new')).toBe(true)
    expect(isPortalBlockedPath('/billing')).toBe(true)
    expect(isPortalBlockedPath('/scim-provisioning')).toBe(true)
    expect(isPortalBlockedPath('/sso-config')).toBe(true)
    expect(isPortalBlockedPath('/findings')).toBe(false)
    expect(isPortalBlockedPath('/clients')).toBe(false)
    expect(isPortalBlockedPath('/engines')).toBe(false)
  })
})
