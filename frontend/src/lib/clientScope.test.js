import { describe, it, expect } from 'vitest'
import {
  assignedClientId,
  allowedClientIds,
  isClientUser,
  isPlatformOwner,
  isStaffUser,
  canCreateClients,
  canDeleteClients,
  isPortalBlockedPath,
  shouldHideClientPicker,
  filterVisibleClients,
  boundClientId,
  canScopeSwitch,
} from './clientScope.js'

const owner = { ok: true, role: 'ceo', is_owner: true, can_create_clients: true, can_delete_clients: true }
const superadmin = { ok: true, role: 'admin', is_superadmin: true, is_owner: true, can_create_clients: true, can_delete_clients: true }
const staff = { ok: true, role: 'operator', is_staff: true, can_create_clients: false, can_delete_clients: false }
const portal = {
  ok: true,
  role: 'client',
  assigned_client_id: 7,
  is_client_user: true,
  can_create_clients: false,
  can_delete_clients: false,
}

describe('clientScope policy', () => {
  it('treats ceo and superadmin as owner', () => {
    expect(isPlatformOwner(owner)).toBe(true)
    expect(isPlatformOwner(superadmin)).toBe(true)
    expect(isPlatformOwner(staff)).toBe(false)
    expect(isPlatformOwner(portal)).toBe(false)
  })

  it('locks portal users to assigned_client_id', () => {
    expect(isClientUser(portal)).toBe(true)
    expect(assignedClientId(portal)).toBe(7)
    expect(isClientUser(staff)).toBe(false)
    expect(assignedClientId(staff)).toBe(null)
  })

  it('only the owner may create or delete clients', () => {
    expect(canCreateClients(owner)).toBe(true)
    expect(canDeleteClients(owner)).toBe(true)
    expect(canCreateClients(superadmin)).toBe(true)
    expect(canDeleteClients(staff)).toBe(false)
    expect(canCreateClients(staff)).toBe(false)
    expect(canDeleteClients(portal)).toBe(false)
    expect(canCreateClients(portal)).toBe(false)
  })

  it('staff remain tenant-wide operators', () => {
    expect(isStaffUser(staff)).toBe(true)
    expect(isStaffUser(owner)).toBe(true)
    expect(isStaffUser(portal)).toBe(false)
  })

  it('hides portal blocked paths from portal sessions', () => {
    expect(isPortalBlockedPath('/admin')).toBe(true)
    expect(isPortalBlockedPath('/clients/new')).toBe(true)
    expect(isPortalBlockedPath('/billing')).toBe(true)
    expect(isPortalBlockedPath('/findings')).toBe(false)
    expect(isPortalBlockedPath('/clients')).toBe(false)
    expect(isPortalBlockedPath('/engines')).toBe(false)
  })

  it('never offers a client picker to a scoped session', () => {
    expect(shouldHideClientPicker(portal, [{ id: 7 }, { id: 8 }])).toBe(true)
    expect(shouldHideClientPicker(staff, [{ id: 1 }, { id: 2 }])).toBe(false)
    expect(shouldHideClientPicker(staff, [{ id: 1 }])).toBe(true)
    expect(shouldHideClientPicker({ ...staff, can_scope_switch: true }, [{ id: 1 }])).toBe(false)
    expect(shouldHideClientPicker({ ...portal, can_scope_switch: false, client_picker_hidden: true }, [{ id: 7 }])).toBe(true)
    expect(canScopeSwitch(portal)).toBe(false)
    expect(canScopeSwitch({ ...staff, can_scope_switch: true })).toBe(true)
    expect(canScopeSwitch({ ...portal, can_scope_switch: false })).toBe(false)
    expect(boundClientId(portal, [{ id: 7 }, { id: 99 }])).toBe(7)
    expect(filterVisibleClients(portal, [{ id: 7 }, { id: 99 }])).toEqual([{ id: 7 }])
    expect(allowedClientIds(portal)).toEqual([7])
    expect(allowedClientIds({ ...portal, allowed_client_ids: [3, 4] })).toEqual([3, 4])
    expect(shouldHideClientPicker(staff, [])).toBe(false)
    expect(shouldHideClientPicker(staff, [{ id: 1 }])).toBe(true)
    expect(shouldHideClientPicker({ ...portal, assigned_client_id: null, allowed_client_ids: [3, 4], client_picker_hidden: false }, [{ id: 3 }, { id: 4 }])).toBe(false)
    expect(filterVisibleClients({ ...portal, allowed_client_ids: [3, 4] }, [{ id: 3 }, { id: 4 }, { id: 9 }])).toEqual([{ id: 3 }, { id: 4 }])
    expect(boundClientId({ ...portal, assigned_client_id: null, allowed_client_ids: [3, 4] }, [{ id: 3 }, { id: 4 }], 4)).toBe(4)
    expect(boundClientId({ ...portal, assigned_client_id: null, allowed_client_ids: [3, 4] }, [{ id: 3 }, { id: 4 }], 9)).toBe(3)
  })

  it('does not treat staff impersonation JWT cid as a portal lock', () => {
    const impersonating = {
      ...staff,
      assigned_client_id: 5,
      impersonating: true,
      can_scope_switch: true,
      is_client_user: false,
      client_picker_hidden: false,
    }
    expect(isClientUser(impersonating)).toBe(false)
    expect(isStaffUser(impersonating)).toBe(true)
    expect(canScopeSwitch(impersonating)).toBe(true)
    expect(shouldHideClientPicker(impersonating, [{ id: 5 }, { id: 9 }])).toBe(false)
    expect(filterVisibleClients(impersonating, [{ id: 5 }, { id: 9 }])).toEqual([{ id: 5 }, { id: 9 }])
    expect(boundClientId(impersonating, [{ id: 5 }, { id: 9 }])).toBe(5)
  })
})
