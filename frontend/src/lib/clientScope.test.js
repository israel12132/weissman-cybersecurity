import { describe, it, expect } from 'vitest'
import {
  assignedClientId,
  isClientUser,
  isPlatformOwner,
  isStaffUser,
  canCreateClients,
  canDeleteClients,
  isPortalBlockedPath,
  allowedClientIds,
  filterVisibleClients,
  shouldHideClientPicker,
  boundClientId,
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

  it('hides tenant-admin surfaces from portal sessions', () => {
    expect(isPortalBlockedPath('/admin')).toBe(true)
    expect(isPortalBlockedPath('/clients/new')).toBe(true)
    expect(isPortalBlockedPath('/billing')).toBe(true)
    expect(isPortalBlockedPath('/findings')).toBe(false)
    expect(isPortalBlockedPath('/clients')).toBe(false)
    expect(isPortalBlockedPath('/engines')).toBe(false)
  })

  it('hides the picker and overwrites spoofed client ids for portal sessions', () => {
    const roster = [{ id: 7, name: 'acme' }, { id: 99, name: 'other' }]
    const scoped = {
      ...portal,
      client_picker_hidden: true,
      allowed_client_ids: [7],
    }
    expect(allowedClientIds(scoped)).toEqual([7])
    expect(filterVisibleClients(scoped, roster)).toEqual([{ id: 7, name: 'acme' }])
    expect(shouldHideClientPicker(scoped, roster)).toBe(true)
    expect(boundClientId(scoped, roster, 99)).toBe(7)
    expect(filterVisibleClients(staff, roster)).toEqual(roster)
    expect(shouldHideClientPicker(staff, roster)).toBe(false)
    expect(boundClientId(staff, roster, 99)).toBe(99)
  })

  it('fails closed on an empty allow-list instead of trusting a spoofed id', () => {
    const roster = [{ id: 7, name: 'acme' }, { id: 99, name: 'other' }]
    const empty = { ok: true, role: 'client', is_client_user: true, allowed_client_ids: [] }
    expect(allowedClientIds(empty)).toEqual([])
    expect(filterVisibleClients(empty, roster)).toEqual([])
    expect(shouldHideClientPicker(empty, roster)).toBe(true)
    expect(boundClientId(empty, roster, 99)).toBeNull()
  })
})
