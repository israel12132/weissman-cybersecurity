import { describe, it, expect } from 'vitest'
import {
  ROLE_RANK,
  effectiveRole,
  sessionRoleRank,
  sessionHasRole,
} from './roles.js'

describe('roles ladder', () => {
  it('ranks the ladder strictly increasing', () => {
    expect(ROLE_RANK.viewer).toBeLessThan(ROLE_RANK.analyst)
    expect(ROLE_RANK.analyst).toBeLessThan(ROLE_RANK.operator)
    expect(ROLE_RANK.operator).toBeLessThan(ROLE_RANK.admin)
    expect(ROLE_RANK.admin).toBeLessThan(ROLE_RANK.ceo)
    expect(ROLE_RANK.ceo).toBeLessThan(ROLE_RANK.superadmin)
  })

  it('is_superadmin overrides any role string', () => {
    expect(effectiveRole({ ok: true, role: 'viewer', is_superadmin: true })).toBe('superadmin')
    expect(sessionHasRole({ role: 'viewer', is_superadmin: true }, 'ceo')).toBe(true)
  })

  it('treats unknown / missing role as viewer', () => {
    expect(effectiveRole(null)).toBe('viewer')
    expect(effectiveRole({ ok: false })).toBe('viewer')
    expect(effectiveRole({ role: 'wizard' })).toBe('viewer')
    expect(sessionRoleRank(null)).toBe(ROLE_RANK.viewer)
  })

  it('hasRole enforces the minimum', () => {
    const analyst = { ok: true, role: 'analyst' }
    expect(sessionHasRole(analyst, 'viewer')).toBe(true)
    expect(sessionHasRole(analyst, 'analyst')).toBe(true)
    expect(sessionHasRole(analyst, 'operator')).toBe(false)
    expect(sessionHasRole(analyst, 'admin')).toBe(false)
    expect(sessionHasRole(analyst, 'ceo')).toBe(false)
  })

  it('admin does not satisfy ceo gate; ceo does', () => {
    expect(sessionHasRole({ role: 'admin' }, 'ceo')).toBe(false)
    expect(sessionHasRole({ role: 'ceo' }, 'ceo')).toBe(true)
  })

  it('an unknown gate never locks a user out', () => {
    expect(sessionHasRole({ role: 'viewer' }, '')).toBe(true)
    expect(sessionHasRole({ role: 'viewer' }, 'nonexistent')).toBe(true)
  })

  it('role matching is case-insensitive', () => {
    expect(sessionHasRole({ role: 'CEO' }, 'ceo')).toBe(true)
    expect(sessionHasRole({ role: 'Admin' }, 'ADMIN')).toBe(true)
  })

  it('client portal ranks with operator for in-scope engine writes', () => {
    expect(effectiveRole({ ok: true, role: 'client' })).toBe('client')
    expect(ROLE_RANK.client).toBe(ROLE_RANK.operator)
    expect(sessionHasRole({ role: 'client' }, 'operator')).toBe(true)
    expect(sessionHasRole({ role: 'client' }, 'admin')).toBe(false)
    expect(sessionHasRole({ role: 'client' }, 'ceo')).toBe(false)
  })
})
