import { describe, it, expect } from 'vitest'
import { isNavActive, canAccessNavItem } from './appNav'

describe('isNavActive', () => {
  it('matches exact paths and normalizes trailing slashes', () => {
    expect(isNavActive('/clients', '/clients')).toBe(true)
    expect(isNavActive('/clients/', '/clients')).toBe(true)
    expect(isNavActive('/clients', '/clients/')).toBe(true)
  })

  it('matches nested paths by prefix', () => {
    expect(isNavActive('/clients/123', '/clients')).toBe(true)
    expect(isNavActive('/clients/123/engagements', '/clients')).toBe(true)
  })

  it('does not treat sibling prefixes as active', () => {
    expect(isNavActive('/clients-archive', '/clients')).toBe(false)
    expect(isNavActive('/findings', '/clients')).toBe(false)
  })

  it('root only matches the root path', () => {
    expect(isNavActive('/', '/')).toBe(true)
    expect(isNavActive('/findings', '/')).toBe(false)
  })

  it('exact flag disables prefix matching', () => {
    expect(isNavActive('/clients/123', '/clients', true)).toBe(false)
    expect(isNavActive('/clients', '/clients', true)).toBe(true)
  })
})

describe('canAccessNavItem (RBAC nav gating)', () => {
  it('allows unrestricted items for any role', () => {
    expect(canAccessNavItem({ to: '/clients' }, { role: 'viewer' })).toBe(true)
    expect(canAccessNavItem({ to: '/findings' }, {})).toBe(true)
  })

  it('hides items flagged hideFromNav', () => {
    expect(canAccessNavItem({ to: '/clients', hideFromNav: true }, { is_ceo: true })).toBe(false)
  })

  it('blocks restricted targets for non-privileged roles', () => {
    for (const to of ['/admin', '/ceo-vault', '/ceo-keys', '/ceo', '/supreme-nerve-center']) {
      expect(canAccessNavItem({ to }, { role: 'viewer' })).toBe(false)
      expect(canAccessNavItem({ to }, { role: 'analyst' })).toBe(false)
      expect(canAccessNavItem({ to }, null)).toBe(false)
    }
  })

  it('allows restricted targets for ceo / superadmin', () => {
    expect(canAccessNavItem({ to: '/admin' }, { role: 'ceo' })).toBe(true)
    expect(canAccessNavItem({ to: '/ceo-vault' }, { role: 'ceo' })).toBe(true)
    expect(canAccessNavItem({ to: '/ceo-keys' }, { role: 'ceo' })).toBe(true)
    expect(canAccessNavItem({ to: '/ceo-keys' }, { role: 'admin' })).toBe(false)
    expect(canAccessNavItem({ to: '/ceo-keys' }, { is_superadmin: true })).toBe(true)
    expect(canAccessNavItem({ to: '/ceo' }, { is_superadmin: true })).toBe(true)
  })

  it('gates /system-config at admin (not visible to operator/analyst)', () => {
    expect(canAccessNavItem({ to: '/system-config' }, { role: 'operator' })).toBe(false)
    expect(canAccessNavItem({ to: '/system-config' }, { role: 'admin' })).toBe(true)
    expect(canAccessNavItem({ to: '/system-config' }, { role: 'ceo' })).toBe(true)
  })

  it('honors an explicit per-item minRole override', () => {
    expect(canAccessNavItem({ to: '/anything', minRole: 'operator' }, { role: 'analyst' })).toBe(false)
    expect(canAccessNavItem({ to: '/anything', minRole: 'operator' }, { role: 'operator' })).toBe(true)
  })
})
