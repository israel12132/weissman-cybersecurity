import { describe, it, expect } from 'vitest'
import { isNavActive, findNavMatch, canAccessNavItem } from './appNav.js'
describe('appNav extra', () => {
  it('isNavActive', () => expect(isNavActive('/command-center/operations', '/command-center/operations')).toBe(true))
  it('findNavMatch', () => expect(findNavMatch('/engines')).toBeTruthy())
  it('canAccessNavItem admin', () => {
    expect(canAccessNavItem({ to: '/admin' }, { is_superadmin: true })).toBe(true)
  })
})