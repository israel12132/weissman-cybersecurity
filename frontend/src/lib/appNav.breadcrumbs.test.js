import { describe, it, expect } from 'vitest'
import { buildBreadcrumbs, PRIMARY_NAV } from './appNav.js'
describe('appNav breadcrumbs', () => {
  it('primary nav', () => expect(PRIMARY_NAV.length).toBeGreaterThan(3))
  it('breadcrumbs', () => {
    const c = buildBreadcrumbs('/engines', { pageTitle: 'Engines', t: (k) => k })
    expect(c.length).toBeGreaterThan(0)
  })
})