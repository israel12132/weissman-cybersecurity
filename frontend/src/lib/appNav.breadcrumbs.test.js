import { describe, it, expect } from 'vitest'
import { buildBreadcrumbs, PRIMARY_NAV, NAV_GROUPS } from './appNav.js'
describe('appNav breadcrumbs', () => {
  it('primary nav', () => expect(PRIMARY_NAV.length).toBeGreaterThan(3))
  it('lists dominion once in the sidebar', () => {
    expect(PRIMARY_NAV.filter((i) => i.to === '/dominion')).toHaveLength(1)
    expect(NAV_GROUPS.flatMap((g) => g.items).filter((i) => i.to === '/dominion')).toHaveLength(0)
  })
  it('breadcrumbs', () => {
    const c = buildBreadcrumbs('/engines', { pageTitle: 'Engines', t: (k) => k })
    expect(c.length).toBeGreaterThan(0)
  })
})