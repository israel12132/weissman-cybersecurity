import { describe, expect, it } from 'vitest'
import { filterClientsForOperatorRoster, isSandboxClient, shouldShowSandboxClients } from './clientRoster'

describe('clientRoster', () => {
  it('detects sandbox clients by name', () => {
    expect(isSandboxClient({ name: 'E2E Pipeline Client' })).toBe(true)
    expect(isSandboxClient({ name: 'Playwright E2E 123' })).toBe(true)
    expect(isSandboxClient({ name: 'Tesla Inc. (Bugcrowd VRP)' })).toBe(false)
  })

  it('filters sandbox clients from operator roster by default', () => {
    const all = [
      { id: 1, name: 'E2E Pipeline Client' },
      { id: 4, name: 'Tesla Inc. (Bugcrowd VRP)' },
    ]
    expect(filterClientsForOperatorRoster(all)).toEqual([{ id: 4, name: 'Tesla Inc. (Bugcrowd VRP)' }])
  })

  it('shows sandbox when localStorage toggle is set', () => {
    const key = 'weissman.show_sandbox_clients'
    localStorage.setItem(key, '1')
    expect(shouldShowSandboxClients()).toBe(true)
    const all = [{ id: 1, name: 'E2E Pipeline Client' }]
    expect(filterClientsForOperatorRoster(all)).toHaveLength(1)
    localStorage.removeItem(key)
  })
})
