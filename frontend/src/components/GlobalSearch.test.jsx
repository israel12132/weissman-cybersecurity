import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'

// --- Mocks: keep the palette isolated from router/auth/i18n/network ---
const navigateSpy = vi.fn()
vi.mock('react-router-dom', () => ({ useNavigate: () => navigateSpy }))
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, opts) => (opts?.query ? `${k}:${opts.query}` : k) }),
}))
vi.mock('../context/AuthContext', () => ({
  // A session with no special role → items without minRole stay accessible.
  useAuth: () => ({ session: { role: 'admin', roleRank: 3 } }),
}))
vi.mock('../lib/apiBase', () => ({
  apiFetch: vi.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve({ results: [] }) })),
}))
// Deterministic nav registry so assertions don't depend on the real appNav.
vi.mock('../lib/appNav', () => ({
  PRIMARY_NAV: [
    { to: '/clients', labelKey: 'Clients', icon: '🏢' },
    { to: '/engines', labelKey: 'Engines', icon: '⬡' },
  ],
  NAV_GROUPS: [
    { id: 'cmd', labelKey: 'g', items: [
      { to: '/audit', labelKey: 'Audit Log', icon: '📋' },
      { to: '/findings', labelKey: 'Findings', icon: '◉' },
    ] },
  ],
  canAccessNavItem: () => true,
}))

import GlobalSearch from './GlobalSearch'

function open() {
  fireEvent.keyDown(document, { key: 'k', ctrlKey: true })
}

beforeEach(() => { navigateSpy.mockClear() })
afterEach(() => cleanup())

describe('GlobalSearch command palette', () => {
  it('is hidden until Ctrl+K, then shows quick-nav suggestions', () => {
    render(<GlobalSearch />)
    expect(screen.queryByRole('dialog')).toBeNull()
    open()
    expect(screen.getByRole('dialog')).toBeTruthy()
    // Idle → quick-nav options rendered from the registry.
    const options = screen.getAllByRole('option')
    expect(options.length).toBeGreaterThanOrEqual(4)
    expect(screen.getByText('Audit Log')).toBeTruthy()
  })

  it('filters routes instantly by query with no network round-trip', () => {
    render(<GlobalSearch />)
    open()
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'audit' } })
    const options = screen.getAllByRole('option')
    expect(options.length).toBe(1)
    expect(within(options[0]).getByText('Audit Log')).toBeTruthy()
  })

  it('navigates to the highlighted route on Enter (keyboard only)', () => {
    render(<GlobalSearch />)
    open()
    const input = screen.getByRole('combobox')
    fireEvent.change(input, { target: { value: 'audit' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(navigateSpy).toHaveBeenCalledWith('/audit')
  })

  it('ArrowDown moves the active option before Enter', () => {
    render(<GlobalSearch />)
    open()
    const input = screen.getByRole('combobox')
    // idle quick-nav: first item is /clients; ArrowDown → /engines.
    fireEvent.keyDown(input, { key: 'ArrowDown' })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(navigateSpy).toHaveBeenCalledWith('/engines')
  })

  it('Escape closes the palette', () => {
    render(<GlobalSearch />)
    open()
    expect(screen.getByRole('dialog')).toBeTruthy()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})
