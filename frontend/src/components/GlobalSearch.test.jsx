import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'

// --- Mocks: keep the palette isolated from router/auth/i18n/network ---
const navigateSpy = vi.fn()
let mockPathname = '/findings'
vi.mock('react-router-dom', () => ({
  useNavigate: () => navigateSpy,
  useLocation: () => ({ pathname: mockPathname }),
}))
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, opts) => (opts?.query ? `${k}:${opts.query}` : k) }),
}))
const logoutSpy = vi.fn()
vi.mock('../context/AuthContext', () => ({
  // A session with no special role → items without minRole stay accessible.
  useAuth: () => ({ session: { role: 'admin', roleRank: 3 }, logout: logoutSpy }),
}))
const toggleThemeSpy = vi.fn()
vi.mock('../context/ThemeContext', () => ({
  useTheme: () => ({ toggleTheme: toggleThemeSpy, isLight: false }),
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

beforeEach(() => {
  navigateSpy.mockClear(); logoutSpy.mockClear(); toggleThemeSpy.mockClear()
  mockPathname = '/findings'
  try { localStorage.clear() } catch { /* ignore */ }
})
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

  it('runs a matched global action (theme toggle) on Enter', () => {
    render(<GlobalSearch />)
    open()
    const input = screen.getByRole('combobox')
    // 'theme' matches the theme-toggle action label, not any route.
    fireEvent.change(input, { target: { value: 'theme' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(toggleThemeSpy).toHaveBeenCalledTimes(1)
    expect(navigateSpy).not.toHaveBeenCalled()
  })

  it('does not show actions in the idle quick-nav list', () => {
    render(<GlobalSearch />)
    open()
    // Idle: only nav suggestions, no Sign out / theme actions.
    expect(screen.queryByText('components.globalSearch.action_signout')).toBeNull()
  })

  it('surfaces a recently-visited route in the idle list', () => {
    // Seed a prior visit to /audit, then land on /findings.
    localStorage.setItem('weissman_palette_recents', JSON.stringify(['/audit', '/findings']))
    mockPathname = '/findings'
    render(<GlobalSearch />)
    open()
    const options = screen.getAllByRole('option')
    // The most-recent accessible route that isn't the current page appears first.
    expect(within(options[0]).getByText('Audit Log')).toBeTruthy()
    expect(within(options[0]).getByText('components.globalSearch.recent')).toBeTruthy()
  })

  it('Escape closes the palette', () => {
    render(<GlobalSearch />)
    open()
    expect(screen.getByRole('dialog')).toBeTruthy()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})
