import { describe, it, expect, vi, beforeEach, afterEach, beforeAll } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import FindingDrawer from './FindingDrawer.jsx'

// jsdom has no layout engine, so offsetParent is always null and the focus trap's
// visibility filter would find nothing. Shim it to the DOM parent (standard workaround)
// so focusable elements are considered visible.
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'offsetParent', {
    configurable: true,
    get() {
      return this.parentNode
    },
  })
})

// i18n is not initialised in the test env — return the key so assertions are stable.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))
// These children hit the network / are heavy; stub them so the drawer renders in isolation.
vi.mock('../findings/FindingLiveVerify', () => ({
  __esModule: true,
  default: () => null,
  LiveVerdictBadge: () => null,
  liveVerdictFromFinding: () => null,
}))
vi.mock('./SupplyChainGraph', () => ({ __esModule: true, default: () => null }))

const FINDING = {
  raw_id: 'f-1',
  title: 'SQL Injection in /login',
  severity: 'high',
  description: 'Boolean-based blind SQLi',
}

describe('FindingDrawer', () => {
  beforeEach(() => {
    document.body.style.overflow = ''
  })
  // vitest runs with globals:false, so RTL's automatic afterEach cleanup isn't registered.
  afterEach(cleanup)

  it('renders nothing when there is no finding (closed state)', () => {
    const { container } = render(<FindingDrawer finding={null} onClose={() => {}} />)
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(container.querySelector('[role="dialog"]')).toBeNull()
  })

  it('renders an accessible dialog with the finding title when open', () => {
    render(<FindingDrawer finding={FINDING} onClose={() => {}} />)
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(screen.getByText(/SQL Injection in \/login/)).toBeInTheDocument()
  })

  it('traps initial focus inside the drawer for keyboard users', () => {
    render(<FindingDrawer finding={FINDING} onClose={() => {}} />)
    const dialog = screen.getByRole('dialog')
    // useFocusTrap focuses the first focusable element inside the drawer on open.
    expect(dialog.contains(document.activeElement)).toBe(true)
  })

  it('closes on Escape', () => {
    const onClose = vi.fn()
    render(<FindingDrawer finding={FINDING} onClose={onClose} />)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('locks body scroll while open and restores it on close', () => {
    const { rerender } = render(<FindingDrawer finding={FINDING} onClose={() => {}} />)
    expect(document.body.style.overflow).toBe('hidden')
    rerender(<FindingDrawer finding={null} onClose={() => {}} />)
    expect(document.body.style.overflow).not.toBe('hidden')
  })
})
