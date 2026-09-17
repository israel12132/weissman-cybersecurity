import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

vi.mock('react-router', () => ({
  useParams: () => ({ clientId: '7' }),
  Link: ({ children, to }) => <a href={to}>{children}</a>,
}))

vi.mock('framer-motion', () => ({
  motion: new Proxy({}, { get: () => (p) => <div {...p} /> }),
}))

vi.mock('../ui/StandaloneLabShell', () => ({
  __esModule: true,
  default: ({ children }) => <div>{children}</div>,
}))

const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import AttackChainView from './AttackChainView.jsx'

describe('AttackChainView', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint no-chain theater when the attack-chain API is unavailable', async () => {
    apiFetch.mockResolvedValue({
      ok: false,
      unavailable: true,
      steps: [],
      detail: 'store down',
    })
    render(<AttackChainView />)
    expect(await screen.findByTestId('attack-chain-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.tools.attackChainView.no_chain')).toBeNull()
  })

  it('renders live steps when the store answers', async () => {
    apiFetch.mockResolvedValue({
      steps: [{ step_order: 1, step_label: 'Initial access', payload_or_action: 'http' }],
    })
    render(<AttackChainView />)
    expect(await screen.findByText('Initial access')).toBeTruthy()
    expect(screen.queryByTestId('attack-chain-unavailable')).toBeNull()
  })
})
