import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key, opts = {}) => {
      const map = {
        'roeBlocked.badge': 'RoE blocked',
        'roeBlocked.title': 'Rules of Engagement blocked this probe',
        'roeBlocked.notEmpty': 'This is not an empty scan. Critical-infrastructure engines did not run.',
        'roeBlocked.control': `Control: ${opts.control || ''}`,
        'roeBlocked.wouldRun': `If authorized, this engine would: ${opts.detail || ''}`,
        'roeBlocked.whoMustEnable': 'A tenant administrator must explicitly enable industrial OT. Weissman never auto-enables this flag.',
        'roeBlocked.enableTitle': 'How an admin enables OT (fail-closed)',
        'roeBlocked.enableStepOt': 'PATCH industrial_ot_enabled with X-Weissman-Destructive-Confirm.',
        'roeBlocked.enableStepRoe': 'Then complete remaining RoE gates.',
        'roeBlocked.enableStepAuth': 'Set probe authorization and whitelist.',
        'roeBlocked.clientId': `Client #${opts.id}`,
        'roeBlocked.timestamp': `Blocked at ${opts.time}`,
        'roeBlocked.neverAuto': 'Never auto-enabled',
      }
      return map[key] || key
    },
    i18n: { language: 'en' },
  }),
}))

import RoeBlockedState, { RoeBlockedBadge } from './RoeBlockedState.jsx'

describe('RoeBlockedState', () => {
  it('renders a distinct blocked badge, not a green empty scan', () => {
    render(<RoeBlockedBadge />)
    expect(screen.getByRole('status')).toHaveTextContent(/RoE blocked/i)
  })

  it('shows control, would-run, and never-auto copy', () => {
    render(
      <MemoryRouter>
        <RoeBlockedState
          roe={{
            control: 'industrial_ot_enabled',
            would_run_if_authorized: 'KNXnet/IP SEARCH_REQUEST (read-only)',
            client_id: 7,
            never_auto_enabled: true,
            who_must_enable: 'tenant_admin',
          }}
        />
      </MemoryRouter>,
    )
    expect(screen.getByText(/industrial_ot_enabled/)).toBeInTheDocument()
    expect(screen.getByText(/KNXnet/)).toBeInTheDocument()
    expect(screen.getByText(/never auto-enables/i)).toBeInTheDocument()
    expect(screen.queryByText(/0 findings/i)).not.toBeInTheDocument()
  })
})
