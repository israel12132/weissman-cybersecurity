import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent, within } from '@testing-library/react'

vi.mock('react-i18next', () => {
  const t = (k) => k
  return { useTranslation: () => ({ t, i18n: { language: 'en' } }) }
})
vi.mock('react-router', () => ({ Link: ({ children }) => <a>{children}</a> }))
vi.mock('../../context/ClientContext', () => ({
  useClient: () => ({ selectedClientId: 'c1', selectedClient: { id: 'c1' } }),
}))
// Stub the evidence drawer so we can observe whether a row-click opened it (and for which finding).
vi.mock('../warroom/DigitalEvidenceHUD', () => ({
  default: ({ finding }) => <div data-testid="evidence-drawer" data-open-finding={finding ? finding.id : ''} />,
}))
// Stub the interactive verify controls with a real button we can click.
vi.mock('../findings/FindingLiveVerify', () => ({
  default: () => <button type="button" data-testid="verify-btn">verify</button>,
  LiveVerdictBadge: () => <span data-testid="verdict" />,
}))
const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../../utils/apiFetch', () => ({ apiFetch }))

import FindingsTab from './FindingsTab'

const FINDINGS = [
  { id: 11, title: 'Reflected XSS on /search', severity: 'high', source: 'xss_engine' },
  { id: 22, title: 'Open S3 bucket', severity: 'critical', source: 'asm' },
]

beforeEach(() => {
  apiFetch.mockReset()
  apiFetch.mockImplementation((url) =>
    Promise.resolve(String(url).includes('/findings') ? { findings: FINDINGS } : {}),
  )
})
afterEach(() => cleanup())

describe('FindingsTab → DataTable', () => {
  it('renders findings, opens the evidence drawer on row-click, and stops propagation on the verify control', async () => {
    render(<FindingsTab />)
    await waitFor(() => expect(screen.getByText('Reflected XSS on /search')).toBeInTheDocument())

    const bodyRows = document.querySelectorAll('table tbody tr')
    expect(bodyRows.length).toBe(FINDINGS.length)
    // drawer starts closed
    expect(screen.getByTestId('evidence-drawer').getAttribute('data-open-finding')).toBe('')

    // Clicking a row opens the evidence drawer for THAT finding.
    fireEvent.click(screen.getByText('Reflected XSS on /search'))
    await waitFor(() =>
      expect(screen.getByTestId('evidence-drawer').getAttribute('data-open-finding')).toBe('11'),
    )

    // Clicking the verify control in the OTHER row must NOT change the drawer (stopPropagation).
    const secondRow = bodyRows[1]
    fireEvent.click(within(secondRow).getByTestId('verify-btn'))
    // still finding 11 (row-2's verify click did not open the drawer for finding 22)
    expect(screen.getByTestId('evidence-drawer').getAttribute('data-open-finding')).toBe('11')
  })
})
