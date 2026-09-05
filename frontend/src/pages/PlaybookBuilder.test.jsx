import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { CUSTOM_STORAGE_KEY } from '../lib/playbookCatalog.js'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => (typeof d === 'string' ? d : k),
    i18n: { language: 'en' },
  }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../components/PlaybookGraph', () => ({
  __esModule: true,
  default: () => <div data-testid="playbook-graph" />,
}))

vi.mock('../components/engine/ShellScanActions', () => ({
  __esModule: true,
  default: () => null,
}))

vi.mock('../utils/confirmDialog', () => ({
  confirmDialog: vi.fn(async () => true),
  promptDialog: vi.fn(async () => 'Night desk'),
}))

import PlaybookBuilder from './PlaybookBuilder.jsx'

describe('PlaybookBuilder catalog', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    apiFetch.mockResolvedValue({ playbooks: [] })
    try { localStorage.removeItem(CUSTOM_STORAGE_KEY) } catch { /* jsdom */ }
  })
  afterEach(cleanup)

  it('shows selectable built-in playbooks and a blank-canvas option', async () => {
    render(
      <MemoryRouter>
        <PlaybookBuilder />
      </MemoryRouter>,
    )
    await waitFor(() => {
      expect(screen.getByTestId('playbook-catalog')).toBeTruthy()
    })
    expect(screen.getByTestId('playbook-blank')).toBeTruthy()
    expect(screen.getByTestId('playbook-template-kev-exposed-containment')).toBeTruthy()
    expect(screen.getByTestId('playbook-template-secret-leak-break-glass')).toBeTruthy()
    expect(screen.getByTestId('playbook-template-identity-attack-containment')).toBeTruthy()
    expect(screen.getByTestId('playbook-template-iac-supply-chain-pr')).toBeTruthy()
    expect(screen.getAllByTestId(/playbook-template-/).length).toBeGreaterThanOrEqual(12)
  })

  it('loads a catalog playbook into the editor as a disabled draft', async () => {
    render(
      <MemoryRouter>
        <PlaybookBuilder />
      </MemoryRouter>,
    )
    await waitFor(() => screen.getByTestId('playbook-template-kev-exposed-containment'))
    const card = screen.getByTestId('playbook-template-kev-exposed-containment')
    fireEvent.click(card.querySelector('button'))
    await waitFor(() => {
      expect(screen.getByTestId('playbook-name').value).toBe('Critical KEV → isolate + page')
    })
    const enabled = screen.getByRole('checkbox')
    expect(enabled.checked).toBe(false)
  })

  it('starts a blank playbook from the catalog card', async () => {
    render(
      <MemoryRouter>
        <PlaybookBuilder />
      </MemoryRouter>,
    )
    await waitFor(() => screen.getByTestId('playbook-blank'))
    fireEvent.click(screen.getByTestId('playbook-blank'))
    await waitFor(() => {
      expect(screen.getByTestId('playbook-name').value).toBe('')
    })
  })
})
