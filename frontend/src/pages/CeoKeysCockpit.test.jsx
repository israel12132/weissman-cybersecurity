import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, d) => (typeof d === 'string' ? d : k), i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const get = vi.fn()
const put = vi.fn()
const post = vi.fn()
const del = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  api: {
    get: (...args) => get(...args),
    put: (...args) => put(...args),
    post: (...args) => post(...args),
    delete: (...args) => del(...args),
  },
}))

vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ title, actions, children }) => (
    <div>
      <h1>{title}</h1>
      <div>{actions}</div>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/engine/WeissmanListToolbar', () => ({
  __esModule: true,
  default: ({ searchQuery, onSearchChange }) => (
    <input
      type="search"
      value={searchQuery}
      onChange={(e) => onSearchChange(e.target.value)}
      aria-label="search"
    />
  ),
}))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: (findings) => ({
    exportCsv: vi.fn(),
    filteredFindings: findings,
    searchQuery: '',
    setSearchQuery: vi.fn(),
  }),
}))
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast: { success: vi.fn(), error: vi.fn() }, success: vi.fn(), error: vi.fn() }),
}))
vi.mock('../utils/confirmDialog', () => ({ confirmDialog: vi.fn(async () => true) }))
vi.mock('../hooks/useFocusTrap', () => ({ __esModule: true, default: () => {} }))

import CeoKeysCockpit from './CeoKeysCockpit.jsx'

const payload = {
  summary: { total: 2, armed: 1, missing: 1, required_missing: 1, custom: 0 },
  keys: [
    {
      env_name: 'WEISSMAN_LLM_API_KEY',
      aliases: ['OPENAI_API_KEY'],
      category: 'llm',
      is_secret: true,
      requires_restart: false,
      tier: 'recommended',
      custom: false,
      configured: false,
      sources: [],
      last4: null,
      value_len: null,
      preview: null,
      in_keyring: false,
    },
    {
      env_name: 'NVD_API_KEY',
      aliases: [],
      category: 'intel',
      is_secret: true,
      requires_restart: false,
      tier: 'recommended',
      custom: false,
      configured: true,
      sources: ['env'],
      last4: 'e123',
      value_len: 19,
      preview: null,
      in_keyring: false,
    },
  ],
}

describe('CeoKeysCockpit', () => {
  beforeEach(() => {
    get.mockReset()
    put.mockReset()
    get.mockResolvedValue(payload)
  })
  afterEach(cleanup)

  it('renders armed and missing keys from the live CEO API', async () => {
    render(
      <MemoryRouter>
        <CeoKeysCockpit />
      </MemoryRouter>,
    )
    await waitFor(() => expect(get).toHaveBeenCalledWith('/api/ceo/platform-keys'))
    expect(await screen.findByText('WEISSMAN_LLM_API_KEY')).toBeInTheDocument()
    expect(screen.getByText('NVD_API_KEY')).toBeInTheDocument()
    expect(screen.getByText('pages.ceoKeysCockpit.missing')).toBeInTheDocument()
    expect(screen.getByText('pages.ceoKeysCockpit.armed')).toBeInTheDocument()
    expect(screen.queryByText('supersecretvalue123')).not.toBeInTheDocument()
  })

  it('opens the add dialog for a missing key', async () => {
    render(
      <MemoryRouter>
        <CeoKeysCockpit />
      </MemoryRouter>,
    )
    const addButtons = await screen.findAllByText('pages.ceoKeysCockpit.add')
    fireEvent.click(addButtons[0])
    expect(screen.getByDisplayValue('WEISSMAN_LLM_API_KEY')).toBeInTheDocument()
    expect(screen.getByText('pages.ceoKeysCockpit.add_title')).toBeInTheDocument()
  })
})
