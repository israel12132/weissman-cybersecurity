import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

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
vi.mock('../components/engine/ShellScanActions', () => ({
  __esModule: true,
  default: () => null,
}))
vi.mock('../components/engine/WeissmanListToolbar', () => ({
  __esModule: true,
  default: () => null,
}))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: () => ({
    exportCsv: vi.fn(),
    filteredFindings: [],
    searchQuery: '',
    setSearchQuery: vi.fn(),
  }),
}))

import AskWeissman from './AskWeissman.jsx'

describe('AskWeissman hermetic safeguards', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('renders tenant, weissman_ro, timeout, LIMIT 200, and sealed-plan guards', () => {
    render(
      <MemoryRouter>
        <AskWeissman />
      </MemoryRouter>,
    )
    const list = screen.getByRole('list', { name: 'ask_weissman.safeguards_aria' })
    expect(list).toHaveTextContent('ask_weissman.guard_tenant')
    expect(list).toHaveTextContent('ask_weissman.guard_role')
    expect(list).toHaveTextContent('ask_weissman.guard_timeout')
    expect(list).toHaveTextContent('ask_weissman.guard_limit')
    expect(list).toHaveTextContent('ask_weissman.guard_plan')
    expect(list).toHaveTextContent('ask_weissman.guard_oracle')
    expect(list).toHaveTextContent('ask_weissman.guard_mask')
    expect(list).toHaveTextContent('ask_weissman.guard_depth')
    expect(list).toHaveTextContent('ask_weissman.guard_vector')
    const input = screen.getByRole('textbox', { name: 'ask_weissman.placeholder' })
    expect(input).toHaveAttribute('maxLength', '2000')
  })

  it('posts only { question } and surfaces live seal/role/timeout/limit from the API', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      result: {
        plan: { table: 'vulnerabilities', select: ['id'], filters: [] },
        sql: 'SELECT "id" FROM (SELECT "id" FROM "vulnerabilities" WHERE "tenant_id" = $1) AS "_ask_tenant_scope" LIMIT 50',
        rows: [{ id: 1 }],
        row_count: 1,
        elapsed_ms: 12,
        error: null,
        plan_sealed: true,
        exec_role: 'weissman_ro',
        tenant_bound: 7,
        row_cap: 200,
        statement_timeout_ms: 15000,
      },
    })
    render(
      <MemoryRouter>
        <AskWeissman />
      </MemoryRouter>,
    )
    const input = screen.getByRole('textbox', { name: 'ask_weissman.placeholder' })
    fireEvent.change(input, { target: { value: 'show critical KEV findings' } })
    fireEvent.submit(input.closest('form'))
    await waitFor(() => expect(apiFetch).toHaveBeenCalled())
    expect(apiFetch).toHaveBeenCalledWith('/api/ask', {
      method: 'POST',
      body: { question: 'show critical KEV findings' },
    })
    expect(screen.getAllByText('ask_weissman.guard_plan').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText(/weissman_ro · 15000ms · LIMIT 200/)).toBeInTheDocument()
  })

  it('surfaces a generic 429 without oracle or rate internals', async () => {
    const err = new Error('Ask Weissman is temporarily unavailable. Retry later.')
    err.status = 429
    err.response = {
      json: async () => ({
        ok: false,
        code: 'rate_limited',
        detail: 'Ask Weissman is temporarily unavailable. Retry later.',
      }),
    }
    apiFetch.mockRejectedValue(err)
    render(
      <MemoryRouter>
        <AskWeissman />
      </MemoryRouter>,
    )
    const input = screen.getByRole('textbox', { name: 'ask_weissman.placeholder' })
    fireEvent.change(input, { target: { value: 'is there a client whose name starts with A?' } })
    fireEvent.submit(input.closest('form'))
    await waitFor(() => {
      expect(
        screen.getByText('Ask Weissman is temporarily unavailable. Retry later.'),
      ).toBeInTheDocument()
    })
    expect(screen.queryByText(/brute-force/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/limit_per_minute/i)).not.toBeInTheDocument()
  })
})
