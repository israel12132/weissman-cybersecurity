import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

vi.mock('../components/ui/Button', () => ({
  __esModule: true,
  default: ({ children, onClick, disabled }) => (
    <button type="button" onClick={onClick} disabled={disabled}>{children}</button>
  ),
}))
vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ title, children }) => (
    <div>
      <h1>{title}</h1>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/DataTable', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/Toaster', () => ({ useToast: () => ({ toast: () => {} }) }))
vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    clients: [{ id: 1, name: 'Acme' }],
    selectedClientId: 1,
    setSelectedClientId: () => {},
  }),
}))
vi.mock('../utils/apiFetch', () => ({
  apiFetch: async () => ({
    snapshot: {
      entry_count: 3,
      jewel_count: 0,
      paths: [],
      choke_points: [],
      computed_at_unix: 1_700_000_000,
      total_path_ale_usd: 0,
      max_path_score: 0,
    },
  }),
}))

import AttackPaths from './AttackPaths.jsx'

describe('AttackPaths jewel banner', () => {
  it('shows the zero-jewel auto-tag banner when the live snapshot has no jewels', async () => {
    render(<AttackPaths />)
    expect(await screen.findByTestId('jewel-auto-tag-banner')).toBeTruthy()
    expect(screen.getByText('pages.attackPaths.zero_jewel_title')).toBeTruthy()
  })
})
