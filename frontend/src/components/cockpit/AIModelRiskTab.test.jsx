import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'

vi.mock('react-i18next', () => {
  const t = (k, fb) => (typeof fb === 'string' ? fb : k)
  return { useTranslation: () => ({ t }) }
})
vi.mock('react-router', () => ({ Link: ({ children }) => <a>{children}</a> }))
vi.mock('../../context/ClientContext', () => ({
  useClient: () => ({ selectedClientId: 'c1', selectedClient: { id: 'c1', name: 'Acme' } }),
}))
const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../../utils/apiFetch', () => ({ apiFetch }))

import AIModelRiskTab from './AIModelRiskTab'

const EVENTS = [
  { id: 'ev1', attack_vector: 'prompt_injection', endpoint_url: 'https://api.x/chat', leakage_score: 0.8, hallucination_score: 0.2, blocked: true },
  { id: 'ev2', attack_vector: 'jailbreak', endpoint_url: 'https://api.x/agent', leakage_score: 0.1, hallucination_score: 0.9, blocked: false },
]

beforeEach(() => {
  apiFetch.mockReset()
  apiFetch.mockImplementation((url) => {
    const u = String(url)
    if (u.includes('/events')) return Promise.resolve({ events: EVENTS })
    if (u.includes('/summary')) return Promise.resolve({ vectors: [] })
    return Promise.resolve({})
  })
})
afterEach(() => cleanup())

describe('AIModelRiskTab → DataTable', () => {
  it('renders recent LLM-fuzz events through the DataTable primitive with score cells', async () => {
    render(<AIModelRiskTab />)
    await waitFor(() => expect(screen.getByText('https://api.x/chat')).toBeInTheDocument())
    const bodyRows = document.querySelectorAll('#ai-model-risk-events-table table tbody tr, table tbody tr')
    expect(bodyRows.length).toBe(EVENTS.length)
    // score cells rendered with toFixed(2)
    expect(screen.getByText('0.80')).toBeInTheDocument()
    expect(screen.getByText('0.90')).toBeInTheDocument()
  })
})
