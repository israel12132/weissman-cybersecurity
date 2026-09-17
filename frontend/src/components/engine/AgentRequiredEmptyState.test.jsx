import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

import AgentRequiredEmptyState from './AgentRequiredEmptyState.jsx'

describe('AgentRequiredEmptyState', () => {
  afterEach(cleanup)

  it('asks the operator to enroll when the fleet is known empty', () => {
    render(
      <MemoryRouter>
        <AgentRequiredEmptyState engineId="ebpf_sensor" />
      </MemoryRouter>,
    )
    const node = screen.getByTestId('agent-required-empty')
    expect(node.getAttribute('data-unavailable')).toBe('false')
    expect(node.getAttribute('data-live')).toBe('false')
    expect(node.textContent).toMatch(/agentRequired.empty_title/)
    expect(node.textContent).toMatch(/ebpf_sensor/)
    expect(node.textContent).not.toMatch(/agentRequired.unavailable_title/)
  })

  it('does not tell the operator to install an agent when status is unknown', () => {
    const onRetry = vi.fn()
    render(
      <MemoryRouter>
        <AgentRequiredEmptyState engineId="ebpf_sensor" unavailable onRetry={onRetry} />
      </MemoryRouter>,
    )
    const node = screen.getByTestId('agent-required-empty')
    expect(node.getAttribute('data-unavailable')).toBe('true')
    expect(node.getAttribute('data-live')).toBe('false')
    expect(node.textContent).toMatch(/agentRequired.unavailable_title/)
    expect(node.textContent).not.toMatch(/agentRequired.empty_title/)
    expect(node.textContent).not.toMatch(/agentRequired.install_hint/)
    expect(node.textContent).not.toMatch(/agentRequired.install_cta/)
  })

  it('does not fall through to install copy when retry is missing', () => {
    render(
      <MemoryRouter>
        <AgentRequiredEmptyState engineId="ebpf_sensor" unavailable />
      </MemoryRouter>,
    )
    const node = screen.getByTestId('agent-required-empty')
    expect(node.getAttribute('data-unavailable')).toBe('true')
    expect(node.textContent).toMatch(/agentRequired.open_management/)
    expect(node.textContent).not.toMatch(/agentRequired.empty_title/)
    expect(node.textContent).not.toMatch(/agentRequired.install_hint/)
  })
})
