import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

const gate = vi.hoisted(() => ({
  blocked: false,
  loading: false,
  isAgentRequired: true,
  fleetUnavailable: false,
  refresh: vi.fn(),
}))

vi.mock('../../hooks/useAgentRequiredGate', () => ({
  useAgentRequiredGate: () => gate,
}))

import AgentRequiredGate from './AgentRequiredGate.jsx'

describe('AgentRequiredGate', () => {
  afterEach(() => {
    cleanup()
    gate.blocked = false
    gate.loading = false
    gate.isAgentRequired = true
    gate.fleetUnavailable = false
  })

  it('renders children when an agent is online', () => {
    render(
      <MemoryRouter>
        <AgentRequiredGate engineId="ebpf_sensor">
          <div>scan-surface</div>
        </AgentRequiredGate>
      </MemoryRouter>,
    )
    expect(screen.getByText('scan-surface')).toBeTruthy()
  })

  it('shows the install empty state for a known-empty fleet', () => {
    gate.blocked = true
    render(
      <MemoryRouter>
        <AgentRequiredGate engineId="ebpf_sensor">
          <div>scan-surface</div>
        </AgentRequiredGate>
      </MemoryRouter>,
    )
    expect(screen.queryByText('scan-surface')).toBeNull()
    expect(screen.getByTestId('agent-required-empty').getAttribute('data-unavailable')).toBe('false')
    expect(screen.getByText('agentRequired.empty_title')).toBeTruthy()
  })

  it('shows the unknown-status empty state instead of install copy', () => {
    gate.fleetUnavailable = true
    render(
      <MemoryRouter>
        <AgentRequiredGate engineId="ebpf_sensor">
          <div>scan-surface</div>
        </AgentRequiredGate>
      </MemoryRouter>,
    )
    expect(screen.queryByText('scan-surface')).toBeNull()
    expect(screen.getByTestId('agent-required-empty').getAttribute('data-unavailable')).toBe('true')
    expect(screen.getByText('agentRequired.unavailable_title')).toBeTruthy()
    expect(screen.queryByText('agentRequired.empty_title')).toBeNull()
  })
})
