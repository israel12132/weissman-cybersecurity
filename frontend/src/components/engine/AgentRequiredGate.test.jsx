import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, d) => (typeof d === 'string' ? d : k), i18n: { language: 'en' } }),
}))

vi.mock('../../hooks/useAgentRequiredGate', () => ({
  useAgentRequiredGate: (id) => ({
    blocked: id === 'process_hollowing',
    isAgentRequired: id === 'process_hollowing',
    loading: false,
  }),
}))

vi.mock('./AgentQueuePanel', () => ({
  __esModule: true,
  default: ({ engineId }) => <div data-testid="queue">{engineId}</div>,
}))

vi.mock('../../context/EngineHubContext', () => ({
  useEngineHub: () => ({ hubClientId: '9' }),
}))

import AgentRequiredGate from './AgentRequiredGate.jsx'

describe('AgentRequiredGate', () => {
  afterEach(cleanup)

  it('keeps run controls visible for agent-required engines (enqueue, do not hide)', () => {
    render(
      <MemoryRouter>
        <AgentRequiredGate engineId="process_hollowing">
          <button type="button">Run engine</button>
        </AgentRequiredGate>
      </MemoryRouter>,
    )
    expect(screen.getByTestId('queue')).toHaveTextContent('process_hollowing')
    expect(screen.getByText('Run engine')).toBeInTheDocument()
  })

  it('does not wrap remote probes with the agent queue', () => {
    render(
      <MemoryRouter>
        <AgentRequiredGate engineId="liquid_matrix">
          <button type="button">Run remote</button>
        </AgentRequiredGate>
      </MemoryRouter>,
    )
    expect(screen.queryByTestId('queue')).not.toBeInTheDocument()
    expect(screen.getByText('Run remote')).toBeInTheDocument()
  })
})
