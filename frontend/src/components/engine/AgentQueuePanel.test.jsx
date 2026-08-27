import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, d) => (typeof d === 'string' ? d : k), i18n: { language: 'en' } }),
}))

const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../../hooks/useAgentFleetStatus', () => ({
  useAgentFleetStatus: () => ({
    hasOnlineAgent: false,
    onlineCount: 0,
    loading: false,
  }),
}))

import AgentQueuePanel from './AgentQueuePanel.jsx'

describe('AgentQueuePanel', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    apiFetch.mockResolvedValue({
      ok: true,
      pending: 2,
      running: 0,
      waiting: 2,
      tasks: [
        {
          task_id: 't-1',
          engine: 'process_hollowing',
          target: 'host.local',
          status: 'pending',
          scan_job_id: 'job-aaa',
        },
      ],
    })
  })
  afterEach(cleanup)

  it('renders live queue truth without invented findings', async () => {
    render(
      <MemoryRouter>
        <AgentQueuePanel engineId="process_hollowing" clientId={7} />
      </MemoryRouter>,
    )
    expect(await screen.findByTestId('agent-queue-panel')).toBeInTheDocument()
    expect(screen.getByText('agentRequired.queue_title')).toBeInTheDocument()
    expect(await screen.findByText('process_hollowing')).toBeInTheDocument()
    expect(screen.queryByText(/fake/i)).not.toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalled()
    const url = apiFetch.mock.calls[0][0]
    expect(url).toContain('/api/agents/queue')
    expect(url).toContain('engine=process_hollowing')
    expect(url).toContain('client_id=7')
  })
})
