import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('../../context/ClientContext', () => ({
  useClient: () => ({ selectedClientId: '7' }),
}))
vi.mock('../../context/WarRoomContext', () => ({
  useWarRoom: () => ({ lastTelemetry: null }),
}))
vi.mock('@xyflow/react', () => ({
  ReactFlow: () => null,
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  useNodesState: () => [[], vi.fn(), vi.fn()],
  useEdgesState: () => [[], vi.fn(), vi.fn()],
}))
const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import LivePipelineMonitor from './LivePipelineMonitor.jsx'

describe('LivePipelineMonitor', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not claim no active run when pipeline state is unavailable', async () => {
    apiFetch.mockImplementation((url) => {
      if (String(url).includes('/api/pipeline/state')) {
        return Promise.reject(new Error('store down'))
      }
      return Promise.resolve({ nodes: [], edges: [] })
    })
    render(<LivePipelineMonitor />)
    expect(await screen.findByTestId('pipeline-monitor-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.cockpitTabs.livePipelineMonitor.noActiveRun')).toBeNull()
  })
})
