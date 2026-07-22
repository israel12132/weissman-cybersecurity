import { describe, it, expect, beforeEach, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, act, waitFor } from '@testing-library/react'

// Mock the network layer the hook writes through.
vi.mock('../lib/apiBase', () => ({ apiFetch: vi.fn() }))
import { apiFetch } from '../lib/apiBase'
import { useApiMutation } from './useApiMutation.js'

function makeResponse({ ok = true, status = 200, body = '' } = {}) {
  return { ok, status, text: async () => body }
}

let queryClient
function wrapper({ children }) {
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
}

beforeEach(() => {
  vi.clearAllMocks()
  queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
})

describe('useApiMutation', () => {
  it('optimistically updates the cache and keeps it after a successful write', async () => {
    queryClient.setQueryData(['items'], [{ id: 1, status: 'open' }])
    apiFetch.mockResolvedValue(makeResponse({ body: '{"ok":true}' }))

    const { result } = renderHook(
      () =>
        useApiMutation({
          path: '/items/bulk',
          method: 'PATCH',
          optimisticKey: ['items'],
          optimisticUpdate: (prev, vars) =>
            (prev || []).map((it) => (it.id === vars.id ? { ...it, status: vars.status } : it)),
        }),
      { wrapper },
    )

    await act(async () => {
      result.current.mutate({ id: 1, status: 'closed' })
    })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(queryClient.getQueryData(['items'])[0].status).toBe('closed')
    // Request went out as JSON with the right method.
    expect(apiFetch).toHaveBeenCalledWith(
      '/items/bulk',
      expect.objectContaining({ method: 'PATCH' }),
    )
    const init = apiFetch.mock.calls[0][1]
    expect(JSON.parse(init.body)).toEqual({ id: 1, status: 'closed' })
    expect(init.headers['Content-Type']).toBe('application/json')
  })

  it('rolls the cache back when the write fails', async () => {
    queryClient.setQueryData(['items'], [{ id: 1, status: 'open' }])
    apiFetch.mockResolvedValue(makeResponse({ ok: false, status: 500, body: '{"detail":"boom"}' }))

    const { result } = renderHook(
      () =>
        useApiMutation({
          path: '/items/bulk',
          method: 'PATCH',
          optimisticKey: ['items'],
          optimisticUpdate: (prev, vars) =>
            (prev || []).map((it) => (it.id === vars.id ? { ...it, status: vars.status } : it)),
        }),
      { wrapper },
    )

    await act(async () => {
      result.current.mutate({ id: 1, status: 'closed' })
    })

    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error.message).toBe('boom')
    // Snapshot restored.
    expect(queryClient.getQueryData(['items'])[0].status).toBe('open')
  })

  it('supports a per-variables request builder and returns parsed JSON', async () => {
    apiFetch.mockResolvedValue(makeResponse({ body: '{"id":7,"status":"closed"}' }))

    const { result } = renderHook(
      () =>
        useApiMutation({
          request: (vars) => ({
            path: `/findings/${vars.id}`,
            method: 'PATCH',
            body: { status: vars.status },
          }),
        }),
      { wrapper },
    )

    let returned
    await act(async () => {
      returned = await result.current.mutateAsync({ id: 7, status: 'closed' })
    })

    expect(returned).toEqual({ id: 7, status: 'closed' })
    expect(apiFetch).toHaveBeenCalledWith(
      '/findings/7',
      expect.objectContaining({ method: 'PATCH' }),
    )
  })
})
