import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('../utils/apiFetch', () => ({
  apiFetch: vi.fn(),
}))

import { apiFetch } from '../utils/apiFetch'
import { downloadApiFile } from './downloadApiFile'

describe('downloadApiFile', () => {
  beforeEach(() => {
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn(() => 'blob:mock'),
      revokeObjectURL: vi.fn(),
    })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  it('uses content-disposition filename when present', async () => {
    const click = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(click)
    apiFetch.mockResolvedValue({
      headers: new Headers({ 'content-disposition': 'attachment; filename="Weissman_Board.xlsx"' }),
      blob: async () => new Blob(['PK']),
    })
    const name = await downloadApiFile('/api/findings/export/xlsx', 'fallback.xlsx')
    expect(name).toBe('Weissman_Board.xlsx')
    expect(apiFetch).toHaveBeenCalledWith('/api/findings/export/xlsx', { raw: true })
    expect(click).toHaveBeenCalled()
  })
})
