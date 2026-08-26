import { describe, it, expect } from 'vitest'
import { isTenantFullScanTimeout, tenantFullScanTimeoutSecs } from './jobLastErrorExplain.js'

describe('jobLastErrorExplain', () => {
  it('detects the worker tenant_full_scan wall-clock timeout', () => {
    const err = 'job timed out after 3600s (tenant_full_scan)'
    expect(isTenantFullScanTimeout(err)).toBe(true)
    expect(tenantFullScanTimeoutSecs(err)).toBe(3600)
  })

  it('ignores other errors', () => {
    expect(isTenantFullScanTimeout('scan cycle failed: db')).toBe(false)
    expect(isTenantFullScanTimeout('')).toBe(false)
    expect(isTenantFullScanTimeout(null)).toBe(false)
  })
})
