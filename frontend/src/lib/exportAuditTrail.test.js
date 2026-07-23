import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  auditTrailToRows,
  auditTrailToJson,
  exportAuditTrailCsv,
  exportAuditTrailJson,
} from './exportAuditTrail.js'

const entries = [
  { timestamp: '2026-07-22T09:00:00Z', actor: 'ada', action: 'login', target: 'console', ip: '10.0.0.1', result: 'success', detail: '' },
  { timestamp: '2026-07-22T09:05:00Z', actor: 'grace', action: 'delete', target: 'finding:42', ip: '10.0.0.2', result: 'failure', detail: 'denied' },
]

describe('exportAuditTrail', () => {
  it('maps entries to a stable header + rows', () => {
    const { header, rows } = auditTrailToRows(entries)
    expect(header).toEqual(['timestamp', 'actor', 'action', 'target', 'ip', 'result', 'detail'])
    expect(rows[0][1]).toBe('ada')
    expect(rows[1][2]).toBe('delete')
  })

  it('serializes to JSON with the column subset', () => {
    const json = JSON.parse(auditTrailToJson(entries))
    expect(json).toHaveLength(2)
    expect(json[0].actor).toBe('ada')
    expect(json[1].result).toBe('failure')
  })

  it('fills missing fields with empty/null', () => {
    const { rows } = auditTrailToRows([{ actor: 'x' }])
    expect(rows[0][0]).toBe('') // timestamp missing
    const json = JSON.parse(auditTrailToJson([{ actor: 'x' }]))
    expect(json[0].timestamp).toBe(null)
  })
})

describe('exportAuditTrail downloads', () => {
  let clickSpy
  beforeEach(() => {
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })
  afterEach(() => {
    clickSpy.mockRestore()
  })

  it('triggers a CSV download', () => {
    exportAuditTrailCsv(entries)
    expect(URL.createObjectURL).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalled()
  })

  it('triggers a JSON download', () => {
    exportAuditTrailJson(entries)
    expect(URL.createObjectURL).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalled()
  })
})
