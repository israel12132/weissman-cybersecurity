import { describe, it, expect } from 'vitest'
import { complianceCsvRows, COMPLIANCE_CSV_HEADER } from './CompliancePosturePanel.jsx'

describe('CompliancePosturePanel helpers', () => {
  describe('complianceCsvRows', () => {
    it('emits one row per control across frameworks, aligned with the header', () => {
      const rows = complianceCsvRows([
        {
          framework: 'OWASP Top 10 2021',
          controls: [
            { control: 'A03:2021', title: 'Injection', finding_count: 3, critical: 1, high: 2, medium: 0, low: 0, info: 0, other: 0 },
          ],
        },
        {
          framework: 'PCI DSS 4.0',
          controls: [
            { control: '6.2.4', title: 'Injection prevention', finding_count: 3, critical: 1, high: 2, medium: 0, low: 0, info: 0, other: 0 },
          ],
        },
      ])
      expect(rows).toHaveLength(2)
      expect(rows[0]).toHaveLength(COMPLIANCE_CSV_HEADER.length)
      expect(rows[0][0]).toBe('OWASP Top 10 2021')
      expect(rows[0][1]).toBe('A03:2021')
      expect(rows[1][0]).toBe('PCI DSS 4.0')
    })

    it('is robust to missing fields / non-array input', () => {
      expect(complianceCsvRows(null)).toEqual([])
      expect(complianceCsvRows(undefined)).toEqual([])
      expect(complianceCsvRows([{ framework: 'X' }])).toEqual([]) // no controls → no rows
      const rows = complianceCsvRows([{ framework: 'X', controls: [{}] }])
      expect(rows[0]).toHaveLength(COMPLIANCE_CSV_HEADER.length)
      expect(rows[0][3]).toBe(0) // finding_count defaults to 0
    })
  })
})
