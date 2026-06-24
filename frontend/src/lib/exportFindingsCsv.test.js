import { describe, it, expect } from 'vitest'
import { exportStandardFindingsCsv, escapeCsvCell } from './exportFindingsCsv'

describe('exportFindingsCsv', () => {
  it('escapes quotes in CSV cells', () => {
    expect(escapeCsvCell('say "hello"')).toBe('"say ""hello"""')
  })

  it('exports header and rows', () => {
    const clicked = []
    const orig = document.createElement
    document.createElement = (tag) => {
      const el = orig.call(document, tag)
      if (tag === 'a') {
        el.click = () => clicked.push(el.download)
      }
      return el
    }
    URL.createObjectURL = () => 'blob:test'
    URL.revokeObjectURL = () => {}

    exportStandardFindingsCsv(
      [{ severity: 'high', title: 'Test', type: 'jwt', description: 'd', remediation: 'r' }],
      'test-export',
    )

    document.createElement = orig
    expect(clicked.length).toBe(1)
    expect(clicked[0]).toMatch(/^test-export-\d{4}-\d{2}-\d{2}\.csv$/)
  })
})
