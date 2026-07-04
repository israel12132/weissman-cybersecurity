import { describe, it, expect } from 'vitest'
import { exportPolicyFindingsCsv } from './exportFindingsCsv.js'
describe('exportPolicyFindingsCsv', () => {
  it('triggers download', () => {
    const clicked = []
    const orig = document.createElement
    document.createElement = (tag) => {
      const el = orig.call(document, tag)
      if (tag === 'a') el.click = () => clicked.push(1)
      return el
    }
    URL.createObjectURL = () => 'blob:test'
    URL.revokeObjectURL = () => {}
    exportPolicyFindingsCsv([{ control: 'AC-1', status: 'fail' }], 'policy')
    document.createElement = orig
    expect(clicked.length).toBe(1)
  })
})