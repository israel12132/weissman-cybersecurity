import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'LivePipelineMonitor.jsx'),
  'utf8',
)

describe('LivePipelineMonitor live-only truth', () => {
  it('does not paint an empty DAG canvas when GET /api/dag fails', () => {
    expect(src).toMatch(/data-testid="live-pipeline-dag-unavailable"/)
    expect(src).toMatch(/dag_unavailable/)
    expect(src).toMatch(/setDagUnavailable\(true\)/)
    expect(src).toMatch(/!Array\.isArray\(d\.nodes\)/)
  })
})
