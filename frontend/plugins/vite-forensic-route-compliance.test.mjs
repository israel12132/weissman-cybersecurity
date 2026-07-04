import { describe, it, expect } from 'vitest'
import { auditForensicRoutes } from './vite-forensic-route-compliance.mjs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

describe('forensic route compliance plugin', () => {
  it('passes for all engine hub routes in the registry', () => {
    const violations = auditForensicRoutes({
      root,
      srcDir: path.join(root, 'src'),
    })
    expect(violations).toEqual([])
  })

  it('requires websocket-security evidence registry entry', async () => {
    const { ROUTE_EVIDENCE } = await import('../src/lib/routeEvidence.js')
    expect(ROUTE_EVIDENCE['/websocket-security']).toBe('pages.websocketSecurity.evidence_notice')
  })
})
