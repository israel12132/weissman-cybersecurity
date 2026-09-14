import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CICDThreatMatrix.jsx'),
  'utf8',
)

const fetchFx = src.slice(
  src.indexOf('const fetchFindings = useCallback'),
  src.indexOf('const runScan'),
)
const run = src.slice(src.indexOf('const runScan'), src.indexOf('return ('))

describe('CICDThreatMatrix live-only truth', () => {
  it('mutes leftover leftover-playbook modal after a failed GET /cicd-findings', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/clients\/\$\{clientId\}\/cicd-findings`/)
    expect(src).toMatch(/\{modalFinding && !findingsError && \(/)
    expect(src).toMatch(/useFocusTrap\(modalRef, !!modalFinding && !findingsError\)/)
    expect(src).toMatch(/data-testid="cicd-lab-unavailable"/)
  })

  it('keeps leftover leftover-modalFinding in state and does not catch-clear it', () => {
    expect(fetchFx).not.toMatch(/setModalFinding\(null\)/)
    expect(fetchFx).toMatch(/setFindingsError\(e\?\.message \|\| t\(`\$\{NS\}\.fetch_failed`\)\)/)
    expect(src).toMatch(/modalFinding\.blast_radius/)
  })

  it('keeps findingsError GET-only — pipeline run POST does not set findingsError', () => {
    expect(run).not.toMatch(/setFindingsError/)
    expect(run).toMatch(/method: 'POST'/)
    expect(run).toMatch(/\.catch\(\(\) => fetchFindings\(\)\)/)
  })
})
