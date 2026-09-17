import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CemDagoMesh.jsx'),
  'utf8',
)

describe('CemDagoMesh live-only truth', () => {
  it('does not paint no_waves when CEM-DAGO mesh load fails', () => {
    expect(src).toMatch(/data-testid="cem-dago-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/!Array\.isArray\(man\?\.manifests\) \|\| !Array\.isArray\(wv\?\.waves\)/)
    expect(src).not.toMatch(/setWaves\(Array\.isArray\(wv\?\.waves\) \? wv\.waves : \[\]\)/)
  })

  it('does not dump leftover leftover-blackboard CSV after a failed mesh GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !evidenceRows\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed mesh GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/cem-dago\/status'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !evidenceRows\.length\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/\} catch \(e\) \{\n {6}setError\(e\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)\n {4}\} finally \{/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n {6}setError[\s\S]{0,160}setStatus\(/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n {6}setError[\s\S]{0,160}setManifests\(/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n {6}setError[\s\S]{0,160}setWaves\(/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n {6}setError[\s\S]{0,160}setBlackboard\(/)
  })
})
