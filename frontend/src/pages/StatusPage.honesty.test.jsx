import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'StatusPage.jsx'),
  'utf8',
)

describe('StatusPage live-only truth', () => {
  it('does not paint safe-mode OFF when health.global_safe_mode is not a boolean', () => {
    expect(src).toMatch(
      /typeof state\.health\.global_safe_mode !== 'boolean'\) return 'unknown'/,
    )
    expect(src).not.toMatch(/if \(state\.health\?\.global_safe_mode\) return 'degraded'/)
    expect(src).toMatch(/state\.health\?\.global_safe_mode === true/)
  })
})
