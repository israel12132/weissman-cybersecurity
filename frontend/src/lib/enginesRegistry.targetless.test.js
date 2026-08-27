import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { TARGETLESS_ENGINE_IDS, ENGINES_REGISTRY } from './enginesRegistry.js'
import { engineRequiresTarget } from './clientTarget.js'

const contract = JSON.parse(
  readFileSync(
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../shared/engine_target_contract.json'),
    'utf8',
  ),
)

describe('targetless engines', () => {
  it('set non-empty', () => expect(TARGETLESS_ENGINE_IDS.size).toBeGreaterThan(0))

  it('matches requiresTarget flags on every registry row', () => {
    for (const e of ENGINES_REGISTRY) {
      expect(engineRequiresTarget(e.id)).toBe(e.requiresTarget !== false)
      expect(TARGETLESS_ENGINE_IDS.has(e.id)).toBe(e.requiresTarget === false)
    }
  })

  it('shared engine_target_contract.json matches the registry', () => {
    const contractTargetless = new Set(contract.targetless_ids)
    expect(contract.production_engine_count).toBeGreaterThan(500)
    for (const e of ENGINES_REGISTRY) {
      expect(contractTargetless.has(e.id)).toBe(e.requiresTarget === false)
    }
    expect(engineRequiresTarget('zero_day_radar')).toBe(false)
    expect(contractTargetless.has('zero_day_radar')).toBe(true)
  })
})
