import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { ENGINES_REGISTRY, TARGETLESS_ENGINE_IDS } from './enginesRegistry.js'

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')

describe('scan target contract (server invariant, not UI requiresTarget fights)', () => {
  it('engines that need a target are documented; empty target is a stable error', () => {
    const routing = readFileSync(
      resolve(repo, 'fingerprint_engine/src/scan_routing.rs'),
      'utf8',
    )
    expect(routing).toContain('pub const TARGET_REQUIRED_ERROR_CODE: &str = "target_required"')
    expect(routing).toContain('fn is_target_required_message')
    expect(routing).toContain('pub fn reject_empty_target')

    const needTarget = ENGINES_REGISTRY.filter((e) => !TARGETLESS_ENGINE_IDS.has(e.id))
    expect(needTarget.length).toBeGreaterThan(400)
    for (const id of ['osint', 'asm', 'bola_idor', 'graphql_attack', 'jwt_attack']) {
      expect(TARGETLESS_ENGINE_IDS.has(id)).toBe(false)
    }
  })

  it('OpenAPI documents the 400 target_required response on the scan path', () => {
    const openapi = readFileSync(
      resolve(repo, 'fingerprint_engine/src/server_handlers_rest2.inc'),
      'utf8',
    )
    expect(openapi).toContain('/api/command-center/scan')
    expect(openapi).toContain('target_required')
    expect(openapi).toContain('ScanError')
  })
})
