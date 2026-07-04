import { describe, it, expect } from 'vitest'
import {
  getManifestByRoute,
  getManifestByEngineId,
  resolveEngineIdFromRoute,
} from './engineManifestRegistry'

describe('engineManifestRegistry', () => {
  it('resolves tooling hubs by route', () => {
    const tpl = getManifestByRoute('/template-engine')
    expect(tpl?.engine_id).toBe('template_engine')
    expect(tpl?.capabilities?.requires_template_runner).toBe(true)
    expect(tpl?.capabilities?.requires_kill_switch).toBe(true)

    const ast = getManifestByRoute('/ast-fuzzing')
    expect(ast?.engine_id).toBe('semantic_ai_fuzz')
    expect(ast?.capabilities?.requires_ast_viewer).toBe(true)
    expect(ast?.capabilities?.max_ast_nodes).toBe(50000)
  })

  it('synthesizes fallback manifest for parametric engine routes', () => {
    const m = getManifestByEngineId('wifi_attack_engine')
    expect(m?.engine_id).toBe('wifi_attack_engine')
    expect(m?.capabilities?.requires_kill_switch).toBe(true)
  })

  it('resolveEngineIdFromRoute matches manifest engine_id', () => {
    expect(resolveEngineIdFromRoute('/jwt-lab')).toBe('jwt_attack')
    expect(resolveEngineIdFromRoute('/template-engine')).toBe('template_engine')
  })
})
