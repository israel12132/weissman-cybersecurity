import { describe, it, expect } from 'vitest'
import { CRITICAL_INFRA_ENGINE_IDS, isCriticalInfraEngine } from './criticalInfraEngines.js'

describe('criticalInfraEngines', () => {
  it('covers the four live RoE-gated engines from inspection evidence', () => {
    for (const id of [
      'building_automation_attack',
      'robotics_ros2_attack',
      'smart_grid_dlms_attack',
      'maritime_ais_attack',
    ]) {
      expect(isCriticalInfraEngine(id)).toBe(true)
    }
    expect(isCriticalInfraEngine('osint')).toBe(false)
    expect(CRITICAL_INFRA_ENGINE_IDS).toHaveLength(8)
  })
})
