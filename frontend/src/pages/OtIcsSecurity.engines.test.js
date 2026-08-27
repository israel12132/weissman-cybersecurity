import { readFileSync } from 'node:fs'
import { describe, it, expect } from 'vitest'
import { isCriticalInfraEngine } from '../lib/criticalInfraEngines.js'

const src = readFileSync('src/pages/OtIcsSecurity.jsx', 'utf8')

const ROE_GATED = [
  'building_automation_attack',
  'robotics_ros2_attack',
  'smart_grid_dlms_attack',
  'maritime_ais_attack',
]

describe('OT/ICS engine roster', () => {
  it('lists the four RoE-gated OT engines that previously looked like empty success', () => {
    for (const id of ROE_GATED) {
      expect(src).toContain(`id: '${id}'`)
      expect(isCriticalInfraEngine(id)).toBe(true)
    }
  })
})
