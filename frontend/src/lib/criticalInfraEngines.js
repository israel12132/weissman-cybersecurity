/** Canonical RoE-gated critical-infrastructure engine IDs (must match fingerprint_engine critical_infra::ENGINE_IDS). */
export const CRITICAL_INFRA_ENGINE_IDS = [
  'avionics_adsb_attack',
  'maritime_ais_attack',
  'ev_charging_ocpp_attack',
  'smart_grid_dlms_attack',
  'rail_signaling_attack',
  'building_automation_attack',
  'robotics_ros2_attack',
  'ot_sis_triton_attack',
]

export function isCriticalInfraEngine(engineId) {
  const id = String(engineId || '').trim()
  return CRITICAL_INFRA_ENGINE_IDS.includes(id)
}
