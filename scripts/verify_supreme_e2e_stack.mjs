#!/usr/bin/env node
/**
 * Supreme live E2E orchestrator — runs all gates in order (requires ./scripts/run_e2e_stack.sh start).
 *
 * Env:
 *   WEISSMAN_SUPREME_SKIP_GROUPS=1  — skip engine-groups findings (faster)
 *   WEISSMAN_FINDINGS_E2E_FULL=1    — all 14 engine groups (slow)
 */
import { spawnSync } from 'node:child_process'
import path from 'node:path'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')

const steps = [
  { name: 'command_center_coverage', cmd: ['node', 'scripts/verify_command_center_coverage.mjs'] },
  { name: 'scan_pipeline_e2e', cmd: ['node', 'scripts/verify_scan_pipeline_e2e.mjs'] },
  { name: 'fp_tp_confidence_e2e', cmd: ['node', 'scripts/verify_fp_tp_confidence_e2e.mjs'] },
]

if (process.env.WEISSMAN_SUPREME_SKIP_GROUPS !== '1') {
  steps.push({
    name: 'engine_groups_findings_e2e',
    cmd: ['node', 'scripts/verify_engine_groups_findings_e2e.mjs'],
  })
}

console.log('verify_supreme_e2e_stack: starting')
const failures = []

for (const step of steps) {
  console.log(`\n=== ${step.name} ===`)
  const r = spawnSync(step.cmd[0], step.cmd.slice(1), {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env },
  })
  if (r.status !== 0) {
    failures.push(step.name)
  }
}

console.log('')
if (failures.length) {
  console.error(`verify_supreme_e2e_stack: FAIL — ${failures.join(', ')}`)
  process.exit(1)
}
console.log(`verify_supreme_e2e_stack: OK (${steps.length} gates)`)
