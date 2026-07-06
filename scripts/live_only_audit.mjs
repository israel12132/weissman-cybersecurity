#!/usr/bin/env node
/**
 * Live-only policy gate — fails CI if customer-facing production paths contain
 * simulation/demo/mock markers that imply fake telemetry or findings.
 *
 * Usage: node scripts/live_only_audit.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

/** @type {{ file: string, patterns: RegExp[], allow?: RegExp[] }[]} */
const RULES = [
  {
    file: 'fingerprint_engine/src/liquid_matrix_engine.rs',
    patterns: [/simulation_mode/, /simulation_note/],
  },
  {
    file: 'fingerprint_engine/src/server_handlers_rest4.inc',
    patterns: [/status:\s*"simulation"/, /"simulation_mode"/],
    allow: [/status_raw == "simulation"/, /legacy/],
  },
  {
    file: 'frontend/src/components/cockpit/DeceptionGridTab.jsx',
    patterns: [/simulation_mode/, /simulationBadge/],
  },
  {
    file: 'frontend/src/pages/DigitalTwinSimulator.jsx',
    patterns: [/overview_simulated/, /SIMULATION_SCENARIO/, /handleSimulate/],
  },
  {
    file: 'frontend/src/i18n/locales/en.json',
    patterns: [
      /"title":\s*"[^"]*Simulator"/,
      /"badge":\s*"[^"]*SIMULATION"/,
      /Simulates reflected/,
      /Run the simulation to model/,
    ],
    allow: [/Exploit Research Lab/, /Research Lab/],
  },
]

/** Scan broad prod surfaces for forbidden persisted-finding markers. */
const BROAD_FORBIDDEN = [
  {
    label: 'simulation_mode in engine sources',
    globDirs: ['fingerprint_engine/src'],
    ext: '.rs',
    pattern: /insert\([^)]*"simulation_mode"/,
    exclude: [],
  },
  {
    label: 'simulation_mode in frontend pages',
    globDirs: ['frontend/src/pages', 'frontend/src/components/cockpit'],
    ext: '.jsx',
    pattern: /simulation_mode/,
    exclude: ['EvidenceNotice.jsx'],
  },
]

/** Dev-only example binaries must not ship *_demo* artifacts. */
const FORBIDDEN_EXAMPLE_GLOBS = ['fingerprint_engine/examples']
const FORBIDDEN_EXAMPLE_NAME = /demo/i

function read(rel) {
  const abs = path.join(ROOT, rel)
  if (!fs.existsSync(abs)) return null
  return fs.readFileSync(abs, 'utf8')
}

function walk(dir, ext, out = []) {
  if (!fs.existsSync(dir)) return out
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name)
    if (ent.isDirectory()) walk(p, ext, out)
    else if (ent.name.endsWith(ext)) out.push(p)
  }
  return out
}

const violations = []

for (const rule of RULES) {
  const text = read(rule.file)
  if (text == null) {
    violations.push({ file: rule.file, detail: 'missing file' })
    continue
  }
  for (const re of rule.patterns) {
    if (!re.test(text)) continue
    const lines = text.split('\n')
    lines.forEach((line, i) => {
      if (!re.test(line)) return
      if (rule.allow?.some((a) => a.test(line))) return
      violations.push({ file: rule.file, line: i + 1, detail: re.toString(), snippet: line.trim() })
    })
  }
}

for (const rule of BROAD_FORBIDDEN) {
  for (const relDir of rule.globDirs) {
    const absDir = path.join(ROOT, relDir)
    for (const file of walk(absDir, rule.ext)) {
      const rel = path.relative(ROOT, file)
      if (rule.exclude.some((e) => rel.endsWith(e))) continue
      const text = fs.readFileSync(file, 'utf8')
      if (!rule.pattern.test(text)) continue
      const lines = text.split('\n')
      lines.forEach((line, i) => {
        if (!rule.pattern.test(line)) return
        violations.push({ file: rel, line: i + 1, detail: rule.label, snippet: line.trim() })
      })
    }
  }
}

for (const relDir of FORBIDDEN_EXAMPLE_GLOBS) {
  const absDir = path.join(ROOT, relDir)
  if (!fs.existsSync(absDir)) continue
  for (const ent of fs.readdirSync(absDir, { withFileTypes: true })) {
    if (!ent.isFile()) continue
    if (!FORBIDDEN_EXAMPLE_NAME.test(ent.name)) continue
    violations.push({
      file: path.join(relDir, ent.name),
      detail: 'demo example file forbidden in production repo',
      snippet: ent.name,
    })
  }
}

const summary = {
  ok: violations.length === 0,
  violations,
  checked_at: new Date().toISOString(),
  policy: 'live-only — no simulation_mode, demo stubs, or fake finding tags in production paths',
}

console.log(JSON.stringify(summary, null, 2))
process.exit(violations.length === 0 ? 0 : 1)
