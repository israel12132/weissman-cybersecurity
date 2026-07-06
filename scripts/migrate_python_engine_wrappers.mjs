#!/usr/bin/env node
/**
 * Standardize legacy Python engine wrappers to delegate via src/engines/registry.run_engine.
 * Skips remediation_engine.py and non-engine modules.
 */
import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const dir = path.join(root, 'src/engines')
const skip = new Set(['registry.py', '_rust_runner.py', 'remediation_engine.py', '__init__.py'])

const files = fs.readdirSync(dir).filter((f) => f.endsWith('_engine.py') && !skip.has(f))
let updated = 0

for (const file of files) {
  const full = path.join(dir, file)
  const text = fs.readFileSync(full, 'utf8')
  const fnMatch = text.match(/^def (run_[a-z0-9_]+)\(/m)
  const idMatch = text.match(/run_rust_engine\(\s*"([^"]+)"/) || text.match(/run_engine\(\s*"([^"]+)"/)
  if (!fnMatch || !idMatch) {
    console.warn(`skip ${file}: could not parse function/engine id`)
    continue
  }
  const fn = fnMatch[1]
  const engineId = idMatch[1]
  const timeoutMatch = text.match(/timeout=(\d+)/)
  const timeout = timeoutMatch ? Number(timeoutMatch[1]) : 120
  const docMatch = text.match(/"""([\s\S]*?)"""|'''([\s\S]*?)'''/)
  const docLine = (docMatch?.[1] || docMatch?.[2] || `${engineId} — Rust delegate`).trim().split('\n')[0]

  const body = `"""
${docLine}
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("${engineId}", __name__)


def ${fn}(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("${engineId}", target, timeout=${timeout})
`
  if (text === body) continue
  fs.writeFileSync(full, body)
  updated += 1
}

console.log(JSON.stringify({ ok: true, scanned: files.length, updated }, null, 2))
