#!/usr/bin/env node
/**
 * Gate: every `t(`${NS}.key`)` template-literal reference must resolve to a real
 * key in en.json, where NS is a `const NS = 'a.b.c'` string in the same file.
 *
 * Catches the class of bug where a component's namespace prefix is wrong (e.g.
 * GlobalNexus pointed at components.cockpit.* instead of components.cockpitWidgets.*)
 * or a key was never added — both of which render the raw dotted key to the user.
 * The locale-parity test only checks en↔he symmetry, not that code references
 * valid keys, so this closes that gap.
 *
 * Exits 1 on any unresolved reference.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const srcDir = path.join(root, 'frontend', 'src')
const en = JSON.parse(fs.readFileSync(path.join(srcDir, 'i18n', 'locales', 'en.json'), 'utf8'))

const has = (k) => k.split('.').reduce((o, p) => (o && typeof o === 'object' ? o[p] : undefined), en) !== undefined

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) return walk(p)
    return /\.(jsx|js)$/.test(e.name) && !e.name.includes('.test.') ? [p] : []
  })
}

const missing = []
for (const file of walk(srcDir)) {
  const s = fs.readFileSync(file, 'utf8')
  const consts = {}
  for (const m of s.matchAll(/(?:const|let)\s+([A-Z][A-Z0-9_]*)\s*=\s*['"]([a-zA-Z0-9_.]+)['"]/g)) consts[m[1]] = m[2]
  for (const m of s.matchAll(/t\(`\$\{([A-Z][A-Z0-9_]*)\}\.([a-zA-Z0-9_.]+)`/g)) {
    const ns = consts[m[1]]
    if (!ns) continue
    const full = `${ns}.${m[2]}`
    if (!has(full)) missing.push(`${path.relative(root, file)}: t(\`\${${m[1]}}.${m[2]}\`) → ${full}`)
  }
}

if (missing.length) {
  console.error(`✖ ${missing.length} templated i18n key(s) do not resolve in en.json:`)
  for (const m of missing) console.error(`    ${m}`)
  console.error('  Fix the NS prefix or add the key (and its he.json counterpart).')
  process.exit(1)
}
console.log('✓ All `${NS}.key` templated i18n references resolve in en.json.')
