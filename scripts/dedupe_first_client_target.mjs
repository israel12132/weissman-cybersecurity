#!/usr/bin/env node
/**
 * Replace local firstClientTarget() copies with import from lib/clientTarget.js
 * Run: node scripts/dedupe_first_client_target.mjs
 */
import fs from 'node:fs'
import path from 'node:path'

const pagesDir = path.join(path.resolve(path.dirname(new URL(import.meta.url).pathname), '..'), 'frontend/src/pages')

const FN_RE = /\nfunction firstClientTarget\(client\) \{[\s\S]*?\n\}/g

function ensureImport(src) {
  if (src.includes("from '../lib/clientTarget'") || src.includes('from "../lib/clientTarget"')) {
    if (!src.includes('firstClientTarget')) {
      return src.replace(
        /from ['"]\.\.\/lib\/clientTarget['"]/,
        (m) => m.replace("clientTarget'", "clientTarget'").replace(/'/, "'") // noop fallback
      )
    }
    // extend existing import
    if (/import \{([^}]+)\} from ['"]\.\.\/lib\/clientTarget['"]/.test(src)) {
      return src.replace(
        /import \{([^}]+)\} from (['"]\.\.\/lib\/clientTarget['"])/,
        (full, names, from) => {
          if (names.includes('firstClientTarget')) return full
          return `import { ${names.trim()}, firstClientTarget } from ${from}`
        },
      )
    }
    return src
  }
  const hook = "import { firstClientTarget } from '../lib/clientTarget'\n"
  const m = src.match(/^import .+$/m)
  if (m) {
    const idx = src.indexOf(m[0])
    return src.slice(0, idx) + hook + src.slice(idx)
  }
  return hook + src
}

let count = 0
for (const file of fs.readdirSync(pagesDir)) {
  if (!file.endsWith('.jsx')) continue
  const full = path.join(pagesDir, file)
  let src = fs.readFileSync(full, 'utf8')
  if (!FN_RE.test(src)) continue
  FN_RE.lastIndex = 0
  const next = ensureImport(src.replace(FN_RE, ''))
  if (next !== src) {
    fs.writeFileSync(full, next)
    console.log(`deduped ${file}`)
    count += 1
  }
}
console.log(`Done: ${count} files updated`)
