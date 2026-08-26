import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const script = join(dirname(fileURLToPath(import.meta.url)), 'write-html-entries.ts')
const r = spawnSync(process.execPath, ['--experimental-strip-types', script], { stdio: 'inherit' })
process.exit(r.status ?? 1)
