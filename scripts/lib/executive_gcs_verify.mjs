#!/usr/bin/env node
import fs from 'node:fs'
import { execSync } from 'node:child_process'
import path from 'node:path'

const outDir = process.env.ARTIFACT_DIR
const outFile = process.env.OUT_FILE
if (!outDir || !outFile) {
  console.error('ARTIFACT_DIR and OUT_FILE required')
  process.exit(1)
}
fs.mkdirSync(outDir, { recursive: true })

const buckets = [
  { bucket: 'www-test', objects: ['404.html'] },
  { bucket: 'www-staging', objects: ['about-texas/'] },
  { bucket: 'www-bucket', objects: ['167845263424.txt', 'FxCodeShell.jsp'] },
  { bucket: 'www-cdn', objects: ['.well-known/security.txt'] },
]

function probe(url) {
  try {
    const code = execSync("curl -sS -o /dev/null -w '%{http_code}' -m 15 " + JSON.stringify(url), {
      encoding: 'utf8',
    }).trim()
    const head = execSync('curl -sS -I -m 15 ' + JSON.stringify(url) + ' 2>/dev/null | head -5', {
      encoding: 'utf8',
    })
    const listSnippet = execSync('curl -sS -m 15 ' + JSON.stringify(url) + ' 2>/dev/null | head -c 300', {
      encoding: 'utf8',
    })
    return {
      url,
      http_status: Number(code),
      listing_xml_prefix: listSnippet.slice(0, 280),
      headers: head.trim(),
    }
  } catch (e) {
    return { url, error: String(e.message || e) }
  }
}

function hashObject(bucket, key) {
  const url = 'https://storage.googleapis.com/' + bucket + '/' + encodeURIComponent(key).replace(/%2F/g, '/')
  const safe = (bucket + '__' + key.replace(/[^a-zA-Z0-9._-]+/g, '_')).slice(0, 80)
  const filePath = path.join(outDir, safe)
  try {
    execSync('curl -sS -f -m 25 ' + JSON.stringify(url) + ' -o ' + JSON.stringify(filePath))
    const stat = fs.statSync(filePath)
    const hash = execSync('sha256sum ' + JSON.stringify(filePath), { encoding: 'utf8' }).split(/\s+/)[0]
    return { bucket, key, url, bytes: stat.size, sha256: hash, artifact: filePath }
  } catch (e) {
    return { bucket, key, url, error: String(e.message || e) }
  }
}

const report = { verified_at: new Date().toISOString(), buckets: [], objects: [] }
for (const b of buckets) {
  const url = 'https://storage.googleapis.com/' + b.bucket
  report.buckets.push({ ...b, ...probe(url) })
  for (const key of b.objects) {
    report.objects.push(hashObject(b.bucket, key))
  }
}
fs.writeFileSync(outFile, JSON.stringify(report, null, 2))
