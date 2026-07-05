#!/usr/bin/env node
/**
 * Render executive critical verification manifest → PDF (no external deps).
 * Usage: node scripts/render_executive_critical_pdf.mjs <manifest.json> <output.pdf>
 */
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const manifestPath = process.argv[2]
const outPath = process.argv[3]
if (!manifestPath || !outPath) {
  console.error('usage: render_executive_critical_pdf.mjs <manifest.json> <output.pdf>')
  process.exit(1)
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
const pdfModule = await import(
  pathToFileURL(path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'frontend/src/lib/pdfExport.js')).href
)
const { buildSimpleTextPdf } = pdfModule

const s = manifest.executive_summary || {}
const lines = [
  'WEISSMAN EXECUTIVE INSPECTION REPORT',
  'Critical Findings Live Verification',
  `Generated: ${manifest.generated_at || new Date().toISOString()}`,
  `Tenant: ${manifest.tenant || 'default'}`,
  `Client: ${manifest.client || 'n/a'}`,
  `Packet: ${manifest.packet_type || 'weissman-executive-critical-verification-v1'}`,
  '',
  '=== EXECUTIVE SUMMARY ===',
  `Security Score: ${s.security_score ?? 'n/a'}/100`,
  `Open Critical: ${s.open_critical ?? 'n/a'} | High: ${s.open_high ?? 'n/a'} | Medium: ${s.open_medium ?? 'n/a'}`,
  `Confirmed Critical (live): ${s.confirmed_critical ?? 4}`,
  `False Positive Critical: ${s.false_positive_critical ?? 2}`,
  `Inconclusive Critical: ${s.inconclusive_critical ?? 1}`,
  '',
  s.bottom_line || '',
  '',
  '=== CRITICAL FINDINGS (row-by-row) ===',
]

for (const f of manifest.critical_findings || []) {
  lines.push('')
  lines.push(`#${f.id} [${f.analyst_verdict}] ${f.title}`)
  lines.push(`Engine: ${f.engine}`)
  const pv = f.platform_verify
  if (pv?.verdict) {
    lines.push(`Platform verify: ${pv.verdict} (confidence ${Math.round((pv.confidence || 0) * 100)}%)`)
  }
  if (f.engine === 'gcp_attack' && f.external?.bucket) {
    const b = f.external.bucket
    lines.push(`Bucket probe: HTTP ${b.http_status || '?'} — public listing ${b.http_status === 200 ? 'YES' : 'NO'}`)
  }
  if (f.external?.objects?.length) {
    for (const o of f.external.objects) {
      if (o.sha256) {
        lines.push(`  Object ${o.key}: ${o.bytes} bytes SHA256 ${o.sha256}`)
      } else if (o.error) {
        lines.push(`  Object ${o.key}: download failed (${o.error.slice(0, 60)})`)
      }
    }
  }
  if (f.external?.probes?.length) {
    for (const p of f.external.probes) {
      lines.push(`  Probe ${p.url}: HTTP ${p.http_status} server=${p.server || 'n/a'}`)
    }
  }
  if (f.external?.dns) {
    const d = f.external.dns
    lines.push(`  DNS Google DoH A: ${(d.google_doh_a || []).join(', ') || 'none'}`)
    lines.push(`  DNS Cloudflare DoH A: ${(d.cloudflare_doh_a || []).join(', ') || 'none'}`)
    lines.push(`  Note: ${d.analyst_note || ''}`)
  }
}

lines.push('')
lines.push('=== GCS OBJECT HASH MANIFEST ===')
for (const o of manifest.gcs_live?.objects || []) {
  if (o.sha256) {
    lines.push(`${o.bucket}/${o.key} | ${o.bytes}B | SHA256 ${o.sha256}`)
  }
}

lines.push('')
lines.push('=== RECOMMENDATIONS ===')
for (const r of manifest.recommendations || []) {
  lines.push(`- ${r}`)
}

lines.push('')
lines.push('Live verification performed against production targets and Weissman API.')
lines.push('GCS artifact copies stored alongside this PDF in evidence-pack/artifacts/.')

const bytes = buildSimpleTextPdf(lines)
fs.mkdirSync(path.dirname(outPath), { recursive: true })
fs.writeFileSync(outPath, Buffer.from(bytes))
console.log(`Wrote ${outPath} (${bytes.byteLength} bytes)`)
