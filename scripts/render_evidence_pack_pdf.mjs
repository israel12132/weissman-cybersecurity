#!/usr/bin/env node
/**
 * Render audit evidence pack JSON → minimal PDF (text lines, no external deps).
 * Usage: node scripts/render_evidence_pack_pdf.mjs <manifest.json> <output.pdf>
 */
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const manifestPath = process.argv[2]
const outPath = process.argv[3]
if (!manifestPath || !outPath) {
  console.error('usage: render_evidence_pack_pdf.mjs <manifest.json> <output.pdf>')
  process.exit(1)
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
const pdfModule = await import(
  pathToFileURL(path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'frontend/src/lib/pdfExport.js')).href
)
const { buildSimpleTextPdf } = pdfModule

const lines = [
  'WEISSMAN AUDIT EVIDENCE PACK',
  `Generated: ${manifest.generated_at || new Date().toISOString()}`,
  `Git commit: ${manifest.provenance?.git_commit || 'unknown'}`,
  `Packet: ${manifest.packet_type || 'weissman-audit-evidence-pack-v1'}`,
  '',
  '--- Wiring audits ---',
  ...(manifest.wiring_audits || []).map((a) => `${a.name}: ${a.status}${a.detail ? ` (${a.detail})` : ''}`),
  '',
  '--- Security signatures ---',
  ...Object.entries(manifest.security_signatures || {}).map(([k, v]) => `${k}: ${v}`),
  '',
  '--- Compliance mapping ---',
  ...(manifest.compliance?.frameworks || []).map(
    (f) => `${f.id || f.framework}: controls=${f.controls_mapped ?? f.controls ?? 'n/a'} posture=${f.posture_percent ?? 'n/a'}%`,
  ),
  '',
  '--- SBOM ---',
  `components: ${manifest.sbom?.component_count ?? manifest.sbom?.components?.length ?? 'n/a'}`,
  `sbom_sha256: ${manifest.sbom?.sha256 || 'n/a'}`,
  '',
  manifest.notes || 'Cryptographic evidence — verify hashes against CI artifacts.',
]

const bytes = buildSimpleTextPdf(lines)
fs.mkdirSync(path.dirname(outPath), { recursive: true })
fs.writeFileSync(outPath, Buffer.from(bytes))
console.log(`Wrote ${outPath} (${bytes.byteLength} bytes)`)
