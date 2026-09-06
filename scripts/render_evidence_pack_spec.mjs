#!/usr/bin/env node
/**
 * Convert evidence-pack.json into DocumentSpec + WorkbookSpec for weissman-docgen.
 * Usage: node scripts/render_evidence_pack_spec.mjs <manifest.json> <out.docspec.json> <out.bookspec.json>
 */
import fs from 'node:fs'

const [manifestPath, docOut, bookOut] = process.argv.slice(2)
if (!manifestPath || !docOut || !bookOut) {
  console.error('usage: render_evidence_pack_spec.mjs <manifest.json> <docspec.json> <bookspec.json>')
  process.exit(1)
}

const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
const audits = Array.isArray(m.wiring_audits) ? m.wiring_audits : []
const sig = m.security_signatures || {}
const sbom = m.sbom || {}

const doc = {
  title: 'Weissman Audit Evidence Pack',
  subtitle: 'Live wiring, SBOM and compliance provenance — no placeholders.',
  org: 'Weissman Cybersecurity',
  client: 'Inspection',
  classification: 'Confidential',
  lang: 'en',
  control_fields: [
    ['Generated', m.generated_at || ''],
    ['Git commit', m.provenance?.git_commit || ''],
    ['Git branch', m.provenance?.git_branch || ''],
  ],
  sections: [
    {
      title: 'Wiring audits',
      blocks: [
        {
          type: 'table',
          columns: [
            { title: 'Audit', weight: 2, style: 'strong' },
            { title: 'Status', weight: 1, style: 'severity' },
          ],
          rows: audits.map((a) => [a.name || '', a.status || '']),
        },
        { type: 'paragraph', text: m.notes || '' },
      ],
    },
    {
      title: 'Integrity',
      blocks: [
        {
          type: 'key_values',
          rows: [
            ['Cargo.lock SHA-256', sig.cargo_lock_sha256 || ''],
            ['package-lock SHA-256', sig.package_lock_sha256 || ''],
            ['SBOM SHA-256', sig.sbom_sha256 || sbom.sha256 || ''],
            ['SBOM source', sbom.source || ''],
            ['SBOM components', String(sbom.component_count || 0)],
          ],
        },
      ],
    },
  ],
}

const book = {
  title: 'Weissman Audit Evidence Pack',
  subtitle: 'Live wiring and integrity hashes',
  org: 'Weissman Cybersecurity',
  client: 'Inspection',
  classification: 'Confidential',
  lang: 'en',
  actor: 'generate_audit_evidence_pack.sh',
  sheets: [
    {
      name: 'Audits',
      columns: [
        { title: 'Audit', weight: 2, style: 'strong' },
        { title: 'Status', weight: 1, style: 'severity' },
      ],
      rows: audits.map((a) => [a.name || '', a.status || '']),
    },
    {
      name: 'Integrity',
      columns: [
        { title: 'Item', weight: 2, style: 'strong' },
        { title: 'Value', weight: 3, style: 'mono' },
      ],
      rows: [
        ['cargo_lock_sha256', sig.cargo_lock_sha256 || ''],
        ['package_lock_sha256', sig.package_lock_sha256 || ''],
        ['sbom_sha256', sig.sbom_sha256 || sbom.sha256 || ''],
        ['sbom_source', sbom.source || ''],
      ],
    },
  ],
}

fs.writeFileSync(docOut, JSON.stringify(doc, null, 2))
fs.writeFileSync(bookOut, JSON.stringify(book, null, 2))
