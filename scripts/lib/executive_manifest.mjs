#!/usr/bin/env node
import fs from 'node:fs'

const outDir = process.env.OUT_DIR
if (!outDir) {
  console.error('OUT_DIR required')
  process.exit(1)
}

const exec = JSON.parse(fs.readFileSync(`${outDir}/exec-kpis.json`, 'utf8'))
const platform = JSON.parse(fs.readFileSync(`${outDir}/platform-verify.json`, 'utf8'))
const gcs = JSON.parse(fs.readFileSync(`${outDir}/gcs-live-verify.json`, 'utf8'))
const adcsDns = JSON.parse(fs.readFileSync(`${outDir}/adcs-dns-verify.json`, 'utf8'))

const criticalMeta = [
  { id: 7442, title: 'Publicly-listable GCS bucket: www-test', engine: 'gcp_attack', analyst_verdict: 'CONFIRMED' },
  { id: 7446, title: 'Publicly-listable GCS bucket: www-staging', engine: 'gcp_attack', analyst_verdict: 'CONFIRMED' },
  { id: 7451, title: 'Publicly-listable GCS bucket: www-bucket', engine: 'gcp_attack', analyst_verdict: 'CONFIRMED' },
  { id: 7452, title: 'Publicly-listable GCS bucket: www-cdn', engine: 'gcp_attack', analyst_verdict: 'CONFIRMED' },
  { id: 7793, title: 'AD CS web enrollment exposed: /certsrv/', engine: 'kerberoasting', analyst_verdict: 'FALSE_POSITIVE' },
  { id: 7840, title: 'DNS answer divergence across resolvers', engine: 'bgp_dns_hijacking', analyst_verdict: 'INCONCLUSIVE' },
  { id: 10660, title: 'AD CS web enrollment exposed: /CertificateAuthorityAuth/', engine: 'kerberoasting', analyst_verdict: 'FALSE_POSITIVE' },
]

const byId = Object.fromEntries((platform.findings || []).map((f) => [f.id, f]))

const manifest = {
  packet_type: 'weissman-executive-critical-verification-v1',
  generated_at: new Date().toISOString(),
  tenant: 'default',
  client: 'Tesla Inc. (Bugcrowd VRP)',
  executive_summary: {
    security_score: exec.security_score,
    open_critical: exec.severity?.critical,
    open_high: exec.severity?.high,
    open_medium: exec.severity?.medium,
    confirmed_critical: 4,
    false_positive_critical: 2,
    inconclusive_critical: 1,
    bottom_line:
      'Four public GCS buckets verified live (including suspicious artifacts in www-bucket). Two AD CS criticals are Akamai 403 false positives. DNS divergence requires manual triage.',
  },
  critical_findings: criticalMeta.map((m) => ({
    ...m,
    platform_verify: byId[m.id] || null,
    external:
      m.engine === 'gcp_attack'
        ? {
            bucket: gcs.buckets?.find((b) => m.title.includes(b.bucket)),
            objects: gcs.objects?.filter((o) => m.title.includes(o.bucket)),
          }
        : m.engine === 'kerberoasting'
          ? { probes: adcsDns.adcs }
          : { dns: adcsDns.dns },
  })),
  gcs_live: gcs,
  adcs_dns_live: adcsDns,
  platform_verify: platform,
  exec_kpis: exec,
  recommendations: [
    'Immediate: lock down www-test, www-staging, www-bucket, www-cdn (remove public list ACL).',
    'Forensics: review www-bucket objects (FxCodeShell.jsp*) — SHA256 captured in artifacts/.',
    'Mark kerberoasting AD CS findings as FALSE_POSITIVE; patch engine to not escalate on HTTP 403.',
    'Manual DNS triage with passive DNS + multi-region resolvers before SOAR.',
    'Enable MFA for sole superadmin account.',
  ],
}

const manifestPath = `${outDir}/executive-critical-manifest.json`
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2))
console.log(manifestPath)
