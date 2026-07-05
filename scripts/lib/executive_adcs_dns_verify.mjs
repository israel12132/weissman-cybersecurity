#!/usr/bin/env node
import fs from 'node:fs'
import { execSync } from 'node:child_process'

const outFile = process.env.OUT_FILE
if (!outFile) {
  console.error('OUT_FILE required')
  process.exit(1)
}

function probe(url) {
  try {
    const code = execSync("curl -sS -o /dev/null -w '%{http_code}' -m 15 " + JSON.stringify(url), {
      encoding: 'utf8',
    }).trim()
    const server = execSync(
      'curl -sS -I -m 15 ' +
        JSON.stringify(url) +
        " 2>/dev/null | awk -F': ' 'tolower($1)==\"server\"{print $2; exit}'",
      { encoding: 'utf8' },
    ).trim()
    return { url, http_status: Number(code), server }
  } catch (e) {
    return { url, error: String(e.message || e) }
  }
}

function doh(domain, endpoint, extraHeaders = '') {
  try {
    const raw = execSync(
      'curl -sS ' +
        extraHeaders +
        JSON.stringify(endpoint + domain + '&type=A'),
      { encoding: 'utf8' },
    )
    const j = JSON.parse(raw)
    return (j.Answer || []).filter((a) => a.type === 1).map((a) => a.data).sort()
  } catch {
    return []
  }
}

const report = {
  verified_at: new Date().toISOString(),
  adcs: [
    probe('https://www.tesla.com/certsrv/'),
    probe('https://www.tesla.com/CertificateAuthorityAuth/'),
  ],
  dns: {
    domain: 'www.tesla.com',
    google_doh_a: doh('www.tesla.com', 'https://dns.google/resolve?name='),
    cloudflare_doh_a: doh(
      'www.tesla.com',
      'https://cloudflare-dns.com/dns-query?name=',
      "-H 'accept: application/dns-json' ",
    ),
    analyst_note:
      'Resolver divergence alone is not hijack proof; compare with CDN/geo baseline.',
  },
}
fs.writeFileSync(outFile, JSON.stringify(report, null, 2))
