#!/usr/bin/env node
/**
 * CI supply-chain self-enforcing gate (Step 15).
 *
 * The real supply-chain hardening (gitleaks, Trivy fs/config/image, Semgrep, CodeQL,
 * cosign keyless signing + SLSA provenance + SBOM attestation, fail-closed `cosign verify`
 * before `kubectl apply`, SHA-pinned actions, least-privilege token) lives entirely in
 * GitHub Actions YAML, so it only runs on the live runner and NOTHING locally catches a
 * silent regression — e.g. an edit that drops the gitleaks step, flips a Trivy/Semgrep
 * gate from blocking to advisory, unpins an action SHA back to a mutable tag, or removes
 * the anchored `cosign verify` from deploy.yml. Every one of those weakenings passes the
 * existing G1-G7 gate today, because full_audit_gate.sh never inspects .github/workflows/.
 *
 * This gate closes that hole WITHOUT pretending to run the scanners themselves (their
 * binaries are CI-only). It does two verifiable things locally:
 *   (A) Parses the workflow YAML as text and ASSERTS the fail-closed invariants are present
 *       and configured to block — so weakening any control fails this gate immediately.
 *   (B) Runs a dependency-free secret scanner + k8s IaC linter over the deploy surface, and
 *       a `--selftest` that plants a secret + a privileged/insecure manifest into a temp
 *       fixture and asserts the detectors FIRE — proving the detection logic is real, not a
 *       stub, before anyone trusts a clean run.
 *
 * Usage:
 *   node scripts/ci_supply_chain_gate.mjs            # assert invariants + scan deploy surface
 *   node scripts/ci_supply_chain_gate.mjs --selftest # prove the detectors catch planted issues
 *
 * Exit 0 = all invariants hold and (selftest) all detectors fired. Non-zero = a regression.
 */
import { readFileSync, existsSync, readdirSync, mkdtempSync, writeFileSync, mkdirSync, rmSync, statSync } from 'node:fs'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const WF_DIR = join(ROOT, '.github/workflows')
const SELFTEST = process.argv.includes('--selftest')

const violations = []
const v = (msg) => violations.push(msg)

// ── Detectors (pure — reused by both the real scan and --selftest) ─────────────────
const SECRET_RULES = [
  { id: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/, desc: 'AWS access key id' },
  {
    id: 'private-key',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    desc: 'PEM private key block',
  },
  {
    id: 'generic-secret-assignment',
    // NAME = "long-high-entropy-value" where NAME contains SECRET/TOKEN/PASSWORD/APIKEY
    // anywhere (e.g. API_TOKEN, DB_PASSWORD, JWT_SECRET). The 24+ char quoted value keeps
    // this off config that merely NAMES a secret (valueFrom/secretKeyRef, unquoted names).
    re: /\b[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|APIKEY)[A-Z0-9_]*\s*[:=]\s*["'][A-Za-z0-9+/_-]{24,}["']/,
    desc: 'hard-coded secret assignment',
  },
]

// k8s pod-security misconfigurations. `critical` rules are never legitimate and BLOCK on the
// real tree; `strict` rules (a container/pod should set these) are proven by --selftest and
// are advisory on the real tree so this gate never false-positives on a hardened-but-terse
// manifest (e.g. a datastore that legitimately omits readOnlyRootFilesystem).
const IAC_CRITICAL = [
  { id: 'privileged', re: /privileged:\s*true/, desc: 'privileged: true container' },
  { id: 'host-network', re: /hostNetwork:\s*true/, desc: 'hostNetwork: true' },
  { id: 'host-pid', re: /hostPID:\s*true/, desc: 'hostPID: true' },
  { id: 'host-ipc', re: /hostIPC:\s*true/, desc: 'hostIPC: true' },
  { id: 'priv-escalation', re: /allowPrivilegeEscalation:\s*true/, desc: 'allowPrivilegeEscalation: true' },
]
const IAC_STRICT = [
  { id: 'no-runasnonroot', absent: /runAsNonRoot:\s*true/, desc: 'no runAsNonRoot: true' },
  { id: 'no-limits', absent: /limits:/, desc: 'no resource limits' },
  // Advisory, NOT blocking: the checked-in manifests use `:latest` as a template default,
  // but the enforced deploy path (deploy.yml: sed-rewrite to the cosign-verified
  // ${IMAGE}@sha256:<digest> BEFORE kubectl apply) pins the effective image. A raw manual
  // `kubectl apply` of the manifest would still pull a mutable tag, so we surface it.
  { id: 'image-latest', present: /image:\s*\S+:latest(?:\s|$|")/, desc: 'image :latest in manifest (deploy pipeline pins to digest)' },
]

const looksBinary = (buf) => buf.includes('\u0000')
const SKIP_DIRS = new Set(['node_modules', '.git', 'target', 'dist', 'build', '.venv', '__pycache__'])

function walk(dir) {
  const out = []
  if (!existsSync(dir)) return out
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue
    const p = join(dir, name)
    const st = statSync(p)
    if (st.isDirectory()) out.push(...walk(p))
    else if (st.isFile() && st.size < 2_000_000) out.push(p)
  }
  return out
}

function scanSecrets(files) {
  const hits = []
  for (const f of files) {
    // Example/template files legitimately show placeholder shapes.
    if (/\.example(\.|$)|example\.|\.sample(\.|$)|README|\.md$/i.test(f)) continue
    let txt
    try {
      txt = readFileSync(f)
    } catch {
      continue
    }
    if (looksBinary(txt)) continue
    const s = txt.toString('utf8')
    for (const rule of SECRET_RULES) {
      if (rule.re.test(s)) hits.push({ file: f, rule: rule.id, desc: rule.desc })
    }
  }
  return hits
}

function isPodManifest(s) {
  // Match the DOCUMENT's own top-level `kind:` (column 0), not a nested reference such as
  // an HPA's `scaleTargetRef.kind: Deployment` — those carry no pod template to audit.
  return /^kind:\s*(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod|ReplicaSet)\b/m.test(s)
}

function scanIaCCritical(files) {
  const hits = []
  for (const f of files) {
    let s
    try {
      s = readFileSync(f, 'utf8')
    } catch {
      continue
    }
    for (const rule of IAC_CRITICAL) {
      if (rule.re.test(s)) hits.push({ file: f, rule: rule.id, desc: rule.desc })
    }
  }
  return hits
}

function scanIaCStrict(files) {
  // Only meaningful on pod-bearing manifests; returns advisory findings.
  const hits = []
  for (const f of files) {
    let s
    try {
      s = readFileSync(f, 'utf8')
    } catch {
      continue
    }
    if (!isPodManifest(s)) continue
    for (const rule of IAC_STRICT) {
      const flagged = rule.present ? rule.present.test(s) : !rule.absent.test(s)
      if (flagged) hits.push({ file: f, rule: rule.id, desc: rule.desc })
    }
  }
  return hits
}

// ── (A) Workflow fail-closed invariants ────────────────────────────────────────────
function assertWorkflowInvariants() {
  for (const wf of ['ci.yml', 'deploy.yml', 'codeql.yml']) {
    if (!existsSync(join(WF_DIR, wf))) v(`missing workflow ${wf}`)
  }
  const files = existsSync(WF_DIR) ? readdirSync(WF_DIR).filter((n) => /\.ya?ml$/.test(n)) : []
  if (!files.length) return v('no workflow files found under .github/workflows/')

  // Every third-party `uses:` must be a 40-hex commit SHA (no mutable @vN/@branch tag).
  for (const n of files) {
    const s = readFileSync(join(WF_DIR, n), 'utf8')
    const re = /uses:\s*([^\s#]+)/g
    let m
    while ((m = re.exec(s))) {
      const ref = m[1]
      if (ref.startsWith('./') || ref.startsWith('docker://')) continue // local / image action
      const at = ref.lastIndexOf('@')
      if (at === -1) {
        v(`${n}: unpinned action (no @ref): ${ref}`)
        continue
      }
      const pin = ref.slice(at + 1)
      if (!/^[0-9a-f]{40}$/.test(pin)) v(`${n}: action not SHA-pinned: ${ref}`)
    }
  }

  const ci = readFileSync(join(WF_DIR, 'ci.yml'), 'utf8')
  const need = (cond, msg) => {
    if (!cond) v(`ci.yml: ${msg}`)
  }
  // Least-privilege default token.
  need(/permissions:\s*\n\s*contents:\s*read/.test(ci), 'missing top-level `permissions: contents: read`')
  // Secret scanning (gitleaks), blocking.
  need(/gitleaks detect/.test(ci), 'gitleaks detect step removed')
  need(/gitleaks detect[^\n]*--exit-code 1|--exit-code 1[^\n]*\n[^\n]*gitleaks|gitleaks[\s\S]{0,400}--exit-code 1/.test(ci), 'gitleaks not blocking (--exit-code 1 gone)')
  // Trivy dependency (fs) scan, blocking.
  need(/scan-type:\s*fs/.test(ci), 'Trivy fs scan removed')
  need(/exit-code:\s*"1"/.test(ci), 'no blocking Trivy scan (exit-code "1" gone)')
  // Trivy IaC (config) scan of the deploy dir, blocking.
  need(/scan-type:\s*config/.test(ci), 'Trivy IaC (config) scan removed')
  need(/scan-ref:\s*deploy/.test(ci), 'Trivy IaC scan no longer targets deploy/')
  // Semgrep SAST, blocking (--error makes findings fail the step).
  need(/--error/.test(ci), 'Semgrep not blocking (--error gone)')
  // Supply-chain provenance on publish.
  need(/cosign sign/.test(ci), 'cosign image signing removed')
  need(/attest-build-provenance/.test(ci), 'SLSA build-provenance attestation removed')

  // deploy.yml: fail-closed signature verification, anchored, BEFORE kubectl apply.
  if (existsSync(join(WF_DIR, 'deploy.yml'))) {
    const dep = readFileSync(join(WF_DIR, 'deploy.yml'), 'utf8')
    // Strip full-line comments so a comment that merely mentions "kubectl apply" (e.g. the
    // concurrency note) is not mistaken for the command when checking verify-before-apply.
    const depCode = dep
      .split('\n')
      .filter((l) => !/^\s*#/.test(l))
      .join('\n')
    const verifyIdx = depCode.indexOf('cosign verify')
    const applyIdx = depCode.indexOf('kubectl apply')
    if (verifyIdx === -1) v('deploy.yml: fail-closed `cosign verify` removed')
    if (applyIdx === -1) v('deploy.yml: no `kubectl apply` (unexpected — cannot confirm verify ordering)')
    if (verifyIdx !== -1 && applyIdx !== -1 && verifyIdx > applyIdx)
      v('deploy.yml: `cosign verify` no longer runs BEFORE `kubectl apply`')
    if (!/--certificate-identity-regexp\s+'(\^[^']*\$)'/.test(dep))
      v('deploy.yml: cosign identity regexp is not anchored (^...$) — signer identity not constrained')
    if (!/--certificate-github-workflow-repository/.test(dep))
      v('deploy.yml: cosign verify not bound to the workflow repository')
  }
}

// ── (B) --selftest: prove the detectors fire on planted issues ───────────────────────
function selftest() {
  const dir = mkdtempSync(join(tmpdir(), 'scgate-selftest-'))
  const problems = []
  try {
    // Planted secrets.
    writeFileSync(join(dir, 'leak.env'), 'AWS_ACCESS=AKIAIOSFODNN7EXAMPLE\nAPI_TOKEN="abcdef0123456789abcdef0123456789"\n')
    writeFileSync(
      join(dir, 'id_rsa'),
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0planted\n-----END RSA PRIVATE KEY-----\n',
    )
    // Planted privileged + insecure manifest (critical + strict).
    mkdirSync(join(dir, 'k8s'))
    writeFileSync(
      join(dir, 'k8s', 'bad.yaml'),
      [
        'apiVersion: apps/v1',
        'kind: Deployment',
        'spec:',
        '  template:',
        '    spec:',
        '      hostNetwork: true',
        '      containers:',
        '        - name: app',
        '          image: evil/app:latest',
        '          securityContext:',
        '            privileged: true',
        '            allowPrivilegeEscalation: true',
        '',
      ].join('\n'),
    )

    const files = walk(dir)
    const secretHits = scanSecrets(files)
    for (const rule of ['aws-access-key', 'private-key', 'generic-secret-assignment']) {
      if (!secretHits.some((h) => h.rule === rule)) problems.push(`secret detector missed: ${rule}`)
    }
    const critHits = scanIaCCritical(files.filter((f) => f.endsWith('.yaml')))
    for (const rule of ['privileged', 'host-network', 'priv-escalation']) {
      if (!critHits.some((h) => h.rule === rule)) problems.push(`IaC critical detector missed: ${rule}`)
    }
    const strictHits = scanIaCStrict(files.filter((f) => f.endsWith('.yaml')))
    for (const rule of ['no-runasnonroot', 'no-limits', 'image-latest']) {
      if (!strictHits.some((h) => h.rule === rule)) problems.push(`IaC strict detector missed: ${rule}`)
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
  if (problems.length) {
    console.error('ci_supply_chain_gate --selftest FAILED — detector(s) are stubs, not real:')
    for (const p of problems) console.error(`  - ${p}`)
    process.exit(1)
  }
  console.log('ci_supply_chain_gate --selftest OK: all secret + IaC detectors fired on planted fixtures.')
}

// ── main ─────────────────────────────────────────────────────────────────────────
if (SELFTEST) {
  selftest()
  process.exit(0)
}

assertWorkflowInvariants()

const deployFiles = walk(join(ROOT, 'deploy'))
const wfFiles = existsSync(WF_DIR) ? readdirSync(WF_DIR).map((n) => join(WF_DIR, n)) : []
const secretHits = scanSecrets([...deployFiles, ...wfFiles])
for (const h of secretHits) v(`secret in ${relative(ROOT, h.file)}: ${h.desc} (${h.rule})`)

const k8sFiles = deployFiles.filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
const critHits = scanIaCCritical(k8sFiles)
for (const h of critHits) v(`IaC misconfig in ${relative(ROOT, h.file)}: ${h.desc} (${h.rule})`)

const strictHits = scanIaCStrict(k8sFiles)

if (violations.length) {
  console.error('ci_supply_chain_gate FAILED — supply-chain control weakened or misconfig present:')
  for (const m of violations) console.error(`  - ${m}`)
  process.exit(1)
}

console.log(
  `ci_supply_chain_gate OK: workflow fail-closed invariants intact; ` +
    `${k8sFiles.length} k8s manifests + ${deployFiles.length + wfFiles.length} deploy/workflow files clean of critical patterns.`,
)
if (strictHits.length) {
  console.log(`  advisory (non-blocking) pod-security notes: ${strictHits.length}`)
  for (const h of strictHits) console.log(`    - ${relative(ROOT, h.file)}: ${h.desc}`)
}
