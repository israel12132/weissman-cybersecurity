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
// Full-line YAML comments are stripped before content checks so a control mentioned only in a
// comment (e.g. an explanatory "Omitting --error means…") can never satisfy a presence check.
function stripFullLineComments(s) {
  return s
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .join('\n')
}

// Split a workflow into per-step blocks (each starts at `- name:`) so a control's blocking-ness
// is evaluated on the SAME step, not file-wide — otherwise a non-blocking sibling step (e.g. an
// SBOM `scan-type: fs`) or an `exit-code: "1"` on a different Trivy step masks a removed gate.
function stepBlocks(code) {
  return code.split(/\n(?=\s*- name:)/)
}

// A step is neutered at the STEP level — present but unable to fail the job — via
// continue-on-error: true. (A `|| true` on an auxiliary line, e.g. `cat report || true` inside a
// failure handler, does NOT neuter the scanner, so it is checked per-command below, not here.)
function stepNeutered(block) {
  return /continue-on-error:\s*true/.test(block)
}

// True if the SCANNER command line itself swallows its own non-zero exit with a trailing
// `|| true` / `|| :` — the direct way to keep a blocking scanner from failing the job.
function cmdSwallowed(block, cmdRe) {
  return block.split('\n').some((l) => cmdRe.test(l) && /\|\|\s*(true|:)\s*$/.test(l.trimEnd()))
}

/**
 * Pure: given the raw ci.yml / deploy.yml text and a {name: content} map of every workflow
 * file, return the list of fail-closed-invariant violations. Pure so `--selftest` can feed it
 * deliberately-weakened fixtures and assert each weakening is caught.
 */
function collectWorkflowViolations(ci, dep, wfFiles) {
  const out = []
  const push = (m) => out.push(m)
  const need = (cond, msg) => {
    if (!cond) push(`ci.yml: ${msg}`)
  }

  // Every third-party `uses:` must be a 40-hex commit SHA (no mutable @vN/@branch tag).
  for (const [name, content] of Object.entries(wfFiles)) {
    const re = /uses:\s*([^\s#]+)/g
    let m
    while ((m = re.exec(content))) {
      const ref = m[1]
      if (ref.startsWith('./') || ref.startsWith('docker://')) continue // local / image action
      const at = ref.lastIndexOf('@')
      if (at === -1) {
        push(`${name}: unpinned action (no @ref): ${ref}`)
        continue
      }
      if (!/^[0-9a-f]{40}$/.test(ref.slice(at + 1))) push(`${name}: action not SHA-pinned: ${ref}`)
    }
  }

  const ciCode = stripFullLineComments(ci)
  const blocks = stepBlocks(ciCode)

  // Least-privilege default token at the TOP LEVEL (before the first `jobs:`) — a job-level
  // `permissions: contents: read` must not mask a top-level escalation to write.
  const topLevel = ciCode.split(/\njobs:/)[0]
  need(
    /(^|\n)permissions:\s*\n\s+contents:\s*read/.test(topLevel) && !/(^|\n)permissions:\s*\n\s+contents:\s*write/.test(topLevel),
    'top-level `permissions: contents: read` missing or escalated to write',
  )

  // Secret scanning (gitleaks): present, blocking, and not neutered.
  const gitleaks = blocks.filter((b) => /gitleaks detect/.test(b))
  need(gitleaks.length > 0, 'gitleaks detect step removed')
  need(
    gitleaks.some((b) => /--exit-code 1\b/.test(b) && !stepNeutered(b) && !cmdSwallowed(b, /gitleaks detect/)),
    'gitleaks not blocking (--exit-code 1 removed, or step neutered with `|| true` / continue-on-error)',
  )

  // Trivy dependency (fs) scan: a SINGLE step carrying both scan-type: fs AND exit-code "1",
  // not neutered — so removing that step is not masked by the non-blocking SBOM fs step or by
  // an exit-code "1" on the config/image steps.
  const trivyFs = blocks.filter((b) => /scan-type:\s*fs\b/.test(b))
  need(trivyFs.length > 0, 'Trivy fs scan removed')
  need(
    trivyFs.some((b) => /exit-code:\s*"1"/.test(b) && !stepNeutered(b)),
    'no BLOCKING Trivy fs (dependency) scan — the fs step lost its `exit-code: "1"` or was neutered',
  )

  // Trivy IaC (config) scan of deploy/, blocking, not neutered.
  const trivyCfg = blocks.filter((b) => /scan-type:\s*config\b/.test(b))
  need(trivyCfg.length > 0, 'Trivy IaC (config) scan removed')
  need(
    trivyCfg.some((b) => /scan-ref:\s*deploy\b/.test(b) && /exit-code:\s*"1"/.test(b) && !stepNeutered(b)),
    'Trivy IaC (config) scan no longer blocking or no longer targets deploy/',
  )

  // Semgrep SAST blocking (--error), on the semgrep step, not neutered. Comment-stripped, so the
  // explanatory "Omitting --error means…" comment can no longer satisfy this.
  const semgrep = blocks.filter((b) => /\bsemgrep\b/.test(b) && /--error\b/.test(b))
  need(
    semgrep.some((b) => !stepNeutered(b) && !cmdSwallowed(b, /semgrep\b/)),
    'Semgrep not blocking (--error removed from the semgrep step, or step neutered)',
  )

  // Supply-chain provenance on publish.
  need(/cosign sign/.test(ciCode), 'cosign image signing removed')
  need(/attest-build-provenance/.test(ciCode), 'SLSA build-provenance attestation removed')

  // deploy.yml: fail-closed signature verification, anchored AND constraining, BEFORE kubectl apply.
  if (dep) {
    const depCode = stripFullLineComments(dep)
    const verifyIdx = depCode.indexOf('cosign verify')
    const applyIdx = depCode.indexOf('kubectl apply')
    if (verifyIdx === -1) push('deploy.yml: fail-closed `cosign verify` removed')
    if (applyIdx === -1) push('deploy.yml: no `kubectl apply` (cannot confirm verify ordering)')
    if (verifyIdx !== -1 && applyIdx !== -1 && verifyIdx > applyIdx)
      push('deploy.yml: `cosign verify` no longer runs BEFORE `kubectl apply`')
    // The identity regexp must be anchored AND actually constrain the signer to this repo's
    // workflow — an anchored-but-wildcard `^.*$` accepts a signature from any workflow/ref.
    const idm = dep.match(/--certificate-identity-regexp\s+'([^']*)'/)
    const rx = idm ? idm[1] : ''
    const body = rx.replace(/^\^/, '').replace(/\$$/, '')
    const constrains =
      rx.startsWith('^') &&
      rx.endsWith('$') &&
      !/^\.[*+]?$/.test(body) &&
      /github\\?\.com/.test(rx) && // the YAML value escapes the dot as `github\.com`
      /workflows\/[^']*\.yml/.test(rx)
    if (!constrains)
      push('deploy.yml: cosign identity regexp does not CONSTRAIN the signer (must be anchored AND pin the github.com workflow identity, not a bare wildcard)')
    if (!/--certificate-github-workflow-repository/.test(dep))
      push('deploy.yml: cosign verify not bound to the workflow repository')
  }

  return out
}

function assertWorkflowInvariants() {
  for (const wf of ['ci.yml', 'deploy.yml', 'codeql.yml']) {
    if (!existsSync(join(WF_DIR, wf))) v(`missing workflow ${wf}`)
  }
  const names = existsSync(WF_DIR) ? readdirSync(WF_DIR).filter((n) => /\.ya?ml$/.test(n)) : []
  if (!names.length) return v('no workflow files found under .github/workflows/')
  const wfFiles = Object.fromEntries(names.map((n) => [n, readFileSync(join(WF_DIR, n), 'utf8')]))
  for (const m of collectWorkflowViolations(wfFiles['ci.yml'] || '', wfFiles['deploy.yml'] || '', wfFiles)) {
    v(m)
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

    // Workflow fail-closed invariants: a CLEAN baseline must raise nothing (no false positives),
    // and each deliberate weakening must be caught (no false negatives).
    const SHA = 'ed142fd0673e97e23eac54620cfb913e5ce36c25'
    const baseCi = [
      'name: ci',
      'permissions:',
      '  contents: read',
      'jobs:',
      '  security:',
      '    steps:',
      '      - name: Secret scan',
      '        run: gitleaks detect --no-git --exit-code 1 --source .',
      '      - name: Dep scan',
      `        uses: aquasecurity/trivy-action@${SHA}`,
      '        with:',
      '          scan-type: fs',
      '          exit-code: "1"',
      '      - name: IaC scan',
      `        uses: aquasecurity/trivy-action@${SHA}`,
      '        with:',
      '          scan-type: config',
      '          scan-ref: deploy',
      '          exit-code: "1"',
      '      - name: SAST',
      '        run: semgrep scan --error --config p/security-audit',
      '      - name: Sign',
      '        run: cosign sign --yes "img@sha256:x"',
      '      - name: Provenance',
      `        uses: actions/attest-build-provenance@${SHA}`,
      '',
    ].join('\n')
    const baseDep = [
      'name: deploy',
      'jobs:',
      '  deploy:',
      '    steps:',
      '      - name: Verify',
      "        run: cosign verify --certificate-identity-regexp '^https://github\\.com/acme/repo/\\.github/workflows/ci\\.yml@refs/tags/v.*$' --certificate-github-workflow-repository acme/repo \"img@sha256:x\"",
      '      - name: Apply',
      '        run: kubectl apply -f deploy/k8s/x.yaml',
      '',
    ].join('\n')

    const baseViol = collectWorkflowViolations(baseCi, baseDep, { 'ci.yml': baseCi, 'deploy.yml': baseDep })
    if (baseViol.length) problems.push(`workflow baseline should be clean but flagged: ${baseViol.join('; ')}`)

    const weakenings = [
      // --error removed from the semgrep step but left in a comment (the exact false-negative).
      [
        'semgrep --error removed (kept only in a comment)',
        baseCi.replace(
          '        run: semgrep scan --error --config p/security-audit',
          '        # Omitting --error means findings never fail the step\n        run: semgrep scan --config p/security-audit',
        ),
        baseDep,
        /Semgrep/,
      ],
      ['gitleaks neutered with || true', baseCi.replace('--source .', '--source . || true'), baseDep, /gitleaks/],
      ['top-level token escalated to write', baseCi.replace('  contents: read', '  contents: write'), baseDep, /permissions|contents: read/],
      ['fs vuln step lost its exit-code (SBOM/config still present)', baseCi.replace('          scan-type: fs\n          exit-code: "1"', '          scan-type: fs'), baseDep, /Trivy fs/],
      ['cosign identity wildcard', baseCi, baseDep.replace(/'\^https[^']*\$'/, "'^.*$'"), /cosign identity/],
      [`action unpinned to a tag`, baseCi.replace(`@${SHA}`, '@v4'), baseDep, /not SHA-pinned/],
    ]
    for (const [label, ci2, dep2, rx] of weakenings) {
      const viol = collectWorkflowViolations(ci2, dep2, { 'ci.yml': ci2, 'deploy.yml': dep2 })
      if (!viol.some((m) => rx.test(m))) {
        problems.push(`workflow gate MISSED weakening: ${label} :: got [${viol.join(' | ')}]`)
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
  if (problems.length) {
    console.error('ci_supply_chain_gate --selftest FAILED — detector(s) are stubs, not real:')
    for (const p of problems) console.error(`  - ${p}`)
    process.exit(1)
  }
  console.log(
    'ci_supply_chain_gate --selftest OK: secret + IaC detectors fired on planted fixtures; ' +
      'workflow baseline clean and all 6 fail-closed weakenings (semgrep/gitleaks/permissions/trivy-fs/cosign-identity/SHA-pin) caught.',
  )
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
