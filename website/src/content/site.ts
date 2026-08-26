import { metrics } from './metrics'

export const company = {
  legalName: 'Weissman Cybersecurity Ltd.',
  shortName: 'Weissman',
  location: 'Tel Aviv-Yafo, Israel',
  domain: 'weissman.io',
  origin: 'https://weissman.io',
  emails: {
    sales: 'sales@weissman.io',
    security: 'security@weissman.io',
    dpo: 'dpo@weissman.io',
    legal: 'legal@weissman.io',
    support: 'support@weissman.io',
  },
  github: 'https://github.com/israel12132/weissman-cybersecurity',
  companyIdIsrael: '[COMPANY_ID_ISRAEL]',
}

export const cta = {
  primary: { label: 'Book a Demo', href: '/contact/' },
  secondary: { label: 'Explore the Platform', href: '/platform/' },
  signIn: { label: 'Sign in', href: '/command-center/login' },
  trial: { label: 'Start free trial', href: '/signup.html' },
  status: { label: 'System status', href: '/status' },
  apiDocs: { label: 'API docs', href: '/api/docs/' },
}

export const announcement = {
  id: '2026.06.2-liminal-boundary',
  kicker: 'Release 2026.06.2',
  text: 'Liminal Boundary Engine is the current platform release — live probes, ATT&CK-mapped findings, and Command Center operations.',
  href: '/resources/',
  hrefLabel: 'Read the overview',
}

export const hero = {
  kicker: 'Autonomous offensive security + active defence',
  h1: 'The landscape got noisier. Your evidence should not.',
  lead: `Weissman continuously attacks the surfaces you authorise the way an adversary would — ${metrics.productionEngines.value} production engines, live probes, MITRE-mapped findings, and a Command Center that turns validation into action.`,
}

export const threatStory = [
  {
    step: '01',
    title: 'What changed',
    body: 'Attack surfaces now span web, cloud, identity, OT, supply chain, and the models sitting next to production data. A finding that is not proven still consumes the same analyst hour as one that is.',
  },
  {
    step: '02',
    title: 'Where tools fragment',
    body: 'Scanners, ticketing, intel feeds, and SOAR often disagree on the same CVE. Alias-heavy catalogs and simulated checks inflate coverage while leaving blind classes unconfirmed.',
  },
  {
    step: '03',
    title: 'How Weissman is built',
    body: 'Every production engine ID resolves to a real HTTP, TCP, DNS, TLS, or agent probe. Blind classes wait for an OAST callback. Risk is ordered by KEV, EPSS, and attack path — not by who shouted last.',
  },
] as const

export const howItWorks = [
  {
    id: 'observe',
    title: 'Observe',
    body: 'Onboard a client and a written scope. Discovery and the endpoint agent (when installed) map what is actually reachable — domains, cloud roles, hosts, and protocols.',
  },
  {
    id: 'analyse',
    title: 'Analyse',
    body: 'The orchestrator runs the enabled engine suite. Findings are deduplicated by stable signature, clustered, and enriched with CISA KEV and FIRST EPSS at persist time.',
  },
  {
    id: 'validate',
    title: 'Validate and prioritise',
    body: 'OAST confirms blind callbacks. Attack-path inference walks internet-exposed nodes toward crown jewels. FAIR-aligned loss figures sit next to CVSS — not instead of evidence.',
  },
  {
    id: 'respond',
    title: 'Respond',
    body: 'SOAR playbooks notify, isolate, or open a signed pull request. Patches are verified in an ephemeral sandbox before merge. False positives teach the next cycle.',
  },
] as const

export const capabilities = [
  {
    title: 'Live probes, not simulations',
    body: 'Catalog IDs that cannot execute a real check are a wiring failure. CI refuses gaps.',
    href: '/platform/vulnerability-research/',
  },
  {
    title: 'Evidence before severity theatre',
    body: 'Critical and high for blind classes wait on an out-of-band callback, not a payload send.',
    href: '/platform/oast-validation/',
  },
  {
    title: 'Paths to what matters',
    body: 'Dijkstra over the risk graph from internet-exposed assets to crown jewels, with choke-points.',
    href: '/platform/attack-path-intelligence/',
  },
  {
    title: 'Host truth from the agent',
    body: 'A small cross-platform binary: on-host detections plus a 7-day UEBA baseline.',
    href: '/platform/endpoint-protection/',
  },
  {
    title: 'Models you choose',
    body: 'Point Council and Ask Weissman at vLLM, Ollama, or any OpenAI-compatible endpoint.',
    href: '/platform/private-ai/',
  },
  {
    title: 'Operations in one console',
    body: 'Findings, playbooks, agents, audit, and NL questions — the Command Center SOC teams already run.',
    href: '/platform/security-operations/',
  },
] as const

export const solutions = [
  {
    id: 'ciso',
    title: 'CISOs and executives',
    body: 'Board-readable risk: FAIR-aligned loss, compliance control mapping (not a certificate), and a live status channel at /status.',
    points: [
      'Attack-path and financial blast-radius views',
      'Control mapping for SOC 2, ISO 27001, GDPR, NIS2, IEC 62443, PCI, CSA CCM',
      'Human-in-the-loop gates on consequential AI actions',
    ],
  },
  {
    id: 'soc',
    title: 'SOC teams',
    body: 'A Command Center for triage, evidence drawers, MITRE tags, and playbooks that fire on severity, KEV, and exposure.',
    points: [
      `${metrics.commandCenterRoutes.value} operational routes`,
      'FP feedback that reweights confidence',
      'Slack, webhook, and signed-PR actions',
    ],
  },
  {
    id: 'research',
    title: 'Security researchers',
    body: 'Engine-level visibility, ATT&CK mapping against v19.1, and an honest accounting of live probes versus aliases.',
    points: [
      `${metrics.liveProbes.value} distinct live-probe implementations`,
      `${metrics.mitreTechniques.value} mapped techniques`,
      'Responsible disclosure at security@weissman.io',
    ],
  },
  {
    id: 'infra',
    title: 'IT and infrastructure',
    body: 'Scope enforcement at the API edge, multi-tenant Postgres RLS, and the same binary on a laptop, a VPC, or Cloud SaaS.',
    points: [
      'Out-of-scope targets return 403 before a packet leaves',
      'Self-hosted with your Postgres, Redis, and optional Ollama',
      'OIDC and SAML for the control plane',
    ],
  },
  {
    id: 'sensitive',
    title: 'Sensitive-data environments',
    body: 'Keep inference on your side. Self-hosted and BYO-LLM are first-class — not a downgrade path.',
    points: [
      'No third-party analytics on the public site or product',
      'DPA with EU SCCs; subprocessors listed in public',
      'Customer scan data isolated per tenant',
    ],
  },
] as const

export const proofPrinciples = [
  {
    title: 'Integrity over inventory',
    body: 'Findings are persisted from live probes. Agent-required and advisory results are labelled. The catalog will not show an engine that cannot run.',
  },
  {
    title: 'Isolation is mechanical',
    body: 'PostgreSQL row-level security on multi-tenant tables, JWT sessions, TOTP MFA, and optional OIDC/SAML.',
  },
  {
    title: 'Autonomy is off until you ask',
    body: 'Sovereign loops that change cloud posture require explicit dual acknowledgement. Safe-by-default is a product choice.',
  },
  {
    title: 'We run the same loop on ourselves',
    body: 'Weissman scans Weissman. Signed remediation PRs are sandbox-verified before merge — including our own.',
  },
] as const

export const pricing = {
  selfHosted: {
    tier: 'Open',
    name: 'Self-hosted',
    price: '$0',
    unit: '/forever',
    blurb: 'Run on your own infrastructure, your own VPC.',
    items: [
      `All ${metrics.productionEngines.value} production engines`,
      'Endpoint agent (Linux / macOS / Windows packaging)',
      'Multi-tenant Postgres + RLS',
      'Auto-PR remediation',
      'SMTP + webhook alerts',
      'Community support (GitHub Issues)',
      'BYO LLM (Ollama / vLLM / OpenAI-compatible)',
    ],
    cta: { label: 'Get it on GitHub', href: company.github },
  },
  cloud: {
    tier: 'Professional',
    name: 'Cloud SaaS',
    price: `$${metrics.cloudPriceUsd.value}`,
    unit: '/month',
    blurb: 'For SOC teams that do not want to operate the stack.',
    items: [
      'Everything in Self-hosted',
      'Hosted with EU-West data residency by default',
      'Up to 25 clients · 300 scans/month',
      'SSO (OIDC + SAML)',
      `Availability objective: ${metrics.slaUptime.value} (SLA_AND_STATUS.md)`,
      'Email + Slack support, 24h response',
      `${metrics.trialDays.value}-day free trial — no card required`,
    ],
    cta: { label: 'Start free trial', href: '/signup.html' },
  },
  enterprise: {
    tier: 'Custom',
    name: 'Enterprise',
    price: 'Talk to us',
    unit: '',
    blurb: 'For MSSPs, regulated industries, and large attack surfaces.',
    items: [
      'Up to 500 clients · 5,000 scans/month (or custom)',
      'Single-tenant deployment option',
      'Custom data residency (IL, EU-West, US-East, AU-East)',
      'Custom engine development',
      'Audit log export to your SIEM',
      'Named CSM + onboarding workshop',
      'Signed MSA + DPA + compliance mapping pack',
    ],
    cta: { label: 'Contact sales', href: '/contact/' },
  },
}

export const pricingFaqs = [
  {
    q: 'Is anything ever simulated?',
    a: 'No production engine invents a finding. Every catalog ID hits a real endpoint or host surface, or is labelled agent-required until the agent is online.',
  },
  {
    q: 'Can I run this air-gapped?',
    a: 'Yes. Self-hosted ships as Docker Compose or systemd plus Postgres and Redis. Threat-intel feeds can be mirrored locally. Point AI features at Ollama or vLLM on your network.',
  },
  {
    q: 'Who pays for the model?',
    a: 'You do, at the provider you choose. Self-hosted and Cloud both speak the OpenAI chat protocol. Nothing requires a Weissman-hosted LLM.',
  },
  {
    q: 'Will Weissman scan things I did not authorise?',
    a: 'No. Every target is checked against the client’s approved scope. Out-of-scope probes are rejected at the API with 403 before a packet leaves.',
  },
] as const

export const about = {
  lede: 'Weissman Cybersecurity Ltd. builds an autonomous offensive-security and active-defence platform in Tel Aviv-Yafo. The company is engineering-led: the public catalog is the same catalog CI verifies.',
  points: [
    'Rust control plane and engines; memory-unsafe code is denied crate-wide with a documented exception.',
    'React Command Center for operators; public site and product share no third-party analytics.',
    'Cloud SaaS or self-hosted — same product, different where the data lives.',
  ],
}
