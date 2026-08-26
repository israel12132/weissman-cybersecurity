export type ProductAccent = 'accent' | 'risk' | 'ops'

export type Product = {
  id: string
  href: string
  eyebrow: string
  title: string
  summary: string
  accent: ProductAccent
  outcomes: [string, string, string]
  capabilities: string[]
  technical: string
  workflow: string[]
  ctaLabel: string
}

export const products: Product[] = [
  {
    id: 'endpoint-protection',
    href: '/platform/endpoint-protection/',
    eyebrow: 'Endpoint',
    title: 'Endpoint protection that starts on the host',
    summary:
      'A single Rust agent for Linux, macOS, and Windows: on-host detections plus a UEBA sampler that learns a 7-day baseline before it shouts.',
    accent: 'ops',
    outcomes: [
      'Fifteen on-host detections, including process hollowing, persistence, ARP spoof, and log integrity',
      'UEBA z-score alerts after a learning window — not on the first noisy hour',
      'WSS+JWT to the control plane; no persistent secrets left on disk beyond the service token',
    ],
    capabilities: [
      'Cross-platform service install (systemd, launchd, Windows Service)',
      'Process, persistence, USB, EDR-presence, and clipboard-entropy checks',
      'Hour-of-week baselines with |z| > 3 medium and |z| > 6 high',
      'New ports and processes fire only after the bucket has enough samples',
    ],
    technical:
      'The agent enrolls over HTTPS, holds a short-lived session JWT, and ships samples on each dispatch. Server-side UEBA keeps a rolling mean and standard deviation per agent, metric, and hour-of-week. Samples older than 14 days are purged.',
    workflow: [
      'Install with a dashboard token',
      'Learn the host for a week of hour-buckets',
      'Surface host findings next to network engines in the same drawer',
    ],
    ctaLabel: 'See endpoint protection',
  },
  {
    id: 'vulnerability-research',
    href: '/platform/vulnerability-research/',
    eyebrow: 'Research',
    title: 'Vulnerability research with a live-probe bar',
    summary:
      '303 live probes — web, API, cloud, OT/ICS, identity, supply chain, AI/LLM, and more. Aliases resolve to a real implementation. CI fails if they do not.',
    accent: 'risk',
    outcomes: [
      '563 production IDs, every one wired to a runner',
      '226 MITRE ATT&CK techniques against the current v19.1 Enterprise, Mobile, and ICS set',
      'No fabricated or randomised findings in the persist path',
    ],
    capabilities: [
      'HTTP, TCP, DNS, TLS, and agent telemetry probes',
      'OT protocol handshakes (Modbus, DNP3, EtherNet/IP, IEC 61850, S7) — not port banners alone',
      'Supply-chain and leaked-secret checks against authorised scopes',
      'Honest labels for agent-required and advisory results',
    ],
    technical:
      'PRODUCTION_ENGINE_IDS is the catalog. engine_dispatch is the only execution path. verify_engine_wiring.mjs and engine_reality_audit.mjs are the public accounting: live probe, alias, or agent-required — never a silent no-op.',
    workflow: [
      'Enable engines per client and tenant',
      'Orchestrator runs the intersection on a cadence',
      'Findings persist with evidence, CWE, and ATT&CK tags',
    ],
    ctaLabel: 'Explore research engines',
  },
  {
    id: 'detection-response',
    href: '/platform/detection-response/',
    eyebrow: 'Detect + respond',
    title: 'Detection that remembers what was already said',
    summary:
      'Stable finding identity, KEV and EPSS at persist time, a false-positive loop, and playbooks that notify, isolate, or open a verified pull request.',
    accent: 'ops',
    outcomes: [
      'Dedup by target, signature, and CWE — re-fires increment seen_count',
      'Ordering prefers known-exploited and high-EPSS over raw CVSS',
      'Remediation PRs are sandbox-verified before merge',
    ],
    capabilities: [
      'SOAR DSL: when severity / KEV / EPSS / exposure, then act',
      'Actions: status, Slack, webhook, HTTP POST, open PR, isolate host, page on-call',
      'FP marks at three suppress; confidence reweights risk_score',
      'Compliance impact surfaced next to evidence (mapped controls, not certificates)',
    ],
    technical:
      'Intel workers refresh CISA KEV every 6 hours and FIRST EPSS every 12 hours (and on demand). Playbook dispatch is idempotent and written to the audit log.',
    workflow: [
      'Finding persists with enrichment',
      'Analyst confirms, marks FP, or lets a playbook fire',
      'Patch or containment is attested',
    ],
    ctaLabel: 'See detection and response',
  },
  {
    id: 'attack-path-intelligence',
    href: '/platform/attack-path-intelligence/',
    eyebrow: 'Paths',
    title: 'Attack paths from the edge to the jewel',
    summary:
      'A risk graph with Dijkstra from internet-exposed nodes to crown jewels. Edges carry CVSS, EPSS, and KEV. Choke-points are first-class.',
    accent: 'risk',
    outcomes: [
      'Top-K paths, not a hairball screenshot',
      'FAIR-aligned SLE and ALE when asset values are on the client',
      'Snapshots you can replay in the Command Center',
    ],
    capabilities: [
      'Graph nodes from live findings and inventory',
      'KEV floors annual rate assumptions',
      'Choke-point ranking for where one fix cuts many paths',
      'Financial blast-radius beside technical severity',
    ],
    technical:
      'Paths persist in attack_path_snapshots. Dollar figures use SLE = asset_value × max(CVSS/10, 0.5) and an EPSS-informed ARO, with KEV forcing a minimum annual rate. These are model outputs, not insurance quotes.',
    workflow: [
      'Build the graph from current findings',
      'Walk exposed → jewel',
      'Prioritise the node that collapses the most paths',
    ],
    ctaLabel: 'See attack-path intelligence',
  },
  {
    id: 'private-ai',
    href: '/platform/private-ai/',
    eyebrow: 'Private AI',
    title: 'Inference that stays on the endpoint you name',
    summary:
      'Supreme Council and Ask Weissman speak the OpenAI protocol. Point them at vLLM, Ollama, or a hosted API. Ask Weissman never emits raw SQL.',
    accent: 'accent',
    outcomes: [
      'Bring-your-own model is the default posture for regulated work',
      'Natural-language questions compile to an allow-listed QueryPlan',
      'Council strategies are signed into the audit log',
    ],
    capabilities: [
      'Offensive proposer, blind defensive critic, sovereign decision',
      'Vector memory of verified wins only — not of the model’s own claims',
      'Read-only Postgres role, 15-second statement timeout',
      'Human approval gates on consequential actions',
    ],
    technical:
      'Ask Weissman validates a JSON plan against six tables and enumerated columns, forces tenant_id, and executes as weissman_ro. Council memory writes only after an out-of-band probe confirms the strategy. Embedding failures degrade; they do not invent vectors.',
    workflow: [
      'Configure WEISSMAN_LLM_BASE_URL (or keep AI features off)',
      'Ask a question or run a council-assisted scan',
      'Review the audit trail before anything privileged happens',
    ],
    ctaLabel: 'See private AI',
  },
  {
    id: 'security-operations',
    href: '/platform/security-operations/',
    eyebrow: 'Operations',
    title: 'A Command Center built for the people on shift',
    summary:
      '130 routes, live KPI strips, findings drawers, playbook builder, agent fleet, and Ask Weissman — English and Hebrew, including RTL.',
    accent: 'accent',
    outcomes: [
      'One console for scans, evidence, and response',
      'RBAC from viewer through CEO and superadmin',
      'Public /status when the rest of the room is on fire',
    ],
    capabilities: [
      'SSE and WebSocket telemetry',
      'Visual SOAR editor',
      'Audit log viewer',
      'Self-serve signup when the operator enables it',
    ],
    technical:
      'The SPA is React/Vite, proxied behind the same nginx gateway as this site. It talks to weissman-server on /api and /ws. Marketing pages never share that session cookie purpose-built for the product.',
    workflow: [
      'Sign in with MFA',
      'Pick a client and a scope',
      'Work findings the way the shift already works tickets',
    ],
    ctaLabel: 'See security operations',
  },
  {
    id: 'oast-validation',
    href: '/platform/oast-validation/',
    eyebrow: 'OAST',
    title: 'Blind classes wait for a callback',
    summary:
      'A dedicated HTTP and DNS listener. Engines plant a token; the fuzzer polls until the target actually reaches out. That is the difference between sent and proven.',
    accent: 'risk',
    outcomes: [
      'SSRF, XXE, and JNDI-style classes do not go critical on a send alone',
      'Callbacks store source IP, method, path, headers, and DNS qname',
      'Same listener underpins canary and deception flows',
    ],
    capabilities: [
      'Per-scan unique tokens',
      'HTTP and DNS capture',
      'Correlation before verified severity',
      'Operator-configured OAST domain',
    ],
    technical:
      'weissman-oast-server records interactions keyed by token. Engines embed that token in payloads. Critical and high for out-of-band classes require verification_method that proves a callback — not just that a probe was seeded.',
    workflow: [
      'Scan plants a token',
      'Listener records the callback',
      'Finding upgrades only after correlation',
    ],
    ctaLabel: 'See OAST validation',
  },
]

export const platformTabs = products
