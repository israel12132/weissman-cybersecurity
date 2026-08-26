/**
 * English source catalog. Every user-facing marketing string lives here.
 * Missing keys in other locales fall back to these values.
 */
export const en = {
  seo: {
    home: {
      title: 'Weissman Cybersecurity — Live evidence. Clearer response.',
      description:
        'Weissman continuously probes authorised attack surfaces with 563 production engines, verifies findings with live evidence, and helps SOC teams prioritise and respond.',
    },
    platform: {
      title: 'Platform — Weissman Cybersecurity',
      description:
        'One platform for live probing, attack-path intelligence, endpoint telemetry, private AI, OAST validation, and SOC operations.',
    },
    'endpoint-protection': {
      title: 'Endpoint Protection — Weissman Cybersecurity',
      description:
        'Cross-platform Weissman agent with on-host detections and UEBA baselines for Linux, macOS, and Windows.',
    },
    'vulnerability-research': {
      title: 'Vulnerability Research — Weissman Cybersecurity',
      description:
        '303 live probes across web, cloud, OT, identity, and supply chain — every finding from a real network or host check.',
    },
    'detection-response': {
      title: 'Detection and Response — Weissman Cybersecurity',
      description:
        'Deduplicated findings, KEV/EPSS enrichment, SOAR playbooks, and signed-PR remediation with sandbox verification.',
    },
    'attack-path-intelligence': {
      title: 'Attack-Path Intelligence — Weissman Cybersecurity',
      description:
        'Graph-based paths from internet-exposed assets to crown jewels, with choke-point analysis and FAIR-aligned loss estimates.',
    },
    'private-ai': {
      title: 'Private AI — Weissman Cybersecurity',
      description:
        'Bring your own vLLM, Ollama, or OpenAI-compatible model. Ask Weissman compiles natural language to allow-listed SQL on a read-only role.',
    },
    'security-operations': {
      title: 'Security Operations — Weissman Cybersecurity',
      description:
        'Command Center for live events, findings, playbooks, agents, and Ask Weissman — 130 operational routes for SOC teams.',
    },
    'oast-validation': {
      title: 'OAST Validation — Weissman Cybersecurity',
      description:
        'HTTP and DNS out-of-band listeners confirm blind SSRF, XXE, and callback classes before a finding is marked verified.',
    },
    solutions: {
      title: 'Solutions — Weissman Cybersecurity',
      description:
        'How CISOs, SOC teams, researchers, and infrastructure owners use Weissman to see, validate, and act on real risk.',
    },
    technology: {
      title: 'Technology — Weissman Cybersecurity',
      description: 'Observe, analyse, validate, and respond: how Weissman turns live probes into prioritised action.',
    },
    resources: {
      title: 'Resources — Weissman Cybersecurity',
      description:
        'Technical overviews, responsible disclosure, legal documents, and platform references from Weissman Cybersecurity.',
    },
    about: {
      title: 'About — Weissman Cybersecurity',
      description:
        'Weissman Cybersecurity Ltd., Tel Aviv-Yafo. An autonomous offensive-security and active-defence platform built in Rust.',
    },
    contact: {
      title: 'Book a Demo — Weissman Cybersecurity',
      description: 'Request a Weissman demo or speak with the team about deploying the platform in your environment.',
    },
    pricing: {
      title: 'Services — Weissman Cybersecurity',
      description:
        'Weissman is not sold as packaged website tiers. Contact us to scope the platform for your organisation. Existing customers sign in to Command Center.',
    },
    signup: {
      title: 'Request access — Weissman Cybersecurity',
      description: 'Contact Weissman to request platform access. Existing customers sign in to Command Center.',
    },
    terms: {
      title: 'Terms of Service — Weissman Cybersecurity',
      description: 'Terms of Service for the Weissman Cybersecurity platform.',
    },
    privacy: {
      title: 'Privacy Policy — Weissman Cybersecurity',
      description: 'Privacy Policy for Weissman Cybersecurity Ltd. GDPR and CCPA aligned.',
    },
    'terms-he': {
      title: 'תנאי שימוש — Weissman Cybersecurity',
      description: 'תנאי שימוש לפלטפורמת Weissman Cybersecurity.',
    },
    'privacy-he': {
      title: 'מדיניות פרטיות — Weissman Cybersecurity',
      description: 'מדיניות פרטיות של Weissman Cybersecurity Ltd.',
    },
    dpa: {
      title: 'Data Processing Addendum — Weissman Cybersecurity',
      description: 'Data Processing Addendum incorporating EU SCCs (2021/914).',
    },
    subprocessors: {
      title: 'Subprocessors — Weissman Cybersecurity',
      description: 'Current Cloud SaaS sub-processors and threat-intelligence data sources.',
    },
    'security-policy': {
      title: 'Responsible Disclosure — Weissman Cybersecurity',
      description: 'How to report a vulnerability to Weissman Cybersecurity.',
    },
    'not-found': {
      title: 'Page not found — Weissman Cybersecurity',
      description: 'The page you requested is not part of the Weissman public site.',
    },
  },
  a11y: {
    skip: 'Skip to content',
    primaryNav: 'Primary',
    mobileNav: 'Mobile navigation',
    openMenu: 'Open menu',
    closeMenu: 'Close menu',
    closeOverlay: 'Close menu overlay',
    home: 'Weissman home',
    language: 'Language',
    languageEn: 'Switch to English',
    languageHe: 'מעבר לעברית',
    currentLanguage: 'Current language: {name}',
    dismissAnnouncement: 'Dismiss announcement',
    cookie: 'Cookie notice',
    onThisPage: 'On this page',
    featuredPrev: 'Previous featured',
    featuredNext: 'Next featured',
    severityFilter: 'Severity filter',
    resourceFilter: 'Filter resources',
    audiences: 'Audiences',
    platformAreas: 'Platform areas',
    attackPathVisual: 'Illustrative attack-path composition',
    attackPathSvg: 'Internet edge connecting through a choke-point to a crown jewel',
    theaterTabs: 'Product scene phases',
  },
  lang: {
    en: 'English',
    he: 'עברית',
    enShort: 'EN',
    heShort: 'עברית',
  },
  brand: {
    name: 'Weissman',
    legalName: 'Weissman Cybersecurity Ltd.',
    location: 'Tel Aviv-Yafo, Israel',
    product: 'Weissman Cybersecurity Platform',
    jsonLdDescription:
      'Autonomous offensive-security and active-defence platform with live probes, attack-path intelligence, and a SOC Command Center.',
  },
  cta: {
    bookDemo: 'Book a Demo',
    requestDemo: 'Request a demo',
    explorePlatform: 'Explore the Platform',
    experiencePlatform: 'Experience the Platform',
    seeFit: 'See how it fits your environment',
    signIn: 'Sign in',
    customerLogin: 'Customer login',
    startTrial: 'Start free trial',
    learnMore: 'Learn more',
    contactUs: 'Contact us',
    status: 'System status',
    apiDocs: 'API docs',
    github: 'GitHub',
    howItWorks: 'How it works',
    platformOverview: 'Platform overview',
    technologyWalkthrough: 'Full technology walkthrough',
    home: 'Home',
    platform: 'Platform',
  },
  nav: {
    products: 'Platform',
    solutions: 'Solutions',
    technology: 'Technology',
    resources: 'Resources',
    company: 'Company',
    mega: {
      products: {
        platform: 'Platform',
        capabilities: 'Capabilities',
        overview: { label: 'Platform overview', description: 'How the pieces connect' },
        commandCenter: { label: 'Command Center', description: 'SOC workspace and live events' },
        howItWorks: { label: 'How it works', description: 'Observe → validate → respond' },
        endpoint: { label: 'Endpoint protection', description: 'Agent detections and UEBA' },
        research: { label: 'Vulnerability research', description: 'Live probes across domains' },
        detect: { label: 'Detection and response', description: 'Triage, SOAR, signed PRs' },
        paths: { label: 'Attack-path intelligence', description: 'Crown-jewel paths and choke-points' },
        privateAi: { label: 'Private AI', description: 'BYO models, Ask Weissman' },
        oast: { label: 'OAST validation', description: 'Blind callbacks, proven' },
      },
      solutions: {
        audience: 'By audience',
        ciso: { label: 'CISOs', description: 'Risk, mapping, governance' },
        soc: { label: 'SOC teams', description: 'Triage and playbooks' },
        research: { label: 'Researchers', description: 'Coverage you can audit' },
        infra: { label: 'IT and infrastructure', description: 'Scope, SSO, self-host' },
        sensitive: { label: 'Sensitive data', description: 'Your VPC, your model' },
      },
      technology: {
        architecture: 'Architecture',
        how: { label: 'How it works', description: 'Four-stage loop' },
        integrity: { label: 'Engine integrity', description: 'Wiring gate, no silent IDs' },
        inference: { label: 'Private inference', description: 'vLLM, Ollama, allow-listed SQL' },
      },
      resources: {
        library: 'Library',
        all: { label: 'All resources', description: 'Filter by type' },
        disclosure: { label: 'Responsible disclosure', description: 'Report a vulnerability' },
        api: { label: 'API reference', description: 'OpenAPI 3.1' },
        status: { label: 'System status', description: 'Public health' },
      },
      company: {
        weissman: 'Weissman',
        about: { label: 'About', description: 'Who we are' },
        contact: { label: 'Contact', description: 'Demo and sales' },
        pricing: { label: 'Services', description: 'Contact us to scope a deployment' },
        legal: { label: 'Legal', description: 'Terms, privacy, DPA' },
      },
    },
    footer: {
      product: 'Product',
      company: 'Company',
      resources: 'Resources',
      legal: 'Legal',
      platform: 'Platform',
      endpoint: 'Endpoint protection',
      research: 'Vulnerability research',
      detect: 'Detection and response',
      paths: 'Attack-path intelligence',
      privateAi: 'Private AI',
      oast: 'OAST validation',
      operations: 'Security operations',
      pricing: 'Services',
      about: 'About',
      contact: 'Contact',
      signIn: 'Customer login',
      signup: 'Create workspace',
      status: 'System status',
      library: 'Resource library',
      technology: 'Technology',
      solutions: 'Solutions',
      api: 'API docs',
      securityTxt: 'security.txt',
      terms: 'Terms',
      privacy: 'Privacy',
      dpa: 'DPA',
      subprocessors: 'Sub-processors',
      disclosure: 'Responsible disclosure',
    },
    sections: {
      'why-us': 'Why us',
      platform: 'Platform',
      experience: 'Experience',
      capabilities: 'Capabilities',
      'how-it-works': 'How it works',
      proof: 'Proof',
      resources: 'Resources',
      contact: 'Contact',
    },
  },
  announcement: {
    kicker: 'Release 2026.06.2',
    text: 'Liminal Boundary Engine is the current platform release — live probes, ATT&CK-mapped findings, and Command Center operations.',
    hrefLabel: 'Read the overview',
  },
  cookie: {
    body: 'We use functional cookies only — never tracking pixels. By using Weissman you accept our {privacy}.',
    privacy: 'Privacy Policy',
    accept: 'Accept',
  },
  hero: {
    kicker: 'Autonomous offensive security + active defence',
    h1: 'The landscape got noisier. Your evidence should not.',
    lead: 'Weissman probes the attack surfaces you authorise — {engines} production engines, live evidence, and a Command Center for SOC teams who need proof before they act.',
    scrollCue: 'Scroll — noise becomes a path',
    theaterTabs: 'Product scene phases',
    theaterTitle: 'Weissman product scene: findings, attack path, response',
    theaterDesc:
      'An authorised environment with unprioritised alerts, an attributed path from the internet edge to a crown jewel, and a P1 finding with a recommended action.',
    phaseNoise: 'Noise',
    phasePath: 'Path',
    phasePriority: 'Priority',
    captionNoise: 'Unprioritised alerts across distributed endpoints.',
    captionPath: 'Attributed path from the internet edge to a crown jewel.',
    captionPriority: 'F-1042 ordered by exposure, KEV/EPSS, and evidence — not by who shouted last.',
  },
  metrics: {
    productionEngines: 'Production engines',
    liveProbes: 'Live probes',
    engineAliases: 'Catalog aliases',
    agentRequired: 'Agent-required engines',
    commandCenterRoutes: 'Command Center routes',
    auditedPages: 'Audited UI pages',
    mitreTechniques: 'MITRE ATT&CK techniques',
    agentDetections: 'On-host detections',
    kevRefreshHours: 'CISA KEV refresh (hours)',
    epssRefreshHours: 'FIRST EPSS refresh (hours)',
    slaUptime: 'Cloud availability objective',
  },
  featured: {
    eyebrow: 'Featured',
    title: 'From the platform',
  },
  visual: {
    caption: 'Attack path · illustrative',
    live: 'probe live',
    ccCaption: 'Command Center · sample',
  },
  home: {
    threatEyebrow: 'Threat landscape',
    threatTitle: 'Complexity went up. Clarity has to follow.',
    storySub: 'Scroll the stages. The same authorised environment moves from noise, to an attributed path, to one operational view.',
    story: {
      challenge: {
        label: 'Stage 1 — Challenge',
        title: 'Alerts without a path',
        body: 'Web, cloud, identity, OT, and hosts all fire. A finding that is not proven still consumes the same analyst hour as one that is. Coverage that cannot execute a real check is just inventory.',
        visual: 'Unprioritised telemetry',
      },
      transform: {
        label: 'Stage 2 — Transformation',
        title: 'Connect, filter, attribute',
        body: 'Live probes, OAST callbacks, and host telemetry share one finding model. Duplicate noise collapses. The remaining graph is a path — not a pile of CVEs.',
        visual: 'Attributed attack path',
      },
      outcome: {
        label: 'Stage 3 — Outcome',
        title: 'One view you can act on',
        body: 'KEV, EPSS, and crown-jewel exposure order the work. Suggested isolation, rotation, or a signed PR sits next to the evidence — in the Command Center SOC teams already run.',
        visual: 'Prioritised operational view',
      },
    },
    platformEyebrow: 'Platform',
    platformTitle: 'One loop. Seven confirmed surfaces.',
    platformSub: 'Each area is in the product today — not a roadmap slide.',
    interactCtaSub: 'Open a guided walkthrough of detection, analysis, validation, and response — labelled sample data, not a tenant.',
    interactiveEyebrow: 'Experience the platform',
    interactiveTitle: 'How an investigation reads',
    interactiveSub:
      'Sample rows only. Filters and the investigation panel behave like the product; they are not connected to a tenant.',
    capabilitiesEyebrow: 'Capabilities',
    capabilitiesTitle: 'Outcomes, not adjectives',
    howEyebrow: 'How it works',
    howTitle: 'Four stages. No ceremony.',
    solutionsEyebrow: 'Solutions',
    solutionsTitle: 'Built for the people who have to decide',
    solutionsAudience: 'Audience',
    proofEyebrow: 'Proof',
    proofTitle: 'Built for security-critical environments',
    proofSub:
      'We do not publish customer logos or analyst awards we do not have. These are operating principles you can inspect in the product and the legal pack.',
    trustCtaSub: 'Walk the same loop against an environment like yours — Cloud SaaS, self-hosted, or Enterprise.',
    resourcesEyebrow: 'Resources',
    resourcesTitle: 'What we can actually publish',
    finalEyebrow: 'Book a demo',
    finalTitle: 'See the evidence, then decide.',
    finalBody: 'A short form. A real reply. No invented success if this deployment cannot send mail.',
    threat: {
      '01': {
        title: 'What changed',
        body: 'Attack surfaces now span web, cloud, identity, OT, supply chain, and the models sitting next to production data. A finding that is not proven still consumes the same analyst hour as one that is.',
      },
      '02': {
        title: 'Where tools fragment',
        body: 'Scanners, ticketing, intel feeds, and SOAR often disagree on the same CVE. Alias-heavy catalogs and simulated checks inflate coverage while leaving blind classes unconfirmed.',
      },
      '03': {
        title: 'How Weissman is built',
        body: 'Every production engine ID resolves to a real HTTP, TCP, DNS, TLS, or agent probe. Blind classes wait for an OAST callback. Risk is ordered by KEV, EPSS, and attack path — not by who shouted last.',
      },
    },
  },
  howItWorks: {
    observe: {
      title: 'Observe',
      body: 'Onboard a client and a written scope. Discovery and the endpoint agent (when installed) map what is actually reachable — domains, cloud roles, hosts, and protocols.',
    },
    analyse: {
      title: 'Analyse',
      body: 'The orchestrator runs the enabled engine suite. Findings are deduplicated by stable signature, clustered, and enriched with CISA KEV and FIRST EPSS at persist time.',
    },
    validate: {
      title: 'Validate and prioritise',
      body: 'OAST confirms blind callbacks. Attack-path inference walks internet-exposed nodes toward crown jewels. FAIR-aligned loss figures sit next to CVSS — not instead of evidence.',
    },
    respond: {
      title: 'Respond',
      body: 'SOAR playbooks notify, isolate, or open a signed pull request. Patches are verified in an ephemeral sandbox before merge. False positives teach the next cycle.',
    },
  },
  capabilities: {
    probes: {
      title: 'Live probes, not simulations',
      body: 'Catalog IDs that cannot execute a real check are a wiring failure. CI refuses gaps.',
    },
    evidence: {
      title: 'Evidence before severity theatre',
      body: 'Critical and high for blind classes wait on an out-of-band callback, not a payload send.',
    },
    paths: {
      title: 'Paths to what matters',
      body: 'Dijkstra over the risk graph from internet-exposed assets to crown jewels, with choke-points.',
    },
    host: {
      title: 'Host truth from the agent',
      body: 'A small cross-platform binary: on-host detections plus a 7-day UEBA baseline.',
    },
    models: {
      title: 'Models you choose',
      body: 'Point Council and Ask Weissman at vLLM, Ollama, or any OpenAI-compatible endpoint.',
    },
    ops: {
      title: 'Operations in one console',
      body: 'Findings, playbooks, agents, audit, and NL questions — the Command Center SOC teams already run.',
    },
  },
  solutions: {
    pageEyebrow: 'Solutions',
    pageTitle: 'Same platform. Different questions.',
    pageLead:
      'Weissman is sold to operators, not industries we invented. These are the audiences already implied by the product: executives, SOC, research, infrastructure, and teams that cannot send data to a public model.',
    ciso: {
      title: 'CISOs and executives',
      body: 'Board-readable risk: FAIR-aligned loss, compliance control mapping (not a certificate), and a live status channel at /status.',
      points: [
        'Attack-path and financial blast-radius views',
        'Control mapping for SOC 2, ISO 27001, GDPR, NIS2, IEC 62443, PCI, CSA CCM',
        'Human-in-the-loop gates on consequential AI actions',
      ],
    },
    soc: {
      title: 'SOC teams',
      body: 'A Command Center for triage, evidence drawers, MITRE tags, and playbooks that fire on severity, KEV, and exposure.',
      points: [
        '{routes} operational routes',
        'FP feedback that reweights confidence',
        'Slack, webhook, and signed-PR actions',
      ],
    },
    research: {
      title: 'Security researchers',
      body: 'Engine-level visibility, ATT&CK mapping against v19.1, and an honest accounting of live probes versus aliases.',
      points: [
        '{probes} distinct live-probe implementations',
        '{techniques} mapped techniques',
        'Responsible disclosure at security@weissman.io',
      ],
    },
    infra: {
      title: 'IT and infrastructure',
      body: 'Scope enforcement at the API edge, multi-tenant Postgres RLS, and the same binary on a laptop, a VPC, or Cloud SaaS.',
      points: [
        'Out-of-scope targets return 403 before a packet leaves',
        'Self-hosted with your Postgres, Redis, and optional Ollama',
        'OIDC and SAML for the control plane',
      ],
    },
    sensitive: {
      title: 'Sensitive-data environments',
      body: 'Keep inference on your side. Self-hosted and BYO-LLM are first-class — not a downgrade path.',
      points: [
        'No third-party analytics on the public site or product',
        'DPA with EU SCCs; subprocessors listed in public',
        'Customer scan data isolated per tenant',
      ],
    },
  },
  proof: {
    integrity: {
      title: 'Integrity over inventory',
      body: 'Findings are persisted from live probes. Agent-required and advisory results are labelled. The catalog will not show an engine that cannot run.',
    },
    isolation: {
      title: 'Isolation is mechanical',
      body: 'PostgreSQL row-level security on multi-tenant tables, JWT sessions, TOTP MFA, and optional OIDC/SAML.',
    },
    autonomy: {
      title: 'Autonomy is off until you ask',
      body: 'Sovereign loops that change cloud posture require explicit dual acknowledgement. Safe-by-default is a product choice.',
    },
    ourselves: {
      title: 'We run the same loop on ourselves',
      body: 'Weissman scans Weissman. Signed remediation PRs are sandbox-verified before merge — including our own.',
    },
  },
  platformPage: {
    eyebrow: 'Platform',
    title: 'Detection, validation, prioritisation, and response in one control plane.',
    lead: 'Weissman is not a scanner with a theme. Engines, agent, OAST, attack paths, SOAR, and the Command Center share one finding model and one audit trail.',
    modulesEyebrow: 'Modules',
    modulesTitle: 'Confirmed product areas',
    indexEyebrow: 'Index',
    indexTitle: 'Every capability page',
    loopEyebrow: 'Loop',
    loopTitle: 'The same four stages everywhere',
  },
  productPage: {
    outcomes: 'Outcomes',
    capabilities: 'Capabilities',
    technical: 'Technical',
    workflow: 'Workflow',
    related: 'Related',
    outcomesTitle: 'What changes when this is on',
    capabilitiesTitle: 'In the product',
    technicalTitle: 'How it is actually built',
    workflowTitle: 'Architecture in three moves',
    relatedTitle: 'Nearby in the platform',
    walkTitle: 'Walk this in the Command Center',
    missing: 'This capability page is not in the catalog.',
    notFound: 'Not found',
  },
  products: {
    'endpoint-protection': {
      eyebrow: 'Endpoint',
      title: 'Endpoint protection that starts on the host',
      summary:
        'A single Rust agent for Linux, macOS, and Windows: on-host detections plus a UEBA sampler that learns a 7-day baseline before it shouts.',
      ctaLabel: 'See endpoint protection',
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
    },
    'vulnerability-research': {
      eyebrow: 'Research',
      title: 'Vulnerability research with a live-probe bar',
      summary:
        '303 live probes — web, API, cloud, OT/ICS, identity, supply chain, AI/LLM, and more. Aliases resolve to a real implementation. CI fails if they do not.',
      ctaLabel: 'Explore research engines',
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
    },
    'detection-response': {
      eyebrow: 'Detect + respond',
      title: 'Detection that remembers what was already said',
      summary:
        'Stable finding identity, KEV and EPSS at persist time, a false-positive loop, and playbooks that notify, isolate, or open a verified pull request.',
      ctaLabel: 'See detection and response',
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
    },
    'attack-path-intelligence': {
      eyebrow: 'Paths',
      title: 'Attack paths from the edge to the jewel',
      summary:
        'A risk graph with Dijkstra from internet-exposed nodes to crown jewels. Edges carry CVSS, EPSS, and KEV. Choke-points are first-class.',
      ctaLabel: 'See attack-path intelligence',
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
    },
    'private-ai': {
      eyebrow: 'Private AI',
      title: 'Inference that stays on the endpoint you name',
      summary:
        'Supreme Council and Ask Weissman speak the OpenAI protocol. Point them at vLLM, Ollama, or a hosted API. Ask Weissman never emits raw SQL.',
      ctaLabel: 'See private AI',
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
    },
    'security-operations': {
      eyebrow: 'Operations',
      title: 'A Command Center built for the people on shift',
      summary:
        '130 routes, live KPI strips, findings drawers, playbook builder, agent fleet, and Ask Weissman — English and Hebrew, including RTL.',
      ctaLabel: 'See security operations',
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
    },
    'oast-validation': {
      eyebrow: 'OAST',
      title: 'Blind classes wait for a callback',
      summary:
        'A dedicated HTTP and DNS listener. Engines plant a token; the fuzzer polls until the target actually reaches out. That is the difference between sent and proven.',
      ctaLabel: 'See OAST validation',
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
    },
  },
  technologyPage: {
    eyebrow: 'Technology',
    title: 'Observe. Analyse. Validate. Respond.',
    lead: 'The orchestrator is a scoped loop, not a slogan. Scope is enforced before packets. Findings persist only from live probes. Blind classes wait on OAST. Response is audited.',
    stagesEyebrow: 'Stages',
    stagesTitle: 'Mapped to the running system',
    integrityEyebrow: 'Integrity',
    integrityTitle: 'Numbers you can re-run',
  },
  resourcesPage: {
    eyebrow: 'Resources',
    title: 'Published material only.',
    lead: 'No invented case studies or analyst notes. If a category is empty later, it stays empty until there is something real to put in it.',
    empty: 'No published items in this category yet.',
    types: {
      all: 'All',
      product: 'Product',
      research: 'Research',
      technical: 'Technical',
      policy: 'Policy',
      demo: 'Demo',
      legal: 'Legal',
    },
    items: {
      'release-2026-06-2': {
        title: 'Liminal Boundary Engine — 2026.06.2',
        summary: 'Current CalVer release of the Weissman platform.',
      },
      'mitre-coverage': {
        title: 'ATT&CK coverage against v19.1',
        summary: '226 techniques: 192 primary mappings plus 34 code-grounded secondary tags.',
      },
      'engine-integrity': {
        title: 'Engine integrity accounting',
        summary: '563 IDs classified as live probe, alias, or agent-required — CI-gated, no silent catalog entries.',
      },
      'platform-overview': {
        title: 'Platform technical overview',
        summary: 'Observe, analyse, validate, respond — how the orchestrator and Command Center fit.',
      },
      disclosure: {
        title: 'Responsible disclosure',
        summary: 'How to report a vulnerability. No monetary bounty today; we credit in the changelog with consent.',
      },
      'book-demo': {
        title: 'Book a demo',
        summary: 'Walk the Command Center with the Weissman team.',
      },
      'api-docs': {
        title: 'OpenAPI 3.1 reference',
        summary: 'Interactive docs for the control-plane API.',
      },
      status: {
        title: 'Public status',
        summary: 'Live health for the Cloud service.',
      },
      terms: {
        title: 'Terms of Service',
        summary: 'Contract terms for Cloud and self-hosted use.',
      },
      privacy: {
        title: 'Privacy Policy',
        summary: 'What we collect, what we refuse to collect, and how to reach the DPO.',
      },
      dpa: {
        title: 'Data Processing Addendum',
        summary: 'Processor terms including EU SCCs Module 2.',
      },
      subprocessors: {
        title: 'Sub-processors',
        summary: 'Infrastructure, email, payments, and outbound intel feeds.',
      },
    },
  },
  aboutPage: {
    eyebrow: 'Company',
    operateTitle: 'How we operate',
    contactTitle: 'Contact',
    lede: 'Weissman Cybersecurity Ltd. builds an autonomous offensive-security and active-defence platform in Tel Aviv-Yafo. The company is engineering-led: the public catalog is the same catalog CI verifies.',
    points: [
      'Rust control plane and engines; memory-unsafe code is denied crate-wide with a documented exception.',
      'React Command Center for operators; public site and product share no third-party analytics.',
      'Cloud SaaS or self-hosted — same product, different where the data lives.',
    ],
    registered: 'Registered address: {location}. Company number: {id} — filled after incorporation; not invented here.',
    roles: {
      sales: 'sales',
      security: 'security',
      dpo: 'dpo',
      legal: 'legal',
      support: 'support',
    },
  },
  contactPage: {
    eyebrow: 'Contact',
    title: 'Book a demo',
    lead: 'Tell us about the environment you want to walk. If this deployment cannot send mail, the form will say so — it will not pretend the request landed.',
    sales: 'Sales',
    security: 'Security',
    support: 'Support',
  },
  pricingPage: {
    eyebrow: 'Services',
    title: 'No packaged tiers. Talk to us, then we scope the work.',
    lead: 'Whoever wants Weissman in their organisation contacts us. We do not sell self-serve plans on this site. Existing customers sign in to Command Center.',
    emailLabel: 'Write to',
    loginHint: 'Already onboarded? Open the live Command Center with your customer credentials.',
    faqsTitle: 'Questions we already answer',
    faqs: [
      {
        q: 'Is anything ever simulated?',
        a: 'No production engine invents a finding. Every catalog ID hits a real endpoint or host surface, or is labelled agent-required until the agent is online.',
      },
      {
        q: 'Can the platform run in our environment?',
        a: 'Yes. Deployments are scoped with you — including running in your VPC with your Postgres, Redis, and optional private models. Contact us and we will walk the options against your constraints.',
      },
      {
        q: 'Will Weissman scan things I did not authorise?',
        a: 'No. Every target is checked against the client’s approved scope. Out-of-scope probes are rejected at the API with 403 before a packet leaves.',
      },
      {
        q: 'How do existing customers get in?',
        a: 'Use Customer login in the header. It opens Command Center at /command-center/login — the same control plane the product runs on, not a marketing copy of it.',
      },
    ],
  },
  signupPage: {
    title: 'Request access',
    lead: 'Workspaces are opened with us — not as a self-serve package on this site. Tell us about the environment, or sign in if you already have credentials.',
    haveAccount: 'Already a customer?',
  },
  notFound: {
    eyebrow: '404',
    title: 'This path is not a page.',
    body: 'The public site returns a real 404 for unknown URLs so crawlers and monitors are not shown the homepage.',
  },
  legal: {
    englishOnly:
      'This legal document is provided in English. An approved Hebrew translation has not been issued for this page. The English text is the binding version and is listed for legal review.',
    missing: 'Document missing.',
  },
  demoJourney: {
    formTitle: 'Request a walkthrough',
    after: {
      title: 'After you send this',
      body: 'A product specialist replies from {email}. If this deployment cannot send mail, the form says so and offers email — it never pretends the request landed.',
    },
    during: {
      title: 'What you will see',
      body: 'A Command Center walkthrough: live-probe findings, an attributed attack path, and one investigation from detection through recommended response.',
    },
    who: {
      title: 'Who it is for',
      body: 'CISOs, SOC leads, and infrastructure owners evaluating Cloud SaaS, self-hosted, or Enterprise.',
    },
    value: {
      title: 'What you leave with',
      body: 'A clear read on how evidence, priority, and action would look in an environment like yours — not a slide deck of unverified claims.',
    },
  },
  demoForm: {
    name: 'Name',
    email: 'Work email',
    organisation: 'Organisation',
    role: 'Role',
    message: 'What should we cover?',
    sending: 'Sending…',
    submit: 'Request a demo',
    emailSales: 'Email {email}',
    errName: 'Enter your name.',
    errEmail: 'Enter a valid work email.',
    errOrg: 'Enter an organisation name.',
    errMessage: 'Tell us briefly what you want to see (10+ characters).',
    success: 'Request received. We will reply from {email}.',
    smtpOff: 'This deployment is not configured to accept demo requests over email. Use {email} instead.',
    fail: 'The request could not be sent. Try again or email {email}.',
    network: 'Network error. The form was not submitted. Email {email} or retry.',
  },
  signupForm: {
    workspace: 'Workspace name',
    email: 'Work email',
    password: 'Password',
    hint: 'Min 12 characters · mix letters and numbers/symbols',
    agreeBefore: 'I agree to the',
    terms: 'Terms of Service',
    and: 'and',
    privacy: 'Privacy Policy',
    creating: 'Creating…',
    submit: 'Create workspace',
    verify: 'Dev verify link →',
    errWorkspace: 'Workspace name must be 2–80 characters.',
    errEmail: 'Enter a valid work email.',
    errPasswordLen: 'Use at least 12 characters with letters and numbers or symbols.',
    errPasswordMix: 'Mix letters with numbers or symbols.',
    errTerms: 'You must accept the Terms of Service and Privacy Policy.',
    success: 'Check your inbox to confirm your workspace.',
    gated: 'Self-serve signup is not enabled on this deployment. Contact {email}.',
    fail: 'Something went wrong. Try again.',
    network: 'Network error — the workspace was not created. Please try again.',
  },
  interactive: {
    title: 'Command Center walkthrough',
    badge: 'Illustrative — not live tenant data',
    stream: 'sample event stream',
    view: 'View',
    viewExec: 'Executive',
    viewTech: 'Technical',
    viewHint: 'Same sample finding. Different altitude.',
    loop: 'Investigation loop',
    loopDetect: 'Detect',
    loopAnalyse: 'Analyse',
    loopValidate: 'Validate',
    loopRespond: 'Respond',
    loopHint: {
      detect: 'Host and network telemetry as it first lands — including noise that is not yet a path.',
      analyse: 'Dedup, KEV/EPSS enrichment, and ATT&CK tags on a stable finding identity.',
      validate: 'Blind classes wait for an OAST callback before they are marked verified.',
      respond: 'Suggested isolation, rotation, or a signed PR next to the evidence.',
    },
    why: 'Why this was prioritised',
    asset: 'Asset',
    all: 'all',
    id: 'ID',
    finding: 'Finding',
    attack: 'ATT&CK',
    empty: 'No sample rows for this filter.',
    investigation: 'Investigation',
    epss: 'EPSS',
    kev: 'KEV',
    kevYes: 'listed',
    kevNo: 'no',
    timeline: 'Timeline',
    remediation: 'Suggested remediation',
    hidePath: 'Hide sample attack path',
    showPath: 'Expand sample attack path',
    severity: {
      all: 'all',
      critical: 'critical',
      high: 'high',
      medium: 'medium',
      info: 'info',
    },
    findings: {
      'F-1042': {
        title: 'Blind SSRF candidate awaiting callback',
        timeline: 'probe planted · listener idle',
        evidence: 'OAST token embedded. No HTTP/DNS callback yet — not marked verified.',
        remediation: 'Wait for correlation, then restrict egress from the app tier.',
        why: 'High EPSS, internet-facing edge, but not verified until the listener fires — so it is not treated as Critical.',
        exec: 'A possible blind SSRF on the edge. We will not call it confirmed until an out-of-band callback arrives.',
      },
      'F-0988': {
        title: 'Internet-exposed admin path on idp-core',
        timeline: 'live probe · 2 recurrences',
        evidence: 'HTTP 200 on an in-scope admin route. KEV-listed CVE attached at persist.',
        remediation: 'Remove public exposure; require SSO; rotate credentials.',
        why: 'Known-exploited, identity-plane, internet-exposed — this is the path that reaches crown jewels first.',
        exec: 'Your identity plane is reachable from the internet on an admin path. That is the finding to act on now.',
      },
      'F-0771': {
        title: 'New listening port on workstation',
        timeline: 'UEBA · out of learning window',
        evidence: 'Port never seen in this hour-of-week bucket after 24 samples.',
        remediation: 'Confirm expected software; isolate if unexplained.',
        why: 'Unusual after the learning window, but no KEV and no path to a crown jewel — medium until correlated.',
        exec: 'A workstation opened a port it does not usually open. Confirm it is expected software before isolating.',
      },
      'F-0610': {
        title: 'Advisory: agent not enrolled',
        timeline: 'catalog · agent_required',
        evidence: 'Host engines labelled empty until the Weissman agent is online.',
        remediation: 'Install the agent if this host is in written scope.',
        why: 'The catalog will not invent host findings. This row exists so coverage gaps are visible.',
        exec: 'This OT host is in scope, but host engines stay empty until the agent is enrolled. That is labelled, not faked.',
      },
    },
  },
} as const
