/** Shared page table for HTML shells, sitemap, and robots. */
export const ORIGIN = 'https://weissman.io'

export const pages = [
  {
    id: 'home',
    file: 'index.html',
    path: '/',
    title: 'Weissman Cybersecurity — Live evidence. Clearer response.',
    description:
      'Weissman continuously probes authorised attack surfaces with 563 production engines, verifies findings with live evidence, and helps SOC teams prioritise and respond.',
  },
  {
    id: 'platform',
    file: 'platform/index.html',
    path: '/platform/',
    title: 'Platform — Weissman Cybersecurity',
    description:
      'One platform for live probing, attack-path intelligence, endpoint telemetry, private AI, OAST validation, and SOC operations.',
  },
  {
    id: 'endpoint-protection',
    file: 'platform/endpoint-protection/index.html',
    path: '/platform/endpoint-protection/',
    title: 'Endpoint Protection — Weissman Cybersecurity',
    description:
      'Cross-platform Weissman agent with on-host detections and UEBA baselines for Linux, macOS, and Windows.',
  },
  {
    id: 'vulnerability-research',
    file: 'platform/vulnerability-research/index.html',
    path: '/platform/vulnerability-research/',
    title: 'Vulnerability Research — Weissman Cybersecurity',
    description:
      '303 live probes across web, cloud, OT, identity, and supply chain — every finding from a real network or host check.',
  },
  {
    id: 'detection-response',
    file: 'platform/detection-response/index.html',
    path: '/platform/detection-response/',
    title: 'Detection and Response — Weissman Cybersecurity',
    description:
      'Deduplicated findings, KEV/EPSS enrichment, SOAR playbooks, and signed-PR remediation with sandbox verification.',
  },
  {
    id: 'attack-path-intelligence',
    file: 'platform/attack-path-intelligence/index.html',
    path: '/platform/attack-path-intelligence/',
    title: 'Attack-Path Intelligence — Weissman Cybersecurity',
    description:
      'Graph-based paths from internet-exposed assets to crown jewels, with choke-point analysis and FAIR-aligned loss estimates.',
  },
  {
    id: 'private-ai',
    file: 'platform/private-ai/index.html',
    path: '/platform/private-ai/',
    title: 'Private AI — Weissman Cybersecurity',
    description:
      'Bring your own vLLM, Ollama, or OpenAI-compatible model. Ask Weissman compiles natural language to allow-listed SQL on a read-only role.',
  },
  {
    id: 'security-operations',
    file: 'platform/security-operations/index.html',
    path: '/platform/security-operations/',
    title: 'Security Operations — Weissman Cybersecurity',
    description:
      'Command Center for live events, findings, playbooks, agents, and Ask Weissman — 130 operational routes for SOC teams.',
  },
  {
    id: 'oast-validation',
    file: 'platform/oast-validation/index.html',
    path: '/platform/oast-validation/',
    title: 'OAST Validation — Weissman Cybersecurity',
    description:
      'HTTP and DNS out-of-band listeners confirm blind SSRF, XXE, and callback classes before a finding is marked verified.',
  },
  {
    id: 'solutions',
    file: 'solutions/index.html',
    path: '/solutions/',
    title: 'Solutions — Weissman Cybersecurity',
    description:
      'How CISOs, SOC teams, researchers, and infrastructure owners use Weissman to see, validate, and act on real risk.',
  },
  {
    id: 'technology',
    file: 'technology/index.html',
    path: '/technology/',
    title: 'Technology — Weissman Cybersecurity',
    description:
      'Observe, analyse, validate, and respond: how Weissman turns live probes into prioritised action.',
  },
  {
    id: 'resources',
    file: 'resources/index.html',
    path: '/resources/',
    title: 'Resources — Weissman Cybersecurity',
    description:
      'Technical overviews, responsible disclosure, legal documents, and platform references from Weissman Cybersecurity.',
  },
  {
    id: 'about',
    file: 'about/index.html',
    path: '/about/',
    title: 'About — Weissman Cybersecurity',
    description:
      'Weissman Cybersecurity Ltd., Tel Aviv-Yafo. An autonomous offensive-security and active-defence platform built in Rust.',
  },
  {
    id: 'contact',
    file: 'contact/index.html',
    path: '/contact/',
    title: 'Book a Demo — Weissman Cybersecurity',
    description: 'Request a Weissman demo or speak with the team about deploying the platform in your environment.',
  },
  {
    id: 'pricing',
    file: 'pricing.html',
    path: '/pricing.html',
    title: 'Services — Weissman Cybersecurity',
    description:
      'Weissman is not sold as packaged website tiers. Contact us to scope the platform for your organisation. Existing customers sign in to Command Center.',
  },
  {
    id: 'signup',
    file: 'signup.html',
    path: '/signup.html',
    title: 'Request access — Weissman Cybersecurity',
    description: 'Contact Weissman to request platform access. Existing customers sign in to Command Center.',
  },
  {
    id: 'terms',
    file: 'terms.html',
    path: '/terms.html',
    title: 'Terms of Service — Weissman Cybersecurity',
    description: 'Terms of Service for the Weissman Cybersecurity platform.',
  },
  {
    id: 'privacy',
    file: 'privacy.html',
    path: '/privacy.html',
    title: 'Privacy Policy — Weissman Cybersecurity',
    description: 'Privacy Policy for Weissman Cybersecurity Ltd. GDPR and CCPA aligned.',
  },
  {
    id: 'terms-he',
    file: 'terms-he.html',
    path: '/terms-he.html',
    title: 'תנאי שימוש — Weissman Cybersecurity',
    description: 'תנאי שימוש לפלטפורמת Weissman Cybersecurity.',
    lang: 'he',
    dir: 'rtl',
  },
  {
    id: 'privacy-he',
    file: 'privacy-he.html',
    path: '/privacy-he.html',
    title: 'מדיניות פרטיות — Weissman Cybersecurity',
    description: 'מדיניות פרטיות של Weissman Cybersecurity Ltd.',
    lang: 'he',
    dir: 'rtl',
  },
  {
    id: 'dpa',
    file: 'dpa.html',
    path: '/dpa.html',
    title: 'Data Processing Addendum — Weissman Cybersecurity',
    description: 'Data Processing Addendum incorporating EU SCCs (2021/914).',
  },
  {
    id: 'subprocessors',
    file: 'subprocessors.html',
    path: '/subprocessors.html',
    title: 'Subprocessors — Weissman Cybersecurity',
    description: 'Current Cloud SaaS sub-processors and threat-intelligence data sources.',
  },
  {
    id: 'security-policy',
    file: 'security-policy.html',
    path: '/security-policy.html',
    title: 'Responsible Disclosure — Weissman Cybersecurity',
    description: 'How to report a vulnerability to Weissman Cybersecurity.',
  },
  {
    id: 'not-found',
    file: '404.html',
    path: '/404.html',
    title: 'Page not found — Weissman Cybersecurity',
    description: 'The page you requested is not part of the Weissman public site.',
    robots: 'noindex,follow',
  },
]
