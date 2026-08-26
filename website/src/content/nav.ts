export type NavLink = { label: string; href: string; description?: string }

export type MegaColumn = {
  heading: string
  links: NavLink[]
}

export type NavItem = {
  id: string
  label: string
  href: string
  mega?: MegaColumn[]
}

export const mainNav: NavItem[] = [
  {
    id: 'products',
    label: 'Products',
    href: '/platform/',
    mega: [
      {
        heading: 'Platform',
        links: [
          { label: 'Platform overview', href: '/platform/', description: 'How the pieces connect' },
          { label: 'Command Center', href: '/platform/security-operations/', description: 'SOC workspace and live events' },
          { label: 'How it works', href: '/technology/', description: 'Observe → validate → respond' },
        ],
      },
      {
        heading: 'Capabilities',
        links: [
          { label: 'Endpoint protection', href: '/platform/endpoint-protection/', description: 'Agent detections and UEBA' },
          { label: 'Vulnerability research', href: '/platform/vulnerability-research/', description: 'Live probes across domains' },
          { label: 'Detection and response', href: '/platform/detection-response/', description: 'Triage, SOAR, signed PRs' },
          { label: 'Attack-path intelligence', href: '/platform/attack-path-intelligence/', description: 'Crown-jewel paths and choke-points' },
          { label: 'Private AI', href: '/platform/private-ai/', description: 'BYO models, Ask Weissman' },
          { label: 'OAST validation', href: '/platform/oast-validation/', description: 'Blind callbacks, proven' },
        ],
      },
    ],
  },
  {
    id: 'solutions',
    label: 'Solutions',
    href: '/solutions/',
    mega: [
      {
        heading: 'By audience',
        links: [
          { label: 'CISOs', href: '/solutions/#ciso', description: 'Risk, mapping, governance' },
          { label: 'SOC teams', href: '/solutions/#soc', description: 'Triage and playbooks' },
          { label: 'Researchers', href: '/solutions/#research', description: 'Coverage you can audit' },
          { label: 'IT and infrastructure', href: '/solutions/#infra', description: 'Scope, SSO, self-host' },
          { label: 'Sensitive data', href: '/solutions/#sensitive', description: 'Your VPC, your model' },
        ],
      },
    ],
  },
  {
    id: 'technology',
    label: 'Technology',
    href: '/technology/',
    mega: [
      {
        heading: 'Architecture',
        links: [
          { label: 'How it works', href: '/technology/', description: 'Four-stage loop' },
          { label: 'Engine integrity', href: '/platform/vulnerability-research/', description: 'Wiring gate, no silent IDs' },
          { label: 'Private inference', href: '/platform/private-ai/', description: 'vLLM, Ollama, allow-listed SQL' },
        ],
      },
    ],
  },
  {
    id: 'resources',
    label: 'Resources',
    href: '/resources/',
    mega: [
      {
        heading: 'Library',
        links: [
          { label: 'All resources', href: '/resources/', description: 'Filter by type' },
          { label: 'Responsible disclosure', href: '/security-policy.html', description: 'Report a vulnerability' },
          { label: 'API reference', href: '/api/docs/', description: 'OpenAPI 3.1' },
          { label: 'System status', href: '/status', description: 'Public health' },
        ],
      },
    ],
  },
  {
    id: 'company',
    label: 'Company',
    href: '/about/',
    mega: [
      {
        heading: 'Weissman',
        links: [
          { label: 'About', href: '/about/', description: 'Who we are' },
          { label: 'Contact', href: '/contact/', description: 'Demo and sales' },
          { label: 'Pricing', href: '/pricing.html', description: 'Self-hosted, Cloud, Enterprise' },
          { label: 'Legal', href: '/terms.html', description: 'Terms, privacy, DPA' },
        ],
      },
    ],
  },
]

export const footerNav = {
  product: [
    { label: 'Platform', href: '/platform/' },
    { label: 'Endpoint protection', href: '/platform/endpoint-protection/' },
    { label: 'Vulnerability research', href: '/platform/vulnerability-research/' },
    { label: 'Detection and response', href: '/platform/detection-response/' },
    { label: 'Attack-path intelligence', href: '/platform/attack-path-intelligence/' },
    { label: 'Private AI', href: '/platform/private-ai/' },
    { label: 'OAST validation', href: '/platform/oast-validation/' },
    { label: 'Security operations', href: '/platform/security-operations/' },
    { label: 'Pricing', href: '/pricing.html' },
  ],
  company: [
    { label: 'About', href: '/about/' },
    { label: 'Contact', href: '/contact/' },
    { label: 'Sign in', href: '/command-center/login' },
    { label: 'Create workspace', href: '/signup.html' },
    { label: 'System status', href: '/status' },
  ],
  resources: [
    { label: 'Resource library', href: '/resources/' },
    { label: 'Technology', href: '/technology/' },
    { label: 'Solutions', href: '/solutions/' },
    { label: 'API docs', href: '/api/docs/' },
    { label: 'security.txt', href: '/.well-known/security.txt' },
  ],
  legal: [
    { label: 'Terms', href: '/terms.html' },
    { label: 'תנאים', href: '/terms-he.html' },
    { label: 'Privacy', href: '/privacy.html' },
    { label: 'פרטיות', href: '/privacy-he.html' },
    { label: 'DPA', href: '/dpa.html' },
    { label: 'Sub-processors', href: '/subprocessors.html' },
    { label: 'Responsible disclosure', href: '/security-policy.html' },
  ],
}

export const homeSectionNav = [
  { id: 'why-us', label: 'Why us' },
  { id: 'platform', label: 'Platform' },
  { id: 'capabilities', label: 'Capabilities' },
  { id: 'how-it-works', label: 'How it works' },
  { id: 'proof', label: 'Proof' },
  { id: 'resources', label: 'Resources' },
  { id: 'contact', label: 'Contact' },
] as const
