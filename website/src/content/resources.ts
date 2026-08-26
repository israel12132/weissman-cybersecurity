export type ResourceType =
  | 'product'
  | 'research'
  | 'technical'
  | 'policy'
  | 'demo'
  | 'legal'

export type Resource = {
  id: string
  type: ResourceType
  title: string
  summary: string
  href: string
  date?: string
}

export const resourceTypes: { id: ResourceType | 'all'; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'product', label: 'Product' },
  { id: 'research', label: 'Research' },
  { id: 'technical', label: 'Technical' },
  { id: 'policy', label: 'Policy' },
  { id: 'demo', label: 'Demo' },
  { id: 'legal', label: 'Legal' },
]

export const resources: Resource[] = [
  {
    id: 'release-2026-06-2',
    type: 'product',
    title: 'Liminal Boundary Engine — 2026.06.2',
    summary: 'Current CalVer release of the Weissman platform.',
    href: '/platform/',
    date: '2026-06-02',
  },
  {
    id: 'mitre-coverage',
    type: 'research',
    title: 'ATT&CK coverage against v19.1',
    summary: '226 techniques: 192 primary mappings plus 34 code-grounded secondary tags.',
    href: '/platform/vulnerability-research/',
  },
  {
    id: 'engine-integrity',
    type: 'technical',
    title: 'Engine integrity accounting',
    summary: '563 IDs classified as live probe, alias, or agent-required — CI-gated, no silent catalog entries.',
    href: '/technology/',
  },
  {
    id: 'platform-overview',
    type: 'technical',
    title: 'Platform technical overview',
    summary: 'Observe, analyse, validate, respond — how the orchestrator and Command Center fit.',
    href: '/technology/',
  },
  {
    id: 'disclosure',
    type: 'policy',
    title: 'Responsible disclosure',
    summary: 'How to report a vulnerability. No monetary bounty today; we credit in the changelog with consent.',
    href: '/security-policy.html',
  },
  {
    id: 'book-demo',
    type: 'demo',
    title: 'Book a demo',
    summary: 'Walk the Command Center with the Weissman team.',
    href: '/contact/',
  },
  {
    id: 'api-docs',
    type: 'technical',
    title: 'OpenAPI 3.1 reference',
    summary: 'Interactive docs for the control-plane API.',
    href: '/api/docs/',
  },
  {
    id: 'status',
    type: 'product',
    title: 'Public status',
    summary: 'Live health for the Cloud service.',
    href: '/status',
  },
  {
    id: 'terms',
    type: 'legal',
    title: 'Terms of Service',
    summary: 'Contract terms for Cloud and self-hosted use.',
    href: '/terms.html',
    date: '2026-06-03',
  },
  {
    id: 'privacy',
    type: 'legal',
    title: 'Privacy Policy',
    summary: 'What we collect, what we refuse to collect, and how to reach the DPO.',
    href: '/privacy.html',
    date: '2026-06-03',
  },
  {
    id: 'dpa',
    type: 'legal',
    title: 'Data Processing Addendum',
    summary: 'Processor terms including EU SCCs Module 2.',
    href: '/dpa.html',
    date: '2026-06-03',
  },
  {
    id: 'subprocessors',
    type: 'legal',
    title: 'Sub-processors',
    summary: 'Infrastructure, email, payments, and outbound intel feeds.',
    href: '/subprocessors.html',
    date: '2026-06-09',
  },
]

export const featuredRail = [
  resources[0],
  resources[1],
  resources[2],
  resources[4],
  resources[5],
  resources[3],
]
