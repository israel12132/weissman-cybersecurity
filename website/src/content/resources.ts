export type ResourceType = 'product' | 'research' | 'technical' | 'policy' | 'demo' | 'legal'

export type Resource = {
  id: string
  type: ResourceType
  href: string
  date?: string
}

export const resourceTypeIds: Array<ResourceType | 'all'> = [
  'all',
  'product',
  'research',
  'technical',
  'policy',
  'demo',
  'legal',
]

export const resources: Resource[] = [
  { id: 'release-2026-06-2', type: 'product', href: '/platform/', date: '2026-06-02' },
  { id: 'mitre-coverage', type: 'research', href: '/platform/vulnerability-research/' },
  { id: 'engine-integrity', type: 'technical', href: '/technology/' },
  { id: 'platform-overview', type: 'technical', href: '/technology/' },
  { id: 'disclosure', type: 'policy', href: '/security-policy.html' },
  { id: 'book-demo', type: 'demo', href: '/contact/' },
  { id: 'api-docs', type: 'technical', href: '/api/docs/' },
  { id: 'status', type: 'product', href: '/status' },
  { id: 'terms', type: 'legal', href: '/terms.html', date: '2026-06-03' },
  { id: 'privacy', type: 'legal', href: '/privacy.html', date: '2026-06-03' },
  { id: 'dpa', type: 'legal', href: '/dpa.html', date: '2026-06-03' },
  { id: 'subprocessors', type: 'legal', href: '/subprocessors.html', date: '2026-06-09' },
]

export const featuredRail = [
  resources[0],
  resources[1],
  resources[2],
  resources[4],
  resources[5],
  resources[3],
]
