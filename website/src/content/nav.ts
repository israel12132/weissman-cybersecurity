export type NavLink = { id: string; href: string }

export type MegaColumn = {
  id: string
  links: NavLink[]
}

export type NavItem = {
  id: 'products' | 'solutions' | 'technology' | 'resources' | 'company'
  href: string
  mega?: MegaColumn[]
}

export const mainNav: NavItem[] = [
  {
    id: 'products',
    href: '/platform/',
    mega: [
      {
        id: 'platform',
        links: [
          { id: 'overview', href: '/platform/' },
          { id: 'commandCenter', href: '/platform/security-operations/' },
          { id: 'howItWorks', href: '/technology/' },
        ],
      },
      {
        id: 'capabilities',
        links: [
          { id: 'endpoint', href: '/platform/endpoint-protection/' },
          { id: 'research', href: '/platform/vulnerability-research/' },
          { id: 'detect', href: '/platform/detection-response/' },
          { id: 'paths', href: '/platform/attack-path-intelligence/' },
          { id: 'privateAi', href: '/platform/private-ai/' },
          { id: 'oast', href: '/platform/oast-validation/' },
        ],
      },
    ],
  },
  {
    id: 'solutions',
    href: '/solutions/',
    mega: [
      {
        id: 'audience',
        links: [
          { id: 'ciso', href: '/solutions/#ciso' },
          { id: 'soc', href: '/solutions/#soc' },
          { id: 'research', href: '/solutions/#research' },
          { id: 'infra', href: '/solutions/#infra' },
          { id: 'sensitive', href: '/solutions/#sensitive' },
        ],
      },
    ],
  },
  {
    id: 'technology',
    href: '/technology/',
    mega: [
      {
        id: 'architecture',
        links: [
          { id: 'how', href: '/technology/' },
          { id: 'integrity', href: '/platform/vulnerability-research/' },
          { id: 'inference', href: '/platform/private-ai/' },
        ],
      },
    ],
  },
  {
    id: 'resources',
    href: '/resources/',
    mega: [
      {
        id: 'library',
        links: [
          { id: 'all', href: '/resources/' },
          { id: 'disclosure', href: '/security-policy.html' },
          { id: 'api', href: '/api/docs/' },
          { id: 'status', href: '/status' },
        ],
      },
    ],
  },
  {
    id: 'company',
    href: '/about/',
    mega: [
      {
        id: 'weissman',
        links: [
          { id: 'about', href: '/about/' },
          { id: 'contact', href: '/contact/' },
          { id: 'pricing', href: '/pricing.html' },
          { id: 'legal', href: '/terms.html' },
        ],
      },
    ],
  },
]

export const footerNav = {
  product: [
    { id: 'platform', href: '/platform/' },
    { id: 'endpoint', href: '/platform/endpoint-protection/' },
    { id: 'research', href: '/platform/vulnerability-research/' },
    { id: 'detect', href: '/platform/detection-response/' },
    { id: 'paths', href: '/platform/attack-path-intelligence/' },
    { id: 'privateAi', href: '/platform/private-ai/' },
    { id: 'oast', href: '/platform/oast-validation/' },
    { id: 'operations', href: '/platform/security-operations/' },
    { id: 'pricing', href: '/pricing.html' },
  ],
  company: [
    { id: 'about', href: '/about/' },
    { id: 'contact', href: '/contact/' },
    { id: 'signIn', href: '/command-center/login' },
    { id: 'signup', href: '/signup.html' },
    { id: 'status', href: '/status' },
  ],
  resources: [
    { id: 'library', href: '/resources/' },
    { id: 'technology', href: '/technology/' },
    { id: 'solutions', href: '/solutions/' },
    { id: 'api', href: '/api/docs/' },
    { id: 'securityTxt', href: '/.well-known/security.txt' },
  ],
  legal: [
    { id: 'terms', href: '/terms.html' },
    { id: 'privacy', href: '/privacy.html' },
    { id: 'dpa', href: '/dpa.html' },
    { id: 'subprocessors', href: '/subprocessors.html' },
    { id: 'disclosure', href: '/security-policy.html' },
  ],
}

export const homeSectionNav = [
  'why-us',
  'platform',
  'capabilities',
  'how-it-works',
  'proof',
  'resources',
  'contact',
] as const
