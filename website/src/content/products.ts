export type ProductAccent = 'accent' | 'risk' | 'ops'

export type Product = {
  id:
    | 'endpoint-protection'
    | 'vulnerability-research'
    | 'detection-response'
    | 'attack-path-intelligence'
    | 'private-ai'
    | 'security-operations'
    | 'oast-validation'
  href: string
  accent: ProductAccent
}

export const products: Product[] = [
  { id: 'endpoint-protection', href: '/platform/endpoint-protection/', accent: 'ops' },
  { id: 'vulnerability-research', href: '/platform/vulnerability-research/', accent: 'risk' },
  { id: 'detection-response', href: '/platform/detection-response/', accent: 'ops' },
  { id: 'attack-path-intelligence', href: '/platform/attack-path-intelligence/', accent: 'risk' },
  { id: 'private-ai', href: '/platform/private-ai/', accent: 'accent' },
  { id: 'security-operations', href: '/platform/security-operations/', accent: 'accent' },
  { id: 'oast-validation', href: '/platform/oast-validation/', accent: 'risk' },
]

export const platformTabs = products
