export const company = {
  legalName: 'Weissman Cybersecurity Ltd.',
  shortName: 'Weissman',
  domain: 'weissman.io',
  origin: 'https://weissman.io',
  emails: {
    sales: 'weissmancybersecurity@gmail.com',
    security: 'security@weissman.io',
    dpo: 'dpo@weissman.io',
    legal: 'legal@weissman.io',
    support: 'support@weissman.io',
  },
  github: 'https://github.com/israel12132/weissman-cybersecurity',
  companyIdIsrael: '[COMPANY_ID_ISRAEL]',
}

export const announcement = {
  id: '2026.06.2-liminal-boundary',
  href: '/resources/',
}

export const threatStoryIds = ['01', '02', '03'] as const
export const howItWorksIds = ['observe', 'analyse', 'validate', 'respond'] as const
export const capabilityIds = ['probes', 'evidence', 'paths', 'host', 'models', 'ops'] as const
export const capabilityHrefs: Record<(typeof capabilityIds)[number], string> = {
  probes: '/platform/vulnerability-research/',
  evidence: '/platform/oast-validation/',
  paths: '/platform/attack-path-intelligence/',
  host: '/platform/endpoint-protection/',
  models: '/platform/private-ai/',
  ops: '/platform/security-operations/',
}
export const solutionIds = ['ciso', 'soc', 'research', 'infra', 'sensitive'] as const
export const proofIds = ['integrity', 'isolation', 'autonomy', 'ourselves'] as const
/** The live Command Center sign-in. Do not point this at a marketing copy of login. */
export const CUSTOMER_LOGIN_HREF = '/command-center/login'
