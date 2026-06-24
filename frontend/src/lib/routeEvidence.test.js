import { describe, it, expect } from 'vitest'
import {
  resolveRouteEvidence,
  ROUTE_EVIDENCE,
  ROUTE_EVIDENCE_SKIP,
  ROUTE_EVIDENCE_SKIP_PREFIX,
} from './routeEvidence'

const t = (key, opts = {}) => {
  if (opts.defaultValue !== undefined && opts.defaultValue !== '') return opts.defaultValue
  const catalog = {
    'clients_page.evidence_notice': 'Clients live API evidence',
    'pages.jwtAttackLab.evidence_notice': 'JWT lab live API evidence',
    'pages.engineDetail.evidence_notice': 'Engine detail evidence',
    'pages.clientDetail.evidence_notice': 'Client detail evidence',
  }
  return catalog[key] ?? key
}

describe('resolveRouteEvidence', () => {
  it('returns translated evidence for exact mapped routes', () => {
    expect(resolveRouteEvidence('/clients', t)).toBe('Clients live API evidence')
    expect(resolveRouteEvidence('/jwt-lab', t)).toBe('JWT lab live API evidence')
  })

  it('normalizes trailing slashes', () => {
    expect(resolveRouteEvidence('/clients/', t)).toBe('Clients live API evidence')
  })

  it('returns null for skip-listed routes with inline evidence', () => {
    for (const path of ['/billing', '/findings', '/metrics', '/jobs', '/ask']) {
      expect(resolveRouteEvidence(path, t)).toBeNull()
    }
  })

  it('returns null for skip-prefix dynamic routes', () => {
    expect(resolveRouteEvidence('/engines/top-tier/jwt_attack', t)).toBeNull()
    expect(resolveRouteEvidence('/engines/business/foo', t)).toBeNull()
  })

  it('resolves longest prefix for dynamic client and engine routes', () => {
    expect(resolveRouteEvidence('/clients/acme-corp-42', t)).toBe('Client detail evidence')
    expect(resolveRouteEvidence('/engines/jwt_attack', t)).toBe('Engine detail evidence')
    expect(resolveRouteEvidence('/digital-twin/7', t)).toBeNull()
  })

  it('returns null when i18n key is missing (untranslated key echoed back)', () => {
    expect(resolveRouteEvidence('/zero-day-radar', t)).toBeNull()
  })

  it('returns null for unknown routes', () => {
    expect(resolveRouteEvidence('/does-not-exist', t)).toBeNull()
  })
})

describe('route evidence registry', () => {
  it('maps primary engine command centers', () => {
    expect(ROUTE_EVIDENCE['/iac-security']).toBe('pages.iacSecurityCenter.evidence_notice')
    expect(ROUTE_EVIDENCE['/graphql-security']).toBe('pages.graphqlSecurityCommandCenter.evidence_notice')
    expect(ROUTE_EVIDENCE['/attack-surface']).toBe('pages.attackSurfaceManagement.evidence_notice')
  })

  it('does not duplicate skip entries in exact map', () => {
    for (const path of ROUTE_EVIDENCE_SKIP) {
      expect(ROUTE_EVIDENCE[path]).toBeUndefined()
    }
  })

  it('skip-prefix entries are non-empty strings', () => {
    expect(ROUTE_EVIDENCE_SKIP_PREFIX.every((p) => p.startsWith('/'))).toBe(true)
  })
})
