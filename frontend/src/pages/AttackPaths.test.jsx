import { describe, it, expect } from 'vitest'
import en from '../i18n/locales/en.json'
import he from '../i18n/locales/he.json'
import {
  crownJewelFlagsBody,
  crownJewelFlagsPath,
  parseAttackPathsPayload,
} from './attackPathsModel.js'

describe('parseAttackPathsPayload', () => {
  it('surfaces zero_jewel candidates so operators can PATCH a crown jewel', () => {
    const parsed = parseAttackPathsPayload({
      ok: true,
      zero_jewel: true,
      candidate_jewels: [{ id: 42, label: 'prod-vault' }],
      snapshot: { jewel_count: 0, paths: [] },
    })
    expect(parsed.zeroJewel).toBe(true)
    expect(parsed.hasSnapshot).toBe(true)
    expect(parsed.candidateJewels).toEqual([{ id: 42, label: 'prod-vault' }])
    expect(crownJewelFlagsPath(42)).toBe('/api/risk-graph/nodes/42/flags')
    expect(crownJewelFlagsBody()).toEqual({ crown_jewel: true })
  })

  it('does not treat a jewel-bearing snapshot as empty', () => {
    const parsed = parseAttackPathsPayload({
      ok: true,
      zero_jewel: false,
      candidate_jewels: [],
      snapshot: { jewel_count: 2, paths: [{ hops: 2 }] },
    })
    expect(parsed.zeroJewel).toBe(false)
    expect(parsed.candidateJewels).toEqual([])
  })

  it('treats a missing snapshot as zero-jewel with live candidates', () => {
    const parsed = parseAttackPathsPayload({
      ok: true,
      snapshot: null,
      zero_jewel: true,
      candidate_jewels: [{ id: 9, label: 'ad-dc01' }],
    })
    expect(parsed.hasSnapshot).toBe(false)
    expect(parsed.zeroJewel).toBe(true)
    expect(parsed.candidateJewels[0].label).toBe('ad-dc01')
  })
})

describe('attack-path algorithm copy', () => {
  it('labels Dijkstra in the badge and evidence, not BFS', () => {
    expect(en.pages.attackPaths.badge).toBe('Dijkstra')
    expect(he.pages.attackPaths.badge).toBe('דייקסטרה')
    expect(en.pages.attackPaths.evidence_notice).toMatch(/Dijkstra/)
    expect(he.pages.attackPaths.evidence_notice).toMatch(/דייקסטרה/)
    expect(en.pages.attackPaths.no_paths_body).not.toMatch(/Tag a crown jewel/)
    expect(he.pages.attackPaths.no_paths_body).not.toMatch(/סמן נכס כתר/)
  })
})
