import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import { ENGINES_REGISTRY } from './enginesRegistry'
import {
  PLATFORM_RELEASE,
  PLATFORM_RELEASE_NAME,
  PRODUCTION_ENGINE_COUNT,
} from './platformScale'
import en from '../i18n/locales/en.json'
import he from '../i18n/locales/he.json'

const here = dirname(fileURLToPath(import.meta.url))
const changelog = readFileSync(resolve(here, '../../CHANGELOG.md'), 'utf8')
const loginSrc = readFileSync(resolve(here, '../components/cockpit/Login.jsx'), 'utf8')
const routeChunksSrc = readFileSync(resolve(here, '../routing/routeChunks.js'), 'utf8')

/**
 * Guard: the engine count shown before login must equal the real catalog.
 *
 * The login brand panel advertised "254 engines" long after the registry passed 500 — nothing tied
 * the copy to the catalog, so the headline number for the whole platform silently rotted. This test
 * is that tie. `scripts/verify_engine_wiring.mjs` separately holds the registry equal to the
 * backend's `PRODUCTION_ENGINE_IDS`, so pinning to the registry pins to production dispatch.
 */
describe('platform scale constants', () => {
  it('matches the engines registry length exactly', () => {
    expect(PRODUCTION_ENGINE_COUNT).toBe(ENGINES_REGISTRY.length)
  })

  it('counts unique engine ids, not duplicated registry rows', () => {
    const uniqueIds = new Set(ENGINES_REGISTRY.map((engine) => engine.id))
    expect(uniqueIds.size).toBe(PRODUCTION_ENGINE_COUNT)
  })

  it('matches the current CalVer heading in CHANGELOG.md', () => {
    expect(changelog).toContain(`## [${PLATFORM_RELEASE}] — ${PLATFORM_RELEASE_NAME}`)
  })
})

describe('login copy cannot advertise a stale engine count', () => {
  it.each([
    ['en', en],
    ['he', he],
  ])('%s interpolates {{engines}} and never hardcodes 254', (_locale, catalog) => {
    expect(catalog.auth.brand_story).toContain('{{engines}}')
    expect(catalog.auth.trust_engines).toContain('{{engines}}')
    expect(catalog.auth.brand_story).not.toMatch(/\b254\b/)
    expect(catalog.auth.trust_engines).not.toMatch(/\b254\b/)
    expect(catalog.auth.brand_release).toContain('{{release}}')
  })
})

describe('Command Center login is a single live surface', () => {
  it('interpolates the catalog count and release, and never hardcodes 254', () => {
    expect(loginSrc).toContain('PRODUCTION_ENGINE_COUNT')
    expect(loginSrc).toContain('PLATFORM_RELEASE')
    expect(loginSrc).toContain('PLATFORM_RELEASE_NAME')
    expect(loginSrc).toContain('CyberLiveBackdrop')
    expect(loginSrc).not.toMatch(/\b254\b/)
  })

  it('is the only login page the SPA can route to', () => {
    expect(routeChunksSrc).toMatch(
      /export const Login = React\$lazy\(\(\) => import\([^)]*components\/cockpit\/Login/,
    )
    expect(routeChunksSrc.match(/cockpit\/Login/g)?.length).toBe(1)
    expect(routeChunksSrc).not.toMatch(/LoginLegacy|OldLogin|login-legacy/i)
  })
})
