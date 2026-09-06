import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import { PRODUCTION_ENGINE_COUNT } from '../lib/platformScale'
import { ENGINES_REGISTRY } from '../lib/enginesRegistry'

const here = dirname(fileURLToPath(import.meta.url))
const read = (rel) => readFileSync(resolve(here, rel), 'utf8')

const tacticalApp = read('../TacticalApp.jsx')
const routeChunks = read('./routeChunks.js')
const mainBoot = read('../main.jsx')
const loginSrc = read('../components/cockpit/Login.jsx')
const authContext = read('../context/AuthContext.jsx')
const apiBase = read('../lib/apiBase.js')
const protectedRoute = read('../components/cockpit/ProtectedRoute.jsx')
const requireRole = read('../components/auth/RequireRole.jsx')
const ceoProtected = read('../components/ceo/CeoProtectedRoute.jsx')
const appNav = read('../lib/appNav.js')

/**
 * The retired sign-in (CSS mesh + hardcoded 254 engines) must not remain as a second
 * route, import, or toggle. Unauthenticated traffic has one destination: cockpit Login
 * with CyberLiveBackdrop, whose engine count is pinned to the production catalog.
 */
describe('single Command Center login surface', () => {
  it('lazy-loads only components/cockpit/Login', () => {
    expect(routeChunks).toMatch(
      /export const Login = React\$lazy\(\(\) => import\([^)]*components\/cockpit\/Login/,
    )
    expect(routeChunks.match(/cockpit\/Login/g)?.length).toBe(1)
    expect(routeChunks).not.toMatch(/LoginLegacy|OldLogin|AuthScreen|LoginPage|login-legacy/i)
  })

  it('registers a single public login route and no dual-login toggle', () => {
    const loginRoutes = [...tacticalApp.matchAll(/path=["']([^"']*login[^"']*)["']/gi)].map(
      (m) => m[1],
    )
    expect(loginRoutes).toEqual(['login'])
    expect(tacticalApp).not.toMatch(/path=["']signin["']/)
    expect(tacticalApp).not.toMatch(/path=["']auth["']/)
    expect(tacticalApp).not.toMatch(/path=["']sign-in["']/)
    expect(tacticalApp).not.toMatch(/legacy.?login|LoginToggle|useLegacyLogin/i)
    expect(tacticalApp).toMatch(/<Login\s*\/>/)
  })

  it('boots the SPA under /command-center so /login is /command-center/login', () => {
    expect(mainBoot).toContain('basename="/command-center"')
    expect(mainBoot).toContain('TacticalApp')
  })

  it('sends 401/unauthenticated UI traffic to /login, not a retired path', () => {
    expect(protectedRoute).toContain('to="/login"')
    expect(protectedRoute).not.toMatch(/to=["']\/signin["']/)
    expect(requireRole).toContain("navigate('/login'")
    expect(requireRole).toContain('to="/login"')
    expect(ceoProtected).toContain('to="/login"')
    expect(ceoProtected).toContain("navigate('/login'")
  })

  it('authenticates against POST /api/login (never /api/auth/login)', () => {
    expect(authContext).toContain("apiUrl('/api/login')")
    expect(authContext).not.toMatch(/\/api\/auth\/login/)
    expect(apiBase).toContain('/api/login')
  })

  it('does not advertise a second login in app nav', () => {
    expect(appNav).not.toMatch(/LoginLegacy|legacy.?login|\/signin|AuthScreen/i)
  })

  it('keeps the live backdrop and catalog engine count on the remaining login', () => {
    expect(loginSrc).toContain('CyberLiveBackdrop')
    expect(loginSrc).toContain('PRODUCTION_ENGINE_COUNT')
    expect(loginSrc).not.toMatch(/auth-mesh-drift/)
    expect(loginSrc).not.toMatch(/\b254\b/)
    expect(PRODUCTION_ENGINE_COUNT).toBe(573)
    expect(ENGINES_REGISTRY.length).toBe(PRODUCTION_ENGINE_COUNT)
  })
})
