/**
 * Platform scale figures for pre-authentication copy.
 *
 * The login screen quotes the size of the engine fleet, and neither live source is reachable there:
 * `/api/engines/production` needs a JWT, and `enginesRegistry.js` is a 200KB+ catalog deliberately
 * kept out of the boot shell (see enginesRegistryLoader.js). So the number is a constant — and
 * `platformScale.test.js` fails the build if it ever stops matching `ENGINES_REGISTRY.length`, which
 * `scripts/verify_engine_wiring.mjs` in turn holds equal to the backend's `PRODUCTION_ENGINE_IDS`.
 * That chain is what keeps this honest; do not edit the value without running those.
 */
export const PRODUCTION_ENGINE_COUNT = 564

/** Current CalVer release shown on pre-auth surfaces. Keep in lockstep with CHANGELOG.md. */
export const PLATFORM_RELEASE = '2026.06.2'
export const PLATFORM_RELEASE_NAME = 'Liminal Boundary Engine'
