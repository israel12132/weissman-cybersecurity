import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Unit/component tests (jsdom). Playwright e2e specs live in tests-e2e/ and are run
// separately via `npm run test:e2e`, so they're excluded here.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./src/test/setup.js'],
    include: ['src/**/*.{test,spec}.{js,jsx}'],
    exclude: ['node_modules', 'dist', 'tests-e2e'],
    css: false,
    coverage: {
      provider: 'v8',
      // Critical-path modules with deterministic unit coverage (auditor evidence).
      include: [
        'src/lib/clientTarget.js',
        'src/lib/pdfExport.js',
        'src/lib/stableGeoFromLabel.js',
        'src/lib/realityKindMeta.js',
        'src/lib/engineGroupDefs.js',
        'src/lib/enginesRegistryLoader.js',
        'src/lib/engineParamDefsLoader.js',
        'src/lib/engineParamDefsExplicit.js',
        'src/lib/engineParamDefsGroups.js',
        'src/lib/strategicEngineProgram.js',
        'src/lib/topTierEngineProfiles.js',
        'src/lib/engineIntegrationReadiness.js',
        'src/lib/routeEvidence.js',
        'src/lib/sanitizeFinding.js',
        'src/lib/exportFindingsCsv.js',
        'src/lib/appNav.js',
        'src/lib/enginesRegistry.js',
        'src/battlespace/commanderIntent.js',
        'src/hooks/useFindingsWorkbench.js',
      ],
      exclude: ['**/*.test.{js,jsx}', '**/*.spec.{js,jsx}', 'src/test/**'],
      thresholds: {
        lines: 60,
        functions: 60,
        branches: 55,
        statements: 60,
      },
    },
  },
})
