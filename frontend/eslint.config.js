import js from '@eslint/js'
import globals from 'globals'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'

// Flat config (ESLint 9). Scoped to application source (src/**). The Playwright
// specs under tests-e2e/** are TypeScript and linted by their own toolchain, so we
// ignore them here to avoid pulling in a TS parser.
//
// Severity philosophy: ERROR only for real correctness bugs (rules-of-hooks, etc.);
// WARN for style/hygiene so `npm run lint` (which fails on errors) stays a reliable
// CI gate while we burn down the warning backlog over time.
export default [
  {
    ignores: [
      'dist/**',
      'coverage/**',
      'playwright-report/**',
      'test-results/**',
      'node_modules/**',
      'tests-e2e/**',
    ],
  },
  js.configs.recommended,
  {
    files: ['src/**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.es2021,
      },
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    settings: { react: { version: 'detect' } },
    plugins: { react, 'react-hooks': reactHooks },
    rules: {
      ...react.configs.flat.recommended.rules,
      // Vite uses the automatic JSX runtime — no React import needed in scope.
      'react/react-in-jsx-scope': 'off',
      'react/jsx-uses-react': 'off',
      // This is a JavaScript project; we don't enforce prop-types.
      'react/prop-types': 'off',
      // Rules of Hooks is a genuine correctness gate; dependency completeness is advisory.
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      // Surface dead/typo'd bindings without blocking on intentional throwaways.
      'no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
      ],
      // Stylistic React rules → warnings (backlog, not a merge blocker).
      'react/no-unescaped-entities': 'warn',
      'react/display-name': 'warn',
      'react/no-unknown-property': 'warn',
      // Empty blocks (incl. empty catch) are a hygiene smell, not a correctness bug —
      // surfaced as warnings to burn down rather than blocking the gate.
      'no-empty': ['warn', { allowEmptyCatch: false }],
      // Flag `.catch(() => {})` — a silent promise-rejection swallow that leaves the
      // user staring at empty data with no error. Tracked as a warning backlog.
      'no-restricted-syntax': [
        'warn',
        {
          selector:
            "CallExpression[callee.property.name='catch'] > ArrowFunctionExpression[body.body.length=0]",
          message:
            'Empty .catch() swallows errors silently — surface an error state/toast/log, or add a comment explaining why it is safe to ignore.',
        },
      ],
    },
  },
  // Build/tooling config files run in Node.
  {
    files: ['*.config.{js,cjs,mjs}', 'vite.config.js', 'vitest.config.js'],
    languageOptions: { sourceType: 'module', globals: { ...globals.node } },
  },
  // Standalone scripts (e.g. qa-walkthrough.mjs) drive a real browser, so their code
  // legitimately references both Node and browser globals (page.evaluate callbacks).
  {
    files: ['*.mjs', 'scripts/**/*.{js,mjs}'],
    languageOptions: {
      sourceType: 'module',
      globals: { ...globals.node, ...globals.browser },
    },
    rules: {
      'no-unused-vars': 'warn',
      'no-empty': ['warn', { allowEmptyCatch: true }],
    },
  },
  // Unit/component tests (Vitest) — explicit imports, Node + browser context.
  {
    files: ['src/**/*.test.{js,jsx}', 'src/**/*.spec.{js,jsx}', 'src/test/**'],
    languageOptions: { globals: { ...globals.node, ...globals.browser } },
  },
]
