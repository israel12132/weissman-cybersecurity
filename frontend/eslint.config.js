import js from '@eslint/js'
import globals from 'globals'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import jsxA11y from 'eslint-plugin-jsx-a11y'

// Accessibility rules run as WARN (not ERROR) so `npm run lint` — which fails only on
// errors — stays green while we burn down the a11y backlog across the ~77 pages that
// currently lack aria/role coverage. New code is nudged toward accessible markup.
const jsxA11yWarnings = Object.fromEntries(
  Object.entries(jsxA11y.flatConfigs.recommended.rules)
    // Honor the plugin's own recommended baseline: skip rules it ships as "off"
    // (notably the DEPRECATED `label-has-for`, superseded by
    // `label-has-associated-control`, which the old `Object.keys(...)` mapping
    // was force-enabling), and PRESERVE each rule's option object (e.g.
    // `control-has-associated-label`'s ignore-list for bare inputs/textareas)
    // rather than dropping it. Real a11y rules still surface as warnings.
    .filter(([, cfg]) => (Array.isArray(cfg) ? cfg[0] : cfg) !== 'off')
    .map(([rule, cfg]) => [rule, Array.isArray(cfg) ? ['warn', ...cfg.slice(1)] : 'warn']),
)

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
      // 'latest' so the parser understands import attributes (`with { type: 'json' }`),
      // which some engine-manifest modules use; older ecmaVersions error on it.
      ecmaVersion: 'latest',
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
    plugins: { react, 'react-hooks': reactHooks, 'jsx-a11y': jsxA11y },
    rules: {
      ...react.configs.flat.recommended.rules,
      ...jsxA11yWarnings,
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
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrors: 'none',
          // `const { engine, ...rest } = body` names properties to OMIT — the
          // siblings are used (to exclude them), not dead bindings.
          ignoreRestSiblings: true,
        },
      ],
      // Stylistic React rules → warnings (backlog, not a merge blocker).
      'react/no-unescaped-entities': 'warn',
      'react/display-name': 'warn',
      'react/no-unknown-property': 'warn',
      // Native browser dialogs are banned app-wide — use utils/confirmDialog
      // (confirmDialog/promptDialog/alertDialog), which are themed, focus-managed
      // and i18n-friendly. ERROR so a regression can't re-introduce OS chrome.
      'no-restricted-globals': [
        'error',
        { name: 'confirm', message: 'Use confirmDialog from utils/confirmDialog instead of window.confirm.' },
        { name: 'prompt', message: 'Use promptDialog from utils/confirmDialog instead of window.prompt.' },
        { name: 'alert', message: 'Use alertDialog from utils/confirmDialog (or a toast) instead of window.alert.' },
      ],
      'no-restricted-properties': [
        'error',
        { object: 'window', property: 'confirm', message: 'Use confirmDialog from utils/confirmDialog.' },
        { object: 'window', property: 'prompt', message: 'Use promptDialog from utils/confirmDialog.' },
        { object: 'window', property: 'alert', message: 'Use alertDialog from utils/confirmDialog (or a toast).' },
      ],
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
  // Vite build plugins under plugins/ run in Node.
  {
    files: ['*.mjs', 'scripts/**/*.{js,mjs}', 'plugins/**/*.{js,mjs,cjs}'],
    languageOptions: {
      sourceType: 'module',
      globals: { ...globals.node, ...globals.browser },
    },
    rules: {
      'no-unused-vars': 'warn',
      'no-empty': ['warn', { allowEmptyCatch: true }],
    },
  },
  // Service workers under public/ run in the ServiceWorker global scope
  // (self, caches, fetch, clients, …), not a DOM window.
  {
    files: ['public/**/*.js'],
    languageOptions: {
      sourceType: 'script',
      globals: { ...globals.serviceworker, ...globals.browser },
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
  // Service workers under public/ run in the ServiceWorker global scope
  // (self, caches, fetch, clients, …) — not the window scope.
  {
    files: ['public/**/*.js'],
    languageOptions: { globals: { ...globals.serviceworker, ...globals.browser } },
  },
  // Vite plugins under plugins/ run in Node (the top-level `*.mjs` block does not
  // match nested paths in flat config).
  {
    files: ['plugins/**/*.{js,mjs,cjs}'],
    languageOptions: { sourceType: 'module', globals: { ...globals.node } },
  },
]
