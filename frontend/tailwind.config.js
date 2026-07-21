/** @type {import('tailwindcss').Config} */
/**
 * Token color helper: design tokens are defined as `var(--x)` (full hex/rgba values), which
 * Tailwind cannot split for its `/opacity` modifier — so `bg-bg-2/80` used to silently emit
 * nothing. This returns the plain var for solid usages (unchanged CSS, zero risk) and a
 * `color-mix` for an explicit numeric alpha, making `/opacity` work on every token.
 */
const tok = (v) => ({ opacityValue } = {}) =>
  opacityValue === undefined || opacityValue === '1' || String(opacityValue).includes('--tw-')
    ? `var(${v})`
    : `color-mix(in srgb, var(${v}) calc(${opacityValue} * 100%), transparent)`

export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        /* Legacy war palette — preserved for existing SOC components */
        war: {
          black: '#000000',
          dark: '#111111',
          panel: '#0d0d0d',
          border: '#1a1a1a',
          cyan: '#00f5ff',
          gold: '#ffb800',
          red: '#ff3366',
          silver: '#a0aec0',
        },
        'cyber-cyan': '#00f3ff',

        /* Design-system surfaces */
        bg: {
          0: tok('--bg-0'),
          1: tok('--bg-1'),
          2: tok('--bg-2'),
          3: tok('--bg-3'),
          4: tok('--bg-4'),
          elevated: tok('--bg-elevated'),
          overlay: tok('--bg-overlay'),
          glass: tok('--bg-glass'),
          'glass-elevated': tok('--bg-glass-elevated'),
        },

        /* Text hierarchy */
        text: {
          primary: tok('--text-primary'),
          secondary: tok('--text-secondary'),
          tertiary: tok('--text-tertiary'),
          muted: tok('--text-muted'),
          disabled: tok('--text-disabled'),
          inverse: tok('--text-inverse'),
          accent: tok('--text-accent'),
          'accent-violet': tok('--text-accent-violet'),
        },

        /* Borders */
        border: {
          subtle: tok('--border-subtle'),
          DEFAULT: tok('--border-default'),
          strong: tok('--border-strong'),
          accent: tok('--border-accent'),
          'accent-violet': tok('--border-accent-violet'),
          danger: tok('--border-danger'),
        },

        /* Brand accent */
        accent: {
          cyan: tok('--accent-cyan'),
          'cyan-soft': tok('--accent-cyan-soft'),
          'cyan-muted': tok('--accent-cyan-muted'),
          violet: tok('--accent-violet'),
          'violet-soft': tok('--accent-violet-soft'),
          'violet-muted': tok('--accent-violet-muted'),
        },

        /* Severity */
        severity: {
          critical: tok('--severity-critical'),
          'critical-bg': tok('--severity-critical-bg'),
          'critical-border': tok('--severity-critical-border'),
          high: tok('--severity-high'),
          'high-bg': tok('--severity-high-bg'),
          'high-border': tok('--severity-high-border'),
          medium: tok('--severity-medium'),
          'medium-bg': tok('--severity-medium-bg'),
          'medium-border': tok('--severity-medium-border'),
          low: tok('--severity-low'),
          'low-bg': tok('--severity-low-bg'),
          'low-border': tok('--severity-low-border'),
          info: tok('--severity-info'),
          'info-bg': tok('--severity-info-bg'),
          'info-border': tok('--severity-info-border'),
        },

        /* Status */
        status: {
          active: tok('--status-active'),
          'active-bg': tok('--status-active-bg'),
          pending: tok('--status-pending'),
          'pending-bg': tok('--status-pending-bg'),
          resolved: tok('--status-resolved'),
          'resolved-bg': tok('--status-resolved-bg'),
          offline: tok('--status-offline'),
          'offline-bg': tok('--status-offline-bg'),
          error: tok('--status-error'),
          'error-bg': tok('--status-error-bg'),
        },

        /* Intel badges */
        kev: {
          DEFAULT: tok('--kev'),
          bg: tok('--kev-bg'),
          border: tok('--kev-border'),
        },
        epss: {
          high: tok('--epss-high'),
          'high-bg': tok('--epss-high-bg'),
          'high-border': tok('--epss-high-border'),
          mid: tok('--epss-mid'),
          'mid-bg': tok('--epss-mid-bg'),
          low: tok('--epss-low'),
          'low-bg': tok('--epss-low-bg'),
        },
      },

      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Space Mono', 'ui-monospace', 'monospace'],
        display: ['Instrument Sans', 'Inter', 'ui-sans-serif', 'sans-serif'],
        holo: ['Orbitron', 'Instrument Sans', 'sans-serif'],
      },

      fontSize: {
        xs: ['var(--text-xs)', { lineHeight: 'var(--leading-normal)' }],
        sm: ['var(--text-sm)', { lineHeight: 'var(--leading-normal)' }],
        base: ['var(--text-base)', { lineHeight: 'var(--leading-normal)' }],
        md: ['var(--text-md)', { lineHeight: 'var(--leading-snug)' }],
        lg: ['var(--text-lg)', { lineHeight: 'var(--leading-snug)' }],
        xl: ['var(--text-xl)', { lineHeight: 'var(--leading-tight)' }],
        '2xl': ['var(--text-2xl)', { lineHeight: 'var(--leading-tight)' }],
        '3xl': ['var(--text-3xl)', { lineHeight: 'var(--leading-tight)' }],
      },

      letterSpacing: {
        tight: 'var(--tracking-tight)',
        wide: 'var(--tracking-wide)',
        wider: 'var(--tracking-wider)',
      },

      borderRadius: {
        xs: 'var(--radius-xs)',
        sm: 'var(--radius-sm)',
        md: 'var(--radius-md)',
        lg: 'var(--radius-lg)',
        xl: 'var(--radius-xl)',
        '2xl': 'var(--radius-2xl)',
        '3xl': 'var(--radius-3xl)',
      },

      boxShadow: {
        xs: 'var(--shadow-xs)',
        sm: 'var(--shadow-sm)',
        md: 'var(--shadow-md)',
        lg: 'var(--shadow-lg)',
        xl: 'var(--shadow-xl)',
        inner: 'var(--shadow-inner)',
        'glow-cyan': 'var(--shadow-glow-cyan)',
        'glow-violet': 'var(--shadow-glow-violet)',
        'glow-premium': 'var(--shadow-glow-premium)',
        'kev-glow': 'var(--kev-glow)',
      },

      spacing: {
        '0.5': 'var(--space-0-5)',
        '1.5': 'var(--space-1-5)',
        '2.5': 'var(--space-2-5)',
        '3.5': 'var(--space-3-5)',
      },

      transitionTimingFunction: {
        'out-expo': 'var(--ease-out-expo)',
        smooth: 'var(--ease-in-out-smooth)',
      },

      transitionDuration: {
        fast: 'var(--duration-fast)',
        normal: 'var(--duration-normal)',
        slow: 'var(--duration-slow)',
      },

      backgroundImage: {
        'accent-gradient': 'var(--accent-gradient)',
        'accent-gradient-subtle': 'var(--accent-gradient-subtle)',
        'accent-gradient-border': 'var(--accent-gradient-border)',
      },

      zIndex: {
        dropdown: 'var(--z-dropdown)',
        sticky: 'var(--z-sticky)',
        modal: 'var(--z-modal)',
        toast: 'var(--z-toast)',
      },
    },
  },
  plugins: [],
}
