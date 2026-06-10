/** @type {import('tailwindcss').Config} */
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
          0: 'var(--bg-0)',
          1: 'var(--bg-1)',
          2: 'var(--bg-2)',
          3: 'var(--bg-3)',
          4: 'var(--bg-4)',
          elevated: 'var(--bg-elevated)',
          overlay: 'var(--bg-overlay)',
          glass: 'var(--bg-glass)',
          'glass-elevated': 'var(--bg-glass-elevated)',
        },

        /* Text hierarchy */
        text: {
          primary: 'var(--text-primary)',
          secondary: 'var(--text-secondary)',
          tertiary: 'var(--text-tertiary)',
          muted: 'var(--text-muted)',
          disabled: 'var(--text-disabled)',
          inverse: 'var(--text-inverse)',
          accent: 'var(--text-accent)',
          'accent-violet': 'var(--text-accent-violet)',
        },

        /* Borders */
        border: {
          subtle: 'var(--border-subtle)',
          DEFAULT: 'var(--border-default)',
          strong: 'var(--border-strong)',
          accent: 'var(--border-accent)',
          'accent-violet': 'var(--border-accent-violet)',
          danger: 'var(--border-danger)',
        },

        /* Brand accent */
        accent: {
          cyan: 'var(--accent-cyan)',
          'cyan-soft': 'var(--accent-cyan-soft)',
          'cyan-muted': 'var(--accent-cyan-muted)',
          violet: 'var(--accent-violet)',
          'violet-soft': 'var(--accent-violet-soft)',
          'violet-muted': 'var(--accent-violet-muted)',
        },

        /* Severity */
        severity: {
          critical: 'var(--severity-critical)',
          'critical-bg': 'var(--severity-critical-bg)',
          'critical-border': 'var(--severity-critical-border)',
          high: 'var(--severity-high)',
          'high-bg': 'var(--severity-high-bg)',
          'high-border': 'var(--severity-high-border)',
          medium: 'var(--severity-medium)',
          'medium-bg': 'var(--severity-medium-bg)',
          'medium-border': 'var(--severity-medium-border)',
          low: 'var(--severity-low)',
          'low-bg': 'var(--severity-low-bg)',
          'low-border': 'var(--severity-low-border)',
          info: 'var(--severity-info)',
          'info-bg': 'var(--severity-info-bg)',
          'info-border': 'var(--severity-info-border)',
        },

        /* Status */
        status: {
          active: 'var(--status-active)',
          'active-bg': 'var(--status-active-bg)',
          pending: 'var(--status-pending)',
          'pending-bg': 'var(--status-pending-bg)',
          resolved: 'var(--status-resolved)',
          'resolved-bg': 'var(--status-resolved-bg)',
          offline: 'var(--status-offline)',
          'offline-bg': 'var(--status-offline-bg)',
          error: 'var(--status-error)',
          'error-bg': 'var(--status-error-bg)',
        },

        /* Intel badges */
        kev: {
          DEFAULT: 'var(--kev)',
          bg: 'var(--kev-bg)',
          border: 'var(--kev-border)',
        },
        epss: {
          high: 'var(--epss-high)',
          'high-bg': 'var(--epss-high-bg)',
          'high-border': 'var(--epss-high-border)',
          mid: 'var(--epss-mid)',
          'mid-bg': 'var(--epss-mid-bg)',
          low: 'var(--epss-low)',
          'low-bg': 'var(--epss-low-bg)',
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
