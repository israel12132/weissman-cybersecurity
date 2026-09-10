/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './**/*.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        deep: 'var(--bg-deep)',
        charcoal: 'var(--bg-charcoal)',
        elevated: 'var(--bg-elevated)',
        ink: 'var(--text)',
        muted: 'var(--text-muted)',
        dim: 'var(--text-dim)',
        accent: 'var(--accent)',
        'accent-deep': 'var(--accent-deep)',
        risk: 'var(--risk)',
        ops: 'var(--ops)',
        danger: 'var(--danger)',
      },
      fontFamily: {
        sans: ['var(--font-sans)'],
        brand: ['var(--font-brand)'],
        mono: ['var(--font-mono)'],
      },
      borderRadius: {
        card: 'var(--radius)',
      },
      transitionDuration: {
        swift: 'var(--duration-swift)',
        base: 'var(--duration)',
        slow: 'var(--duration-slow)',
      },
      maxWidth: {
        site: '80rem',
      },
    },
  },
  plugins: [],
}
