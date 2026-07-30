export default {
  plugins: {
    // Tailwind v4 moved the PostCSS plugin into its own package; using the
    // `tailwindcss` package directly as a plugin is a hard error in v4.
    '@tailwindcss/postcss': {},
    autoprefixer: {},
  },
}
