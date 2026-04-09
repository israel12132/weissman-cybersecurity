/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
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
      },
      fontFamily: {
        mono: ['"Space Mono"', '"JetBrains Mono"', 'monospace'],
        holo: ['Orbitron', 'Michroma', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
