/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans:   ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono:   ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
        serif:  ['"IBM Plex Serif"', 'Georgia', 'serif'],
      },
      colors: {
        brand: {
          50:  '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
        },
      },
      boxShadow: {
        'card':       '0 1px 2px rgb(15 23 42 / 0.04), 0 1px 3px rgb(15 23 42 / 0.06)',
        'card-hover': '0 4px 6px -1px rgb(15 23 42 / 0.06), 0 2px 4px -2px rgb(15 23 42 / 0.04)',
        'inset-line': 'inset 0 -1px 0 rgb(15 23 42 / 0.06)',
      },
      keyframes: {
        'fade-up':    { from: { opacity: '0', transform: 'translateY(4px)' }, to: { opacity: '1', transform: 'none' } },
        'pulse-ring': {
          '0%, 100%': { boxShadow: '0 0 0 0 rgb(2 132 199 / 0.4)' },
          '50%':      { boxShadow: '0 0 0 6px rgb(2 132 199 / 0)' },
        },
      },
      animation: {
        'fade-up':    'fade-up 0.3s ease-out',
        'pulse-ring': 'pulse-ring 2s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};
