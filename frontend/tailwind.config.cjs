/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base: {
          950: '#080b12',
          900: '#0d111c',
          850: '#111827',
          800: '#172033',
          700: '#22304a',
        },
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(148, 163, 184, 0.16), 0 18px 60px rgba(0, 0, 0, 0.25)',
      },
    },
  },
  plugins: [],
};
