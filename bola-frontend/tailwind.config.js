/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          dark: '#0A0A0A',
          card: '#171717',
          border: '#262626',
          crimson: '#FF3B5C',
          deepred: '#DC2626',
          orange: '#F97316',
          light: '#F5F5F5',
          muted: '#A3A3A3',
          subtle: '#737373',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'Courier New', 'monospace'],
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      boxShadow: {
        'soft': '0 2px 15px -3px rgba(0, 0, 0, 0.04), 0 4px 6px -2px rgba(0, 0, 0, 0.02)',
        'card': '0 10px 30px -5px rgba(15, 23, 42, 0.06), 0 0 1px 1px rgba(15, 23, 42, 0.04)',
        'glow-emerald': '0 0 25px -5px rgba(16, 185, 129, 0.3)',
        'glow-rose': '0 0 25px -5px rgba(244, 63, 94, 0.3)',
        'glow-indigo': '0 0 25px -5px rgba(99, 102, 241, 0.3)',
      },
    },
  },
  plugins: [],
}
