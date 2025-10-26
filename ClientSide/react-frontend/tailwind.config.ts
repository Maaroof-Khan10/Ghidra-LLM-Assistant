import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './pages/**/*.{js,ts,jsx,tsx,mdx}', // Keep this just in case
    './components/**/*.{js,ts,jsx,tsx,mdx}', // Keep this just in case
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['var(--font-inter)', 'sans-serif'],
      },
      colors: {
        gray: {
          900: '#0d1117',
          800: '#161b22',
          700: '#30363d',
          600: '#484f58',
          500: '#6e7681',
          400: '#8b949e',
          300: '#c9d1d9',
          200: '#f0f6fc',
          100: '#fcfdff',
        },
        blue: {
          600: '#2f81f7',
          500: '#388bfd',
          400: '#58a6ff',
        }
      },
    },
  },
  plugins: [],
};
export default config;
