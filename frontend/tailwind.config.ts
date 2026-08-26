import type { Config } from "tailwindcss";

export default {
  content: [
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        qtrust: {
          50: "#f0fdfa",
          500: "#14b8a6",
          600: "#0a675f",
          700: "#096159",
        },
      },
    },
  },
  plugins: [],
} satisfies Config;
