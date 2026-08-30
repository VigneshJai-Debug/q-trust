// ESLint flat config for qtrust-frontend (Next.js 16 / React 19).
// `eslint-config-next@16` exports a native flat config, so `npm run lint`
// runs the full core-web-vitals + TypeScript rule set.

import { defineConfig } from "eslint/config";
import next from "eslint-config-next";

export default defineConfig([
  {
    ignores: [".next/**", "node_modules/**", "out/**", "dist/**", "coverage/**"],
  },
  ...next,
  {
    rules: {
      // Next 16 strict-mode servers are the project gate; avoid noisy churn.
      "@next/next/no-html-link-for-pages": "off",
    },
  },
]);