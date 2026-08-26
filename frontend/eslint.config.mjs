// Minimal ESLint flat config for qtrust-frontend.
// Next.js ships `eslint-config-next` — full linting is opt-in so `npm run build` (next build) stays green
// without requiring ESLint at build time. To enable full linting:
//
//   npm i -D eslint eslint-config-next @next/eslint-plugin-next @eslint/eslintrc
//   // then replace the export below with:
//   // import { FlatCompat } from "@eslint/eslintrc";
//   // const compat = new FlatCompat({ baseDirectory: import.meta.dirname });
//   // export default [
//   //   ...compat.config({ extends: ["next/core-web-vitals"] }),
//   //   { ignores: [".next/**", "node_modules/**", "out/**", "dist/**"] },
//   // ];
//
// Until then, this stub keeps lint opt-in and does not affect `next build`.
// It is intentionally dependency-free: no import of `eslint-config-next` so `next build`
// never fails when eslint deps are absent.

export default [
  {
    ignores: [".next/**", "node_modules/**", "out/**", "dist/**", "coverage/**", ".next/**"],
  },
  {
    files: ["src/**/*.{ts,tsx,js,jsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
    },
    rules: {
      // Project relies on TypeScript `strict` and `next build` type-checking as the gate.
      // Add custom rules here once eslint deps are installed (see header comment).
    },
  },
];
