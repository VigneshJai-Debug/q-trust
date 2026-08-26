// Minimal ESLint flat config for qtrust-backend.
// This file intentionally stays lightweight so `npm run build` (tsc) never depends on lint.
// To enable full type-aware linting, install dev deps and uncomment the `tseslint` block:
//
//   npm i -D eslint @eslint/js typescript-eslint
//
// See also `npm run typecheck` and `npm test` — CI runs `ruff`/`slither`/`semgrep` separately.
export default [
  {
    ignores: ["dist/**", "node_modules/**", "coverage/**", ".coverage*"],
  },
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
    },
    rules: {
      // Keep rules minimal — project uses TypeScript `strict` and `tsc --noEmit` as the gate.
      // Add `no-unused-vars`, `no-console`, etc. here if the team wants an ESLint gate without new deps.
      "no-unused-vars": "off",
    },
  },
];
