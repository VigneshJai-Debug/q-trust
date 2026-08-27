# Q-Trust docs-v2 (VitePress)

Next-generation documentation site for [Q-Trust](https://github.com/humoge7502/q-trust) —
VitePress + native Mermaid diagrams + brand theme (cyan/violet on `#0D1117`).
Staged alongside the live mkdocs site; the switchover runbook is in
[MIGRATION.md](./MIGRATION.md). Nothing here affects production until you run it.

## Quick start

```bash
cd docs-v2
npm install
npm run docs:dev      # dev server at http://localhost:5173/q-trust/
npm run docs:build    # production build → .vitepress/dist
npm run docs:preview  # preview the production build
```

## Layout

```text
docs-v2/
├── package.json               # qtrust-docs (private, vitepress + mermaid)
├── package-lock.json          # lockfile (npm ci / workflow cache key)
├── .vitepress/
│   ├── config.ts              # nav, sidebars, search, head meta, mermaid
│   └── theme/                 # index.ts + custom.css (brand overrides)
├── public/                    # static assets (see note below)
├── index.md                   # home: hero + 6 feature cards + pipeline diagram
├── guide/                     # getting-started.md, installation.md
├── architecture/overview.md   # six subsystems + dataflow diagram
├── security/overview.md       # EIP-712, UUPS+timelock, testing, disclosure
├── packages/                  # sdk.md, inspector.md (real PyPI usage)
├── MIGRATION.md               # mkdocs → VitePress switchover runbook
└── README.md                  # this file
```

## Expected images in `public/`

The site references three brand images that are **provided by the design-kit
assets** (copy them into `docs-v2/public/` before the production switch):

- `public/hero.png` — home-page hero illustration
- `public/logo.png` — site logo (nav/sidebar)
- `public/og-github.png` — social preview image (also referenced by the
  absolute URL in `.vitepress/config.ts`)

They are intentionally not committed with this skeleton.
