// Q-Trust docs-v2 — VitePress config with native Mermaid diagrams.
// Staged alongside the existing mkdocs site (see MIGRATION.md); it does NOT
// affect the production GitHub Pages deployment until the docs.yml workflow
// is edited, per the runbook.
import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

// TODO(owner): after switching production to docs-v2, copy og-github.png into
// docs-v2/public/ so the og:image URL is also served from this site (the
// design kit assets already provide the file — see docs-v2/README.md).
const OG_IMAGE = 'https://humoge7502.github.io/q-trust/og-github.png'

export default withMermaid(
  defineConfig({
    lang: 'en',
    title: 'Q-Trust',
    description:
      'Post-quantum cryptography migration & attestation protocol — CBOM scanning, GNN planning, Base L2 anchoring',

    // GitHub Pages project site lives under /q-trust/
    base: '/q-trust/',

    // "Last updated" timestamps come from the git history of the file —
    // rebases and amended commits will shift displayed dates.
    lastUpdated: true,

    head: [
      ['meta', { property: 'og:title', content: 'Q-Trust' }],
      [
        'meta',
        {
          property: 'og:description',
          content:
            'Post-quantum cryptography migration & attestation protocol — CBOM scanning, GNN planning, Base L2 anchoring',
        },
      ],
      ['meta', { property: 'og:image', content: OG_IMAGE }],
      ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ],

    themeConfig: {
      nav: [
        { text: 'Guide', link: '/guide/getting-started', activeMatch: '/guide/' },
        { text: 'Architecture', link: '/architecture/overview', activeMatch: '/architecture/' },
        { text: 'Security', link: '/security/overview', activeMatch: '/security/' },
        { text: 'Packages', link: '/packages/sdk', activeMatch: '/packages/' },
        { text: 'GitHub', link: 'https://github.com/humoge7502/q-trust' },
      ],

      sidebar: {
        '/guide/': [
          {
            text: 'Guide',
            items: [
              { text: 'Getting Started', link: '/guide/getting-started' },
              { text: 'Installation', link: '/guide/installation' },
            ],
          },
        ],
        '/architecture/': [
          {
            text: 'Architecture',
            items: [{ text: 'System Overview', link: '/architecture/overview' }],
          },
        ],
        '/security/': [
          {
            text: 'Security',
            items: [{ text: 'Security Model', link: '/security/overview' }],
          },
        ],
        '/packages/': [
          {
            text: 'Packages',
            items: [
              { text: 'qtrust-sdk', link: '/packages/sdk' },
              { text: 'qtrust-inspector', link: '/packages/inspector' },
            ],
          },
        ],
      },

      socialLinks: [{ icon: 'github', link: 'https://github.com/humoge7502/q-trust' }],

      footer: {
        message: 'Released under the MIT License.',
        copyright: 'Q-Trust · Built for the post-quantum era',
      },

      search: {
        provider: 'local',
        options: {
          translations: {
            button: {
              buttonText: 'Search docs',
              buttonAriaLabel: 'Search docs',
            },
          },
        },
      },

      outline: [2, 3],
      docFooter: {
        prev: 'Previous page',
        next: 'Next page',
      },
      darkModeSwitchLabel: 'Appearance',
    },

    // Mermaid diagrams render natively in fenced ```mermaid blocks.
    mermaid: {
      // Matches the site's dark-first brand (bg #0D1117 / #0A0E1A).
      theme: 'dark',
    },
  })
)
