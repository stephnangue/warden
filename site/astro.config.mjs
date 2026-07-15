// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
  site: 'https://wardengateway.com',
  integrations: [
    starlight({
      title: 'Warden',
      description:
        'The secure gateway connecting AI agents to the enterprise systems they need to do real work.',
      logo: {
        light: './src/assets/logo-light.svg',
        dark: './src/assets/logo-dark.svg',
        replacesTitle: true,
      },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/custom.css'],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/stephnangue/warden',
        },
      ],
      // PR 1 placeholder sidebar. PR 2 replaces this with the full docs tree
      // mirroring the concepts reading order.
      sidebar: [
        {
          label: 'Start here',
          items: [{ label: 'Getting started', slug: 'getting-started' }],
        },
      ],
    }),
  ],
});
