import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

export const collections = {
  docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),

  // Blog posts render through standalone pages (src/pages/blog/), not Starlight.
  // Posts own their <head>, which is what lets each carry its own og:* tags and
  // canonical URL — the latter matters when a post is cross-posted elsewhere.
  blog: defineCollection({
    // README.md documents the authoring conventions and is not a post.
    loader: glob({ pattern: ['**/*.md', '!**/README.md'], base: './src/content/blog' }),
    schema: z.object({
      /** Used as the <h1>, <title>, and og:title. */
      title: z.string(),
      /** Meta description, listing blurb, and RSS item description — one field, so they cannot drift. */
      description: z.string(),
      /** Plain YYYY-MM-DD. Drives sort order, prev/next, and article:published_time. */
      publishDate: z.coerce.date(),
      /** Set only when a published post materially changes. */
      updatedDate: z.coerce.date().optional(),
      /** Structured rather than a string so mapping onto other blogs' frontmatter is mechanical. */
      authors: z
        .array(z.object({ name: z.string(), url: z.string().url().optional() }))
        .default([{ name: 'Stephane Nangue', url: 'https://github.com/stephnangue' }]),
      /** Lowercase kebab-case labels. Rendered as chips; no tag routes yet. */
      tags: z.array(z.string()).default([]),
      /** Drafts build in dev and are excluded from routes, listing, and RSS in production. */
      draft: z.boolean().default(false),
      /**
       * Set ONLY when the post first appeared somewhere else; emitted as
       * <link rel="canonical">. Unset means self-canonical, which is the normal
       * case — this site is where posts are published first.
       */
      canonicalUrl: z.string().url().optional(),
      /** Path under /images/blog/. Used for og:image; falls back to the shared /og.png. */
      heroImage: z.string().optional(),
    }),
  }),
};
