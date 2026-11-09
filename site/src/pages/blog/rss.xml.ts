import rss from '@astrojs/rss';
import type { APIContext } from 'astro';
import { getPosts } from '../../lib/posts';

export async function GET(context: APIContext) {
  const posts = await getPosts();

  return rss({
    title: 'Warden blog',
    description:
      'Notes on brokering credentials for AI agents — identity, policy, and audit at the gateway.',
    // Astro.site, set in astro.config.mjs.
    site: context.site!,
    items: posts.map((post) => ({
      title: post.data.title,
      description: post.data.description,
      pubDate: post.data.publishDate,
      link: `/blog/${post.id}/`,
    })),
  });
}
