import { getCollection, type CollectionEntry } from 'astro:content';

export type Post = CollectionEntry<'blog'>;

/**
 * Published posts, newest first.
 *
 * Drafts are visible in `astro dev` and excluded from every production surface.
 * The filter lives here rather than at each call site because it has to be
 * identical in three places — the listing, the post route, and the RSS feed.
 * A draft that is built but not linked is an orphan the link checker never
 * visits, so it would ship unreviewed.
 */
export async function getPosts(): Promise<Post[]> {
  const posts = await getCollection('blog', ({ data }) =>
    import.meta.env.PROD ? !data.draft : true,
  );
  return posts.sort(
    (a, b) => b.data.publishDate.valueOf() - a.data.publishDate.valueOf(),
  );
}

/** "17 September 2026" — spelled out, so there is no DD/MM vs MM/DD ambiguity. */
export function formatDate(date: Date): string {
  return date.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

/** Rough reading time in minutes. 230 wpm is the usual prose estimate. */
export function readingTime(body: string | undefined): number {
  const words = (body ?? '').trim().split(/\s+/).filter(Boolean).length;
  return Math.max(1, Math.ceil(words / 230));
}
