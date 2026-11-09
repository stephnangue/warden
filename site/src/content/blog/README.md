# Blog posts

One Markdown file per post. The filename is the slug and the URL segment:
`access-delegation-openbao.md` publishes at `/blog/access-delegation-openbao/`.
No dates in the filename — URLs stay durable, and the date lives in frontmatter.

## Frontmatter

```yaml
---
title: "Access delegation for AI agents with OpenBao"
description: "One or two sentences. Used as the meta description, the listing blurb, and the RSS item."
publishDate: 2026-09-17
tags: [openbao, delegation]
# updatedDate: 2026-10-02      # only when a published post materially changes
# draft: true                  # visible in `npm run dev`, excluded from production
# canonicalUrl: https://...    # ONLY when the post first appeared somewhere else
# heroImage: /images/blog/warden-blog-<slug>-hero.png
---
```

`authors` defaults to the maintainer; override it with a list of
`{ name, url }` when a post has a different or additional author.

## Conventions

- **Plain Markdown, not MDX.** Posts must paste into other blogs without
  translation, so no components.
- **Images** live at `public/images/blog/warden-blog-<slug>-<name>.png` and are
  embedded with the same raw-HTML pattern the docs use:
  `<p align="center"><img alt="a full sentence" src="/images/blog/..." width="860"></p>`.
  A missing image fails CI — linkinator collects `img[src]`.
- **Voice** follows `RELEASE_NOTES.md`: em-dashes, no hype adjectives, no emoji,
  every claim paired with a mechanism.
- `scripts/check-invariants.sh` scans this directory. A post that shows a policy
  is copy-paste surface exactly like a reference page.

## Cross-posting

This site is canonical. When a post is adapted for another blog, leave
`canonicalUrl` unset here, add an attribution line there linking back, and note
the cross-post in an HTML comment at the top of the source file so factual fixes
can be kept in sync.
