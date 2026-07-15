# Warden website

The marketing landing page and documentation site for Warden, served at
[wardengateway.com](https://wardengateway.com). Built with [Astro](https://astro.build) +
[Starlight](https://starlight.astro.build) and deployed to Cloudflare Pages.

## Local development

Requires Node.js 20+.

```sh
cd site
npm install
npm run dev      # http://localhost:4321
```

| Command           | Action                                             |
| ----------------- | -------------------------------------------------- |
| `npm run dev`     | Start the dev server                               |
| `npm run build`   | Build the static site to `dist/`                   |
| `npm run preview` | Preview the built site locally                     |

> The first `npm install` may need the native `sharp`/`esbuild` install scripts approved. They
> are pre-approved in `package.json` under `allowScripts`, so CI and fresh clones run them
> automatically.

## Structure

- `src/content/docs/` — Starlight content root. `index.mdx` is the landing (splash) home; other
  pages are documentation. The full `docs/` tree is migrated here in a follow-up change.
- `src/assets/` — logo variants (`logo-dark.svg`, `logo-light.svg`) and images.
- `src/styles/custom.css` — Warden brand tokens (`#0B1020` navy, `#E01E1E` red, white text).
- `public/favicon.svg` — site favicon.
- `astro.config.mjs` — site config, Starlight integration, and sidebar.

## Deploy — Cloudflare Pages

Connect the GitHub repo to a Cloudflare Pages project with these build settings:

| Setting              | Value           |
| -------------------- | --------------- |
| Root directory       | `site`          |
| Build command        | `npm run build` |
| Build output directory | `dist`        |
| Node version         | `20` or higher  |

Cloudflare's native git integration deploys on push and creates a preview URL for every pull
request — no GitHub Actions workflow required. The custom domain `wardengateway.com` is attached
in the Pages project's **Custom domains** tab.
