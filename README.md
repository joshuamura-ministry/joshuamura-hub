# Joshua Mura — Digital Ministry Hub

The treasure-map ministry hub for Pastor Joshua Mura, hosted on Netlify.

## What's here
- `index.html` — the entire site (single-file app; treasure-map hub).
- `netlify/functions/circle-token.js` — JaaS (8x8) token signer for the live
  prayer/teaching/worship circles. Signs short-lived JWTs so circles are sealed,
  moderated, and embedded in-page.
- `netlify.toml`, `package.json` — Netlify build configuration.

## How deploys work
This repo is connected to Netlify. **Editing a file here (on github.com) and
committing it automatically deploys the site.** No zip dragging, no terminal.

## Secrets (never stored in this repo)
The signer reads four Netlify environment variables (Site configuration →
Environment variables):
- `JAAS_PRIVATE_KEY` — the private key (PEM block)
- `JAAS_KID` — the JaaS Key ID
- `JAAS_APP_ID` — the JaaS AppID
- `CIRCLE_MOD_PASS` — the private moderator passphrase

These live only in Netlify's encrypted store — never in this repository.

## Version
v23 — signer added, awaiting circle wiring.
