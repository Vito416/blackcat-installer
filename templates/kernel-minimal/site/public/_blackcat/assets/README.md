# Stage 3 setup assets

Drop your images here to upgrade the “wow effect” of the installer UI.

Prefer placing assets in `site/_blackcat/asset/` (outside web docroot) — the kernel front controller serves them at `/_blackcat/assets/<filename>`.
This folder (`site/public/_blackcat/assets/`) is kept for convenience / legacy and will also work if you drop the files here.

Suggested files (PNG, no text recommended):
- `fatal-error-cat.png` — generic “fatal gate” mascot (used for HTTP block / front-controller-required and similar fail-closed pages).
- `tls-not-trusted-cat.png` — shown when setup is opened over HTTPS, but the certificate is not publicly trusted (production is fail-closed).
- `hero-banner.png` — optional hero header background or banner.
- `trusted-vs-untrusted.png` — optional split illustration for release trust / integrity.
- `bg-grid.png` — repeating background grid (default theme).
- `bg-grid-red.png` — repeating background grid for error/fail-closed pages (recommended to visually separate “blocked” states).
- `mascot-fallback-red.svg` — universal fallback mascot for red/fail-closed pages (used automatically when a PNG is missing).
- `mascot-fallback-amber.svg` — universal fallback mascot for amber/warn pages (used automatically when a PNG is missing).
- `favicon.png` (64×64 or 128×128) — high-contrast icon for tiny sizes (tab / bookmarks).

Guidelines:
- Prefer dark UI style (fits the installer theme).
- Avoid third‑party logos/trademarks.
- Keep text minimal (or none) so it works in any language.
