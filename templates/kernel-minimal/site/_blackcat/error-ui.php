<?php

declare(strict_types=1);

/**
 * Shared, fail-closed error page UI for the kernel-minimal bundle.
 *
 * - No Composer/autoload dependencies (must work even when vendor/ is missing).
 * - No JS, intended to be used with strict CSP (default-src 'none').
 */

function blackcat_error_ui_favicons_html(): string
{
    return <<<'HTML'
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png" />
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png" />
    <link rel="manifest" href="/site.webmanifest" />
HTML;
}

function blackcat_error_ui_css_base(): string
{
    return <<<'CSS'
*, *::before, *::after { box-sizing: border-box; }

body {
  margin: 0;
  min-height: 100svh;
  display: flex;
  justify-content: center;
  align-items: center;
  padding: clamp(16px, 2.5vh, 56px) 16px 16px;
  font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
  position: relative;
  isolation: isolate;
  overflow-x: hidden;
  background:
    radial-gradient(900px 420px at 20% 0%, rgba(var(--bc-accent2), 0.18), transparent 55%),
    radial-gradient(900px 420px at 80% 0%, rgba(var(--bc-accent), 0.12), transparent 60%),
    #0b0f17;
  color: #e7eefc;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  background: var(--bc-grid-image) repeat;
  background-size: 512px 512px;
  opacity: 0.34;
  mix-blend-mode: screen;
  filter: brightness(2.2) contrast(1.35) saturate(1.15);
  pointer-events: none;
  z-index: 1;
}

body::after {
  content: "";
  position: fixed;
  inset: -20%;
  background:
    radial-gradient(circle at 18% 18%, rgba(var(--bc-accent), 0.18), transparent 52%),
    radial-gradient(circle at 82% 28%, rgba(var(--bc-accent2), 0.18), transparent 54%),
    radial-gradient(circle at 55% 85%, rgba(var(--bc-amber), 0.10), transparent 56%);
  filter: blur(56px) saturate(1.06);
  opacity: 0.38;
  pointer-events: none;
  z-index: 0;
}

@media (prefers-reduced-motion: no-preference) {
  body::before { animation: bcGridDrift 52s linear infinite; }
  body::after { animation: bcAuroraDrift 54s ease-in-out infinite alternate; }
  @keyframes bcGridDrift {
    from { background-position: 0 0; }
    to { background-position: 240px 120px; }
  }
  @keyframes bcAuroraDrift {
    from { transform: translate3d(-0.6%, -0.4%, 0) scale(1.02); }
    to { transform: translate3d(0.9%, 0.8%, 0) scale(1.05); }
  }
}

.frame {
  position: relative;
  max-width: 920px;
  width: 100%;
  isolation: isolate;
}

.card {
  width: 100%;
  border-radius: 18px;
  border: 1px solid rgba(31, 42, 68, 0.86);
  background:
    radial-gradient(900px 420px at 18% 0%, rgba(255, 255, 255, 0.07), transparent 62%),
    radial-gradient(900px 420px at 82% 0%, rgba(var(--bc-accent2), 0.10), transparent 66%),
    linear-gradient(180deg, rgba(15, 21, 36, 0.74), rgba(15, 21, 36, 0.40));
  backdrop-filter: blur(18px) saturate(1.25);
  -webkit-backdrop-filter: blur(18px) saturate(1.25);
  box-shadow:
    0 30px 100px rgba(0, 0, 0, 0.45),
    0 0 0 1px rgba(var(--bc-accent), 0.10);
  overflow: hidden;
  position: relative;
  z-index: 2;
}

.cardBorder {
  position: absolute;
  inset: 0;
  border-radius: 18px;
  pointer-events: none;
}
.cardBorder::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: 18px;
  padding: 1px;
  background: conic-gradient(
    from 210deg,
    rgba(var(--bc-accent), 0.00),
    rgba(var(--bc-accent), 0.24),
    rgba(var(--bc-accent2), 0.18),
    rgba(var(--bc-amber), 0.12),
    rgba(var(--bc-accent), 0.00)
  );
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  opacity: 0.9;
}
.cardBorder::after {
  content: "";
  position: absolute;
  inset: 1px;
  border-radius: 17px;
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.10),
    inset 0 -24px 40px rgba(0, 0, 0, 0.28);
  opacity: 0.85;
}

.header {
  padding: 16px 18px 14px 156px;
  min-height: 142px;
  border-bottom: 1px solid rgba(31, 42, 68, 0.95);
  position: relative;
  background:
    radial-gradient(900px 240px at 18% 0%, rgba(var(--bc-accent), 0.12), transparent 62%),
    radial-gradient(900px 240px at 82% 0%, rgba(var(--bc-accent2), 0.10), transparent 66%),
    linear-gradient(180deg, rgba(15, 21, 36, 0.64), rgba(15, 21, 36, 0.28));
}
.header::before {
  content: "";
  position: absolute;
  inset: 0;
  background:
    radial-gradient(500px 220px at 20% 35%, rgba(var(--bc-accent), 0.10), transparent 68%),
    radial-gradient(520px 240px at 80% 55%, rgba(var(--bc-accent2), 0.09), transparent 70%),
    linear-gradient(180deg, rgba(255, 255, 255, 0.06), transparent 45%);
  opacity: 0.85;
  pointer-events: none;
}
.header::after {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  bottom: -1px;
  height: 1px;
  background: linear-gradient(
    90deg,
    rgba(var(--bc-accent), 0.00),
    rgba(var(--bc-accent), 0.38),
    rgba(var(--bc-accent2), 0.32),
    rgba(var(--bc-accent2), 0.00)
  );
  opacity: 0.85;
  pointer-events: none;
}
@media (max-width: 740px) {
  .header { padding: 86px 18px 14px; min-height: 0; }
}

.mascotWrap {
  width: 148px;
  height: 148px;
  border-radius: 18px;
  background: transparent;
  position: absolute;
  left: -18px;
  top: -22px;
  overflow: visible;
  display: grid;
  place-items: center;
  transform-style: preserve-3d;
  z-index: 3;
}
@media (max-width: 740px) {
  .mascotWrap {
    width: 132px;
    height: 132px;
    left: 50%;
    top: -34px;
    transform: translateX(-50%);
  }
}
.mascotWrap::before {
  content: "";
  position: absolute;
  inset: -34px;
  background:
    radial-gradient(circle at 35% 22%, rgba(var(--bc-accent), 0.34), transparent 58%),
    radial-gradient(circle at 74% 70%, rgba(var(--bc-accent2), 0.22), transparent 60%),
    radial-gradient(circle at 55% 55%, rgba(var(--bc-amber), 0.14), transparent 62%);
  filter: blur(14px);
  opacity: 0.92;
  pointer-events: none;
  z-index: 0;
}
.mascot {
  width: 100%;
  height: 100%;
  background: var(--bc-mascot-image);
  filter: none;
  transform: translate3d(0, 0, 18px) scale(1.06);
  position: relative;
  z-index: 2;
}
@media (prefers-reduced-motion: no-preference) {
  .mascot { animation: bcMascotFloat 6.5s ease-in-out infinite; }
  @keyframes bcMascotFloat {
    0%, 100% { transform: translate3d(0, 0, 18px) scale(1.06); }
    50% { transform: translate3d(0, -2px, 18px) scale(1.06); }
  }
}

h1 {
  margin: 0;
  font-size: 26px;
  font-weight: 780;
  letter-spacing: 0.2px;
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  justify-content: flex-end;
  align-items: baseline;
  color: #e7eefc;
  text-shadow:
    0 1px 0 rgba(0, 0, 0, 0.78),
    0 2px 0 rgba(0, 0, 0, 0.38),
    0 -1px 0 rgba(255, 255, 255, 0.10),
    0 18px 70px rgba(0, 0, 0, 0.48);
}

.muted { color: #9fb0d0; }
.warn { color: #ffd46b; }
.bad { color: #ff7b72; }
.small { font-size: 12px; }

.header .muted {
  margin: 6px 0 0;
  max-width: 640px;
  margin-left: auto;
  text-align: left;
}
.muted strong { color: rgba(var(--bc-accent), 0.95); text-shadow: 0 1px 0 rgba(0, 0, 0, 0.65); }

.pill {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  background: linear-gradient(180deg, rgba(var(--bc-accent), 0.30), rgba(var(--bc-accent), 0.12));
  border: 1px solid rgba(var(--bc-accent), 0.44);
  color: rgba(var(--bc-accent), 0.95);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  letter-spacing: 0.03em;
  text-shadow:
    0 1px 0 rgba(0, 0, 0, 0.72),
    0 10px 40px rgba(0, 0, 0, 0.35);
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.18),
    inset 0 -12px 20px rgba(0, 0, 0, 0.36),
    0 0 0 1px rgba(var(--bc-accent), 0.08),
    0 16px 52px rgba(0, 0, 0, 0.34);
  margin-left: 0;
}
.pillLed {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  display: inline-block;
  background:
    radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.85), rgba(255, 255, 255, 0.00) 45%),
    rgba(var(--bc-accent), 1);
  box-shadow:
    0 0 0 1px rgba(0, 0, 0, 0.35),
    0 0 14px rgba(var(--bc-accent), 0.42),
    0 0 28px rgba(var(--bc-accent), 0.18);
  margin-right: 8px;
  transform: translateY(-1px);
}
@media (prefers-reduced-motion: no-preference) {
  .pillLed { animation: bcLedPulse 1.8s ease-in-out infinite; }
  @keyframes bcLedPulse {
    0%, 100% { opacity: 0.72; filter: saturate(1); }
    50% { opacity: 1; filter: saturate(1.12); }
  }
}

.body { padding: 14px 18px 16px; }
.grid2 { display: grid; grid-template-columns: 1fr; gap: 12px; }
@media (min-width: 980px) { .grid2 { grid-template-columns: 1fr 1fr; } }

.panel {
  margin: 0;
  padding: 12px 14px;
  border-radius: 14px;
  border: 1px solid rgba(31, 42, 68, 0.95);
  background: linear-gradient(180deg, rgba(11, 15, 23, 0.62), rgba(11, 15, 23, 0.42));
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.06);
  position: relative;
  overflow: hidden;
}
.panel::before {
  content: "";
  position: absolute;
  inset: -1px;
  background:
    radial-gradient(420px 180px at 18% 0%, rgba(var(--bc-accent), 0.10), transparent 70%),
    radial-gradient(420px 180px at 82% 0%, rgba(var(--bc-accent2), 0.09), transparent 70%),
    linear-gradient(180deg, rgba(255, 255, 255, 0.06), transparent 42%);
  opacity: 0.62;
  pointer-events: none;
}
.panel strong {
  display: inline-block;
  margin-bottom: 6px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 11px;
  color: #c9d6f3;
}

details.panel > summary {
  list-style: none;
  cursor: pointer;
  user-select: none;
}
details.panel > summary::-webkit-details-marker { display: none; }

ul, ol { margin: 10px 0 0 18px; padding: 0; }
li { margin: 6px 0; }

code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  padding: 1px 6px;
  border-radius: 8px;
  border: 1px solid rgba(31, 42, 68, 0.95);
  background: rgba(11, 15, 23, 0.48);
  color: #d7e3ff;
}

pre {
  margin: 10px 0 0;
  background: rgba(11, 15, 23, 0.55);
  border: 1px solid rgba(31, 42, 68, 0.95);
  padding: 12px 14px;
  border-radius: 14px;
  overflow: auto;
}

.footer { margin-top: 10px; font-size: 12px; color: #9fb0d0; }
CSS;
}

function blackcat_error_ui_normalize_rgb(string $raw, string $fallback): string
{
    $raw = trim($raw);
    if ($raw === '' || str_contains($raw, "\0") || preg_match('/[^0-9,\\s]/', $raw)) {
        return $fallback;
    }
    return preg_replace('/\\s+/', ' ', $raw) ?? $fallback;
}

function blackcat_error_ui_normalize_url(string $raw, string $fallback): string
{
    $raw = trim($raw);
    if ($raw === '' || str_contains($raw, "\0") || str_contains($raw, '<') || str_contains($raw, '>') || str_contains($raw, '"') || str_contains($raw, "'")) {
        return $fallback;
    }
    return $raw;
}

function blackcat_error_ui_mascot_bg(string $primaryUrl, ?string $fallbackUrl, int $fallbackPx): string
{
    $primary = blackcat_error_ui_normalize_url($primaryUrl, '/_blackcat/assets/fatal-error-cat.png');
    $fallback = $fallbackUrl !== null ? blackcat_error_ui_normalize_url($fallbackUrl, '') : '';

    $parts = [];
    $parts[] = 'url("' . $primary . '") center / contain no-repeat';
    if ($fallback !== '') {
        $size = max(16, min(256, $fallbackPx));
        $parts[] = 'url("' . $fallback . '") center / ' . $size . 'px ' . $size . 'px no-repeat';
    }

    return implode(",\n    ", $parts);
}

/**
 * @param list<array{url:string,mode:'contain'|'px',px?:int}> $layers
 */
function blackcat_error_ui_mascot_bg_from_layers(array $layers): string
{
    $parts = [];
    foreach ($layers as $layer) {
        if (!is_array($layer)) {
            continue;
        }
        $url = $layer['url'] ?? null;
        $mode = $layer['mode'] ?? null;
        if (!is_string($url) || !is_string($mode)) {
            continue;
        }

        $url = blackcat_error_ui_normalize_url($url, '');
        if ($url === '') {
            continue;
        }

        if ($mode === 'contain') {
            $parts[] = 'url("' . $url . '") center / contain no-repeat';
            continue;
        }

        if ($mode === 'px') {
            $px = $layer['px'] ?? 92;
            $px = is_int($px) ? $px : 92;
            $size = max(16, min(256, $px));
            $parts[] = 'url("' . $url . '") center / ' . $size . 'px ' . $size . 'px no-repeat';
        }
    }

    if ($parts === []) {
        return 'url("/_blackcat/assets/fatal-error-cat.png") center / contain no-repeat';
    }

    return implode(",\n    ", $parts);
}

/**
 * @param array{
 *   accent_rgb?:string,
 *   accent2_rgb?:string,
 *   grid_url?:string,
 *   mascot_layers?:list<array{url:string,mode:'contain'|'px',px?:int}>,
 *   mascot_primary_url?:string,
 *   mascot_fallback_url?:string|null,
 *   mascot_fallback_px?:int
 * } $vars
 */
function blackcat_error_ui_style_tag(array $vars = []): string
{
    $accent = isset($vars['accent_rgb']) && is_string($vars['accent_rgb'])
        ? blackcat_error_ui_normalize_rgb($vars['accent_rgb'], '255, 123, 114')
        : '255, 123, 114';

    $accent2 = isset($vars['accent2_rgb']) && is_string($vars['accent2_rgb'])
        ? blackcat_error_ui_normalize_rgb($vars['accent2_rgb'], '86, 116, 255')
        : '86, 116, 255';

    $gridUrl = isset($vars['grid_url']) && is_string($vars['grid_url'])
        ? blackcat_error_ui_normalize_url($vars['grid_url'], '/_blackcat/assets/bg-grid-red.png')
        : '/_blackcat/assets/bg-grid-red.png';

    $mascotLayers = $vars['mascot_layers'] ?? null;
    if (is_array($mascotLayers)) {
        $mascotBg = blackcat_error_ui_mascot_bg_from_layers($mascotLayers);
    } else {
    $primary = isset($vars['mascot_primary_url']) && is_string($vars['mascot_primary_url'])
        ? $vars['mascot_primary_url']
        : '/_blackcat/assets/fatal-error-cat.png';

    $fallbackKeyPresent = array_key_exists('mascot_fallback_url', $vars);
    $fallbackExplicit = $fallbackKeyPresent ? ($vars['mascot_fallback_url'] ?? null) : null;
    $fallbackExplicit = is_string($fallbackExplicit) || $fallbackExplicit === null ? $fallbackExplicit : null;

    $accentCompact = str_replace(' ', '', $accent);
    $isAmberTheme = ($accentCompact === '255,212,107');
    $fallbackAuto = $isAmberTheme
        ? '/_blackcat/assets/mascot-fallback-amber.svg'
        : '/_blackcat/assets/mascot-fallback-red.svg';

    // Default: always include a fallback mascot (so missing PNG assets do not break the UI).
    // Opt-out is possible only if the caller explicitly passes `mascot_fallback_url => null`.
    $fallback = $fallbackKeyPresent ? $fallbackExplicit : $fallbackAuto;

    $fallbackPx = isset($vars['mascot_fallback_px']) && is_int($vars['mascot_fallback_px']) ? $vars['mascot_fallback_px'] : 92;

    $mascotBg = blackcat_error_ui_mascot_bg($primary, $fallback, $fallbackPx);
    }

    $varsCss = <<<CSS
:root {
  color-scheme: dark;
  --bc-accent: {$accent};
  --bc-accent2: {$accent2};
  --bc-amber: 255, 212, 107;
  --bc-grid-image: url("{$gridUrl}");
  --bc-mascot-image: {$mascotBg};
}
CSS;

    return "<style>\n" . $varsCss . "\n" . blackcat_error_ui_css_base() . "\n</style>";
}

function blackcat_error_ui_escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Render a fail-closed HTML error page using shared CSS/layout.
 *
 * Note: `lede_html`, `grid_html`, and `after_grid_html` are assumed to be trusted template HTML.
 * Callers must escape any dynamic/untrusted data before passing it in.
 *
 * @param array{
 *   title:string,
 *   h1_prefix:string,
 *   pill?:string|null,
 *   lede_html?:string|null,
 *   grid_html?:string,
 *   after_grid_html?:string,
 *   style_vars?:array,
 *   extra_css?:string|null
 * } $opts
 */
function blackcat_error_ui_render_page(array $opts): string
{
    $title = blackcat_error_ui_escape($opts['title']);
    $h1Prefix = blackcat_error_ui_escape($opts['h1_prefix']);

    $pill = $opts['pill'] ?? null;
    $pill = is_string($pill) && $pill !== '' ? blackcat_error_ui_escape($pill) : null;
    $pillHtml = $pill !== null
        ? ' <span class="pill"><span class="pillLed" aria-hidden="true"></span>' . $pill . '</span>'
        : '';

    $ledeHtml = $opts['lede_html'] ?? null;
    $ledeHtml = is_string($ledeHtml) && $ledeHtml !== '' ? $ledeHtml : null;
    $ledeBlock = $ledeHtml !== null ? '<p class="muted">' . $ledeHtml . '</p>' : '';

    $gridHtml = $opts['grid_html'] ?? '';
    $gridHtml = is_string($gridHtml) ? $gridHtml : '';

    $afterGridHtml = $opts['after_grid_html'] ?? '';
    $afterGridHtml = is_string($afterGridHtml) ? $afterGridHtml : '';

    $styleVars = $opts['style_vars'] ?? [];
    $styleVars = is_array($styleVars) ? $styleVars : [];

    $extraCss = $opts['extra_css'] ?? null;
    $extraCss = is_string($extraCss) && $extraCss !== '' ? $extraCss : null;

    $extraStyleTag = $extraCss !== null ? "<style>\n" . $extraCss . "\n</style>" : '';

    $body = '<div class="body"><div class="grid2">' . $gridHtml . '</div>' . $afterGridHtml . '</div>';

    $favicons = blackcat_error_ui_favicons_html();
    $styleTag = blackcat_error_ui_style_tag($styleVars);

    return <<<HTML
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{$title}</title>
{$favicons}
{$styleTag}{$extraStyleTag}
  </head>
  <body>
    <div class="frame">
      <div class="mascotWrap" aria-hidden="true"><div class="mascot" aria-hidden="true"></div></div>
      <main class="card">
        <div class="cardBorder" aria-hidden="true"></div>
        <div class="header">
          <h1>{$h1Prefix}{$pillHtml}</h1>
          {$ledeBlock}
        </div>
        {$body}
      </main>
    </div>
  </body>
</html>
HTML;
}
