<?php

declare(strict_types=1);

// Optional: shared fail-closed error page UI (no Composer dependency).
// Keep the bundle resilient even if vendor/ is missing.
$__blackcatErrorUi = __DIR__ . DIRECTORY_SEPARATOR . 'error-ui.php';
if (is_file($__blackcatErrorUi)) {
    /** @noinspection PhpIncludeInspection */
    require_once $__blackcatErrorUi;
}

use BlackCat\Config\Runtime\ConfigRepository;
use BlackCat\Config\Runtime\RuntimeConfigInstaller;
use BlackCat\Config\Security\KernelAttestations;
use BlackCat\Core\TrustKernel\Bytes32;
use BlackCat\Core\TrustKernel\IntegrityManifestBuilder;
use BlackCat\Core\TrustKernel\TrustPolicyV3;

/**
 * Stage 3 one-time setup handler (template).
 *
 * Security model:
 * - Setup is gated by an install token stored under `<bundle>/.blackcat/install.token`.
 * - Setup can be disabled permanently by creating `<bundle>/.blackcat/installed.flag`.
 * - The setup UI is served only from the front controller (never as a direct PHP entrypoint).
 */

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_handle(array $paths): void
{
    $path = blackcat_request_path();
    if ($path === '/_blackcat/setup') {
        blackcat_setup_page($paths);
        return;
    }

    if (str_starts_with($path, '/_blackcat/setup/api/')) {
        blackcat_setup_api($paths, substr($path, strlen('/_blackcat/setup/api/')));
        return;
    }

    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Not found.\n";
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_page(array $paths): void
{
    if (blackcat_setup_is_disabled($paths['state_dir'])) {
        // Installer is intentionally unavailable after install (minimize web attack surface).
        // Use signed upgrade tooling instead of reopening setup.
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Not found.\n";
        exit;
    }

    if (!blackcat_is_https_request()) {
        http_response_code(400);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

        $gridHtml = <<<'HTML'
            <div class="panel">
              <strong>Do this:</strong>
              <ol>
                <li>Enable HTTPS (recommended: Let’s Encrypt).</li>
                <li>If you use a reverse proxy, forward the original scheme (<code>Forwarded: proto=https</code> or <code>X-Forwarded-Proto: https</code>) — only trusted local peers are honored.</li>
                <li>Reload via <code>https://</code> and open <code>/_blackcat/setup</code> again.</li>
              </ol>
            </div>
            <div class="panel">
              <strong>Why BlackCat blocks HTTP:</strong>
              <ul class="muted">
                <li>HTTP can be downgraded or intercepted (MITM).</li>
                <li>Setup handles secrets + approvals; a single unsafe request can compromise the system.</li>
                <li>Fail-closed is intentional: no “click-through” bypass.</li>
              </ul>
              <div class="footer warn">Tip: after install, BlackCat disables setup by default. You can also delete the setup module for zero web attack surface.</div>
            </div>
HTML;

        if (function_exists('blackcat_error_ui_render_page')) {
            echo blackcat_error_ui_render_page([
                'title' => 'BlackCat Setup — HTTPS Required',
                'h1_prefix' => 'BlackCat Setup',
                'pill' => 'HTTPS only',
                'lede_html' => '<strong>Plain HTTP is not allowed.</strong> Setup is a high-trust operation (install token + wallet approvals). BlackCat blocks it over HTTP to prevent downgrade and MITM attacks.',
                'grid_html' => $gridHtml,
                'style_vars' => [
                    'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                    'mascot_primary_url' => '/_blackcat/assets/fatal-error-cat.png',
                ],
            ]);
        } else {
            echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — HTTPS Required</title><h1>HTTPS required</h1>';
        }
        exit;
    }

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!is_string($method) || !in_array(strtoupper(trim($method)), ['GET', 'HEAD'], true)) {
        http_response_code(405);
        header('Allow: GET, HEAD');
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

        $gridHtml = <<<'HTML'
            <div class="panel">
              <strong>Allowed on this endpoint:</strong>
              <ul>
                <li><code>GET</code></li>
                <li><code>HEAD</code></li>
              </ul>
            </div>
            <div class="panel">
              <strong>What to do:</strong>
              <ul class="muted">
                <li>Retry with <code>GET</code> (open <code>/_blackcat/setup</code> in a browser).</li>
                <li>For scripts and automation, use <code>/_blackcat/setup/api/*</code>.</li>
              </ul>
            </div>
HTML;

        if (function_exists('blackcat_error_ui_render_page')) {
            echo blackcat_error_ui_render_page([
                'title' => 'BlackCat Setup — Method Not Allowed',
                'h1_prefix' => 'BlackCat Setup',
                'pill' => 'method not allowed',
                'lede_html' => '<strong>This endpoint is read-only.</strong> Only <code>GET</code>/<code>HEAD</code> are accepted here. For actions, use the setup API endpoints.',
                'grid_html' => $gridHtml,
                'style_vars' => [
                    'accent_rgb' => '255, 212, 107',
                    'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                    'mascot_primary_url' => '/_blackcat/assets/method-not-allowed-cat.png',
                ],
            ]);
        } else {
            echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — Method Not Allowed</title><h1>Method not allowed</h1>';
        }
        exit;
    }

    $stateDir = $paths['state_dir'];
    blackcat_ensure_state_dir($stateDir);
    if (!is_dir($stateDir)) {
        blackcat_setup_render_preflight_page($paths, [
            'Unable to create state directory (.blackcat). Fix permissions and reload.',
        ], []);
        exit;
    }

    $preflight = blackcat_setup_preflight($paths);
    if ($preflight['errors'] !== []) {
        blackcat_setup_render_preflight_page($paths, $preflight['errors'], $preflight['warnings']);
        exit;
    }

    $tlsGate = blackcat_setup_tls_gate($stateDir);
    if ($tlsGate['mode'] === 'prod' && $tlsGate['trusted'] !== true) {
        blackcat_setup_render_tls_not_trusted_page($tlsGate);
        exit;
    }

    $tokenPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.token';
    if (!is_file($tokenPath)) {
        $token = bin2hex(random_bytes(32));
        $written = @file_put_contents($tokenPath, $token . "\n");
        if ($written === false || !is_file($tokenPath)) {
            blackcat_setup_render_preflight_page($paths, [
                'Unable to write .blackcat/install.token (permissions or disk error). Fix and reload.',
            ], $preflight['warnings']);
            exit;
        }
        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($tokenPath, 0600);
        }
    }

    $tlsBarHtml = '';
    if ($tlsGate['mode'] === 'dev' && $tlsGate['trusted'] !== true) {
        $tlsBarHtml = '<div class="tlsBar" role="status">'
            . '<strong>DEV WARNING:</strong> TLS certificate is not publicly trusted. '
            . 'Do <strong>not</strong> use this mode in production. Install a CA-trusted certificate (e.g., Let’s Encrypt) and reload. '
            . '</div>';
    }

    $uiMap = $_GET['ui_map'] ?? null;
    $uiMapOn = is_string($uiMap) && in_array(strtolower(trim($uiMap)), ['1', 'true', 'yes', 'on'], true);
    $uiMapValue = $uiMapOn ? '1' : '0';

    $nonce = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    if ($tlsGate['mode'] === 'prod' && $tlsGate['trusted'] === true) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
    header(
        "Content-Security-Policy: default-src 'none'; "
        . "script-src 'nonce-{$nonce}'; "
        . "script-src-attr 'none'; "
        . "connect-src 'self'; "
        . "img-src 'self' data:; "
        . "style-src 'unsafe-inline'; "
        . "base-uri 'none'; "
        . "form-action 'none'; "
        . "frame-ancestors 'none'"
    );
    $assetDir = rtrim($paths['site_dir'], "/\\") . DIRECTORY_SEPARATOR . '_blackcat' . DIRECTORY_SEPARATOR . 'asset';

    $overviewIllustrationUrl = '/_blackcat/assets/hero-banner.png';
    $overviewIllustrationClass = 'overviewArt';
    $overviewLogoPath = $assetDir . DIRECTORY_SEPARATOR . 'setup_logo.png';
    if (is_file($overviewLogoPath)) {
        $overviewIllustrationUrl = '/_blackcat/assets/setup_logo.png';
        $overviewIllustrationClass .= ' isLogo';
    } else {
        $overviewIllustrationPath = $assetDir . DIRECTORY_SEPARATOR . 'setup-overview.png';
        if (is_file($overviewIllustrationPath)) {
            $overviewIllustrationUrl = '/_blackcat/assets/setup-overview.png';
        }
    }

    $overviewIllustrationHtml = '<div class="' . $overviewIllustrationClass . '" aria-hidden="true">'
        . '<img src="' . $overviewIllustrationUrl . '" alt="" loading="lazy" decoding="async" />'
        . '</div>';

    $trustIllustrationPath = $assetDir . DIRECTORY_SEPARATOR . 'trusted-vs-untrusted.png';
    $trustIllustrationHtml = '';
    // Note: we intentionally do not render the "Trusted vs untrusted" panel inside setup
    // (it adds noise to the Stage 3 flow). The image asset can still be used elsewhere.

    $page = <<<'HTML'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>BlackCat Setup</title>
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png" />
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png" />
    <link rel="manifest" href="/site.webmanifest" />
    <style>
	      :root {
	        color-scheme: dark;
	        --bc-accent: 86, 116, 255;
	        --bc-accent2: 118, 227, 157;
	          --bc-ice: 140, 208, 255;
	          --bc-cyan: 84, 220, 255;
	        --bc-amber: 255, 212, 107;
	        --bc-orange: 255, 146, 84;
	        --bc-violet: 183, 76, 255;
	        /* Adventure path (Stage 3 UX): updated by JS to show “where you are”. */
	        --bc-adventure-progress: 0;
	        --bc-adventure-from: var(--bc-amber);
	        --bc-adventure-to: var(--bc-orange);
	        --bc-adventure-marker-x: 50;
	        --bc-adventure-marker-y: 12;
          /* Reset baseline (white glass surfaces) — we’ll rebuild from a clean surface system. */
          --bc-surface-1: rgba(255, 255, 255, 0.11);
          --bc-surface-2: rgba(255, 255, 255, 0.04);
          --bc-surface-3: rgba(255, 255, 255, 0.02);
          --bc-border-1: rgba(255, 255, 255, 0.22);
          --bc-border-2: rgba(255, 255, 255, 0.12);
          --bc-inset-1: rgba(255, 255, 255, 0.16);
          --bc-shadow-1: 0 24px 90px rgba(0, 0, 0, 0.44);
          --bc-shadow-2: 0 0 0 1px rgba(255, 255, 255, 0.06);
          --bc-blur-1: 14px;
          --bc-saturate-1: 1.12;
	        --bc-mask-cat-head: url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20viewBox%3D%270%200%20100%20100%27%3E%3Cpath%20d%3D%27M25%2010%20L10%2028%20L16%2062%20C18%2080%2034%2092%2050%2092%20C66%2092%2082%2080%2084%2062%20L90%2028%20L75%2010%20L63%2028%20L50%2016%20L37%2028%20Z%27%20fill%3D%27black%27/%3E%3C/svg%3E");
	        --bc-mask-glyph-lock: url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2024%2024%22%3E%3Cpath%20d%3D%22M8%2010V8a4%204%200%201%201%208%200v2h2v12H6V10h2zm2%200h4V8a2%202%200%201%200-4%200v2z%22%20fill%3D%22black%22%2F%3E%3C%2Fsvg%3E");
        --bc-mask-glyph-chain: url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2024%2024%22%3E%3Cpath%20d%3D%22M7%206h3v2H7a2%202%200%200%200%200%204h3v2H7a4%204%200%200%201%200-8zm7%200h3a4%204%200%200%201%200%208h-3v-2h3a2%202%200%200%200%200-4h-3V6zm-5%205h6v2H9v-2z%22%20fill%3D%22black%22%2F%3E%3C%2Fsvg%3E");
        --bc-mask-glyph-key: url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2024%2024%22%3E%3Cpath%20d%3D%22M7%2014a5%205%200%201%201%204.9-6H22v4h-2v2h-2v2h-4v-4h-2.1A5%205%200%200%201%207%2014zm0-2a3%203%200%201%200%200-6%203%203%200%200%200%200%206z%22%20fill%3D%22black%22%2F%3E%3C%2Fsvg%3E");
        --bc-mask-glyph-shield: url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2024%2024%22%3E%3Cpath%20d%3D%22M12%202l8%204v6c0%205-3.4%209.2-8%2010-4.6-.8-8-5-8-10V6l8-4z%22%20fill%3D%22black%22%2F%3E%3C%2Fsvg%3E");
        --bc-mask-glyph-wallet: url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2024%2024%22%3E%3Cpath%20d%3D%22M3%207h18v12H3V7zm2%202v8h14V9H5zm12%203h2v2h-2v-2z%22%20fill%3D%22black%22%2F%3E%3C%2Fsvg%3E");
        --bc-mask-glyph-layers: url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2024%2024%22%3E%3Cpath%20d%3D%22M12%203l9%205-9%205-9-5%209-5zm0%208l9%205-9%205-9-5%209-5z%22%20fill%3D%22black%22%2F%3E%3C%2Fsvg%3E");
      }

      *, *::before, *::after { box-sizing: border-box; }

      body {
        margin: 0;
        padding: 24px;
        font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        position: relative;
        isolation: isolate;
        overflow-x: hidden;
        background:
          radial-gradient(900px 420px at 18% 0%, rgba(var(--bc-accent), 0.26), transparent 58%),
          radial-gradient(900px 420px at 82% 0%, rgba(var(--bc-accent2), 0.18), transparent 62%),
          radial-gradient(1100px 700px at 50% 120%, rgba(var(--bc-violet), 0.10), transparent 60%),
          linear-gradient(180deg, #050712 0%, #070b18 52%, #050614 100%);
        color: #e7eefc;
      }
      body::before {
        content: "";
        position: fixed;
        inset: 0;
        background:
          radial-gradient(circle at 15px 20px, rgba(255, 255, 255, 0.36) 0, rgba(255, 255, 255, 0.36) 1px, transparent 2px) 0 0 / 190px 190px,
          radial-gradient(circle at 110px 140px, rgba(255, 255, 255, 0.22) 0, rgba(255, 255, 255, 0.22) 1px, transparent 2px) 0 0 / 260px 260px,
          radial-gradient(circle at 40px 70px, rgba(255, 255, 255, 0.14) 0, rgba(255, 255, 255, 0.14) 2px, transparent 3px) 0 0 / 420px 420px,
          url("/_blackcat/assets/bg-grid.png") repeat;
        background-size: 512px 512px;
        opacity: 0.46;
        mix-blend-mode: screen;
        filter: brightness(2.75) contrast(1.55) saturate(1.30);
        pointer-events: none;
        z-index: 1;
      }
      body::after {
        content: "";
        position: fixed;
        inset: -20%;
        background:
          radial-gradient(circle at 18% 18%, rgba(var(--bc-accent), 0.18), transparent 52%),
          radial-gradient(circle at 82% 28%, rgba(var(--bc-accent2), 0.12), transparent 54%),
          radial-gradient(circle at 55% 85%, rgba(var(--bc-amber), 0.10), transparent 56%),
          radial-gradient(circle at 52% 58%, rgba(var(--bc-violet), 0.10), transparent 60%);
        filter: blur(62px) saturate(1.10);
        opacity: 0.44;
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

      a { color: #8ab4ff; }
      code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      pre {
        background: rgba(11, 15, 23, 0.40);
        border: 1px solid rgba(31, 42, 68, 0.95);
        padding: 12px 14px;
        border-radius: 14px;
        overflow: auto;
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.06);
      }

      .wrap { max-width: 1180px; margin: 0 auto; position: relative; z-index: 2; }
      .wrap::before {
        content: "";
        position: fixed;
        inset: -30%;
        background:
          radial-gradient(900px 520px at 12% 18%, rgba(var(--bc-accent), 0.08), transparent 60%),
          radial-gradient(900px 520px at 86% 20%, rgba(var(--bc-accent2), 0.06), transparent 62%),
          radial-gradient(900px 520px at 56% 92%, rgba(var(--bc-violet), 0.06), transparent 64%);
        filter: blur(48px);
        opacity: 0.55;
        pointer-events: none;
        z-index: -1;
      }

      .hero {
        margin: 4px 0 16px;
        /* Hero design tokens (premium clarity) */
        --hero-gap: 12px;
        --hero-radius-lg: 18px;
        --hero-radius-md: 16px;
        --hero-pad: 18px;
        --hero-blur: 14px;
        --hero-saturate: 1.18;
        --hero-glass-top: rgba(7, 11, 22, 0.22);
        --hero-glass-bottom: rgba(7, 11, 22, 0.10);
        --hero-edge-soft: rgba(255, 255, 255, 0.10);
        --hero-edge-amber: rgba(var(--bc-amber), 0.34);
        --hero-edge-teal: rgba(var(--bc-accent2), 0.30);
        --hero-edge-violet: rgba(var(--bc-violet), 0.26);
        --hero-text: rgba(231, 238, 252, 0.96);
        --hero-muted: rgba(159, 176, 208, 0.92);
      }
      /* Make Kernel Capabilities narrower (more vertical, “sidebar” feel) — but not too thin. */
      .heroGrid { display: grid; grid-template-columns: 1.30fr 0.70fr; gap: var(--hero-gap); }
      @media (max-width: 980px) { .heroGrid { grid-template-columns: 1fr; } }
      /* Hero panels: cleaner glass, crisp edges, less fog than generic panels. */
      .hero .panel {
        margin-top: 0;
        padding: var(--hero-pad);
        border-radius: var(--hero-radius-lg);
        border: 1px solid transparent;
        background:
          /* subtle vignette + edge blooms (keeps center clearer) */
          radial-gradient(720px 260px at 10% 22%, rgba(var(--bc-accent2), 0.10), transparent 62%) padding-box,
          radial-gradient(720px 260px at 90% 30%, rgba(var(--bc-violet), 0.10), transparent 66%) padding-box,
          radial-gradient(820px 340px at 50% 110%, rgba(0, 0, 0, 0.26), transparent 64%) padding-box,
          linear-gradient(180deg, var(--hero-glass-top), var(--hero-glass-bottom)) padding-box,
          /* gradient edge */
          linear-gradient(
            90deg,
            var(--hero-edge-soft),
            var(--hero-edge-amber),
            rgba(var(--bc-orange), 0.28),
            var(--hero-edge-teal),
            var(--hero-edge-violet),
            var(--hero-edge-soft)
          ) border-box;
        backdrop-filter: blur(var(--hero-blur)) saturate(var(--hero-saturate));
        -webkit-backdrop-filter: blur(var(--hero-blur)) saturate(var(--hero-saturate));
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.10),
          inset 0 0 0 1px rgba(255, 255, 255, 0.04),
          0 28px 90px rgba(0, 0, 0, 0.40),
          0 0 0 1px rgba(255, 255, 255, 0.05),
          0 0 36px rgba(var(--bc-accent2), 0.06),
          0 0 76px rgba(var(--bc-violet), 0.05);
      }
      .hero .panel::before,
      .hero .panel::after { content: none; }

      /* Setup Overview panel: blue-toned border + subtle thickness variation + inner edge shadow (3D). */
      header.card.hero .panel:first-of-type {
        isolation: isolate;
        /* Override the generic (amber-heavy) edge with a cleaner blue/cyan ring. */
        background:
          radial-gradient(720px 260px at 10% 22%, rgba(var(--bc-accent2), 0.10), transparent 62%) padding-box,
          radial-gradient(720px 260px at 90% 30%, rgba(var(--bc-violet), 0.10), transparent 66%) padding-box,
          radial-gradient(820px 340px at 50% 110%, rgba(0, 0, 0, 0.26), transparent 64%) padding-box,
          linear-gradient(180deg, var(--hero-glass-top), var(--hero-glass-bottom)) padding-box,
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.12),
            rgba(var(--bc-ice), 0.26),
            rgba(var(--bc-accent2), 0.30),
            rgba(var(--bc-accent), 0.22),
            rgba(var(--bc-violet), 0.28),
            rgba(var(--bc-ice), 0.20),
            rgba(255, 255, 255, 0.10)
          ) border-box;
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.10),
          inset 0 0 0 1px rgba(255, 255, 255, 0.05),
          0 28px 90px rgba(0, 0, 0, 0.40),
          0 0 0 1px rgba(255, 255, 255, 0.05),
          0 0 44px rgba(var(--bc-accent2), 0.08),
          0 0 78px rgba(var(--bc-violet), 0.06);
      }
      header.card.hero .panel:first-of-type > * { position: relative; z-index: 1; }

      /* Border thickness “variation”: a thicker, blue accent along the left arc + partial top/bottom segments. */
      header.card.hero .panel:first-of-type::before {
        content: "";
        position: absolute;
        inset: -1px;
        border-radius: inherit;
        z-index: 2;
        padding: 3px;
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        background:
          /* Left arc (full-height, thicker feel) */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.72), rgba(var(--bc-cyan), 0.38), rgba(var(--bc-ice), 0.00)) 0 0 / 92px 100% no-repeat,
          /* Top segment ~68% width; fades out toward the center */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.78), rgba(var(--bc-accent2), 0.44), rgba(var(--bc-ice), 0.00)) 0 0 / 68% 100% no-repeat,
          /* Bottom segment ~40% width; softer */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.52), rgba(var(--bc-accent2), 0.28), rgba(var(--bc-ice), 0.00)) 0 100% / 40% 100% no-repeat;
        filter: drop-shadow(0 0 10px rgba(var(--bc-ice), 0.10)) drop-shadow(0 0 18px rgba(var(--bc-accent2), 0.06));
        opacity: 0.88;
        pointer-events: none;
      }

      /* Inner “edge shadow”: only near the border (no extra background in the center). */
      header.card.hero .panel:first-of-type::after {
        content: "";
        position: absolute;
        inset: 1px;
        border-radius: calc(var(--hero-radius-lg) - 1px);
        z-index: 0;
        background:
          /* Top / bottom inner falloff */
          linear-gradient(180deg, rgba(0, 0, 0, 0.34), rgba(0, 0, 0, 0.00)) 0 0 / 100% 26px no-repeat,
          linear-gradient(0deg, rgba(0, 0, 0, 0.38), rgba(0, 0, 0, 0.00)) 0 100% / 100% 30px no-repeat,
          /* Left / right inner falloff */
          linear-gradient(90deg, rgba(0, 0, 0, 0.36), rgba(0, 0, 0, 0.00)) 0 0 / 30px 100% no-repeat,
          linear-gradient(-90deg, rgba(0, 0, 0, 0.28), rgba(0, 0, 0, 0.00)) 100% 0 / 26px 100% no-repeat;
        opacity: 0.82;
        mix-blend-mode: multiply;
        pointer-events: none;
      }
      .heroBanner {
        position: absolute;
        inset: 0;
        background: url("/_blackcat/assets/hero-banner.png") left center / cover no-repeat;
        opacity: 0.18;
        mix-blend-mode: screen;
        filter: saturate(1.05) contrast(1.05) brightness(1.05);
        pointer-events: none;
        z-index: 0;
      }
      .heroBanner::after {
        content: "";
        position: absolute;
        inset: 0;
        background: linear-gradient(90deg, rgba(11, 15, 23, 0.10), rgba(11, 15, 23, 0.58));
      }

      .heroTitle {
        margin: 0;
        font-size: 29px;
        font-weight: 780;
        letter-spacing: 0.2px;
        color: var(--hero-text);
        text-shadow:
          0 1px 0 rgba(0, 0, 0, 0.78),
          0 10px 34px rgba(0, 0, 0, 0.34);
      }
      .heroBrand {
        font-weight: 860;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        display: block;
        font-size: 18px;
        color: rgba(255, 255, 255, 0.98);
        margin-bottom: 8px;
        text-shadow: 0 1px 0 rgba(0, 0, 0, 0.78);
      }
      .heroTitleLine2 {
        display: block;
        font-size: 34px;
        line-height: 1.1;
        margin-top: 0;
      }
      .heroTitleAccent {
        display: block;
        margin-bottom: 16px;
        font-weight: 900;
        letter-spacing: 0.01em;
        background: linear-gradient(90deg, rgba(var(--bc-accent), 0.92), rgba(var(--bc-accent2), 0.92));
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
        text-shadow: none;
      }
      @supports not (-webkit-background-clip: text) {
        .heroTitleAccent { color: #d7e3ff; }
      }
      .pillKernelWrap {
        --pillKernelRadius: 999px;
        --pillKernelWrapPad: 4px;
        --pillKernelBorderW: 2px;
        position: relative;
        display: inline-flex;
        align-items: center;
        padding: var(--pillKernelWrapPad);
        border-radius: var(--pillKernelRadius);
        isolation: isolate;
        background: rgba(255, 255, 255, 0.02);
        backdrop-filter: blur(8px) saturate(1.15);
        -webkit-backdrop-filter: blur(8px) saturate(1.15);
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.10),
          0 0 0 1px rgba(255, 255, 255, 0.06),
          0 0 18px rgba(var(--bc-ice), 0.10),
          0 0 30px rgba(var(--bc-violet), 0.06),
          0 16px 58px rgba(0, 0, 0, 0.46);
      }
      .pillKernelWrap::before {
        content: "";
        position: absolute;
        inset: 0;
        border-radius: inherit;
        z-index: 2;
        padding: var(--pillKernelBorderW);
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        background:
          /* Left arc + corner boosters (keeps rounded edge uniformly “thick”). */
          radial-gradient(26px 80% at 0 38%, rgba(var(--bc-ice), 0.94), rgba(var(--bc-ice), 0.00) 72%) 0 0 / 40px 100% no-repeat,
          radial-gradient(20px 20px at 6px 6px, rgba(var(--bc-ice), 0.94), rgba(var(--bc-ice), 0.00) 72%) 0 0 / 34px 34px no-repeat,
          radial-gradient(16px 16px at 6px 22px, rgba(var(--bc-ice), 0.60), rgba(var(--bc-ice), 0.00) 72%) 0 100% / 30px 30px no-repeat,
          /* Left “thickness” taper: strongest at top, softer toward bottom. */
          linear-gradient(
            180deg,
            rgba(var(--bc-ice), 0.68) 0%,
            rgba(var(--bc-cyan), 0.26) 55%,
            rgba(var(--bc-ice), 0.00) 100%
          ) 0 0 / 18px 100% no-repeat,
          /* Segment emphasis: top ~65%, bottom ~38% (fades to normal). */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.92), rgba(var(--bc-cyan), 0.62), rgba(var(--bc-ice), 0.00)) 0 0 / 65% 2px no-repeat,
          linear-gradient(90deg, rgba(var(--bc-ice), 0.70), rgba(var(--bc-cyan), 0.44), rgba(var(--bc-ice), 0.00)) 0 100% / 38% 2px no-repeat,
          /* Base border gradient (premium, but confined to the border ring via mask). */
          linear-gradient(
            90deg,
            rgba(var(--bc-orange), 0.56),
            rgba(var(--bc-accent), 0.36),
            rgba(var(--bc-accent2), 0.32),
            rgba(var(--bc-violet), 0.48)
          );
        box-shadow:
          0 0 14px rgba(var(--bc-ice), 0.16),
          0 0 26px rgba(var(--bc-accent), 0.12);
        opacity: 0.95;
        pointer-events: none;
      }
      /* Thick left-accent overlay: ~2× the base border thickness, fading into the thin ring. */
      .pillKernelWrap::after {
        content: "";
        position: absolute;
        inset: calc(var(--pillKernelBorderW) * -1);
        border-radius: calc(var(--pillKernelRadius) + var(--pillKernelBorderW));
        z-index: 3;
        padding: calc(var(--pillKernelBorderW) * 3);
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        background:
          /* Left border: full-thickness along the whole arc, then fades into the thin ring. */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.84), rgba(var(--bc-cyan), 0.48), rgba(var(--bc-ice), 0.00)) 0 0 / 78px 100% no-repeat,
          radial-gradient(18px 18px at 10px 10px, rgba(var(--bc-ice), 0.70), rgba(var(--bc-ice), 0.00) 72%) 0 0 / 38px 38px no-repeat,
          radial-gradient(18px 18px at 10px 26px, rgba(var(--bc-ice), 0.52), rgba(var(--bc-ice), 0.00) 72%) 0 100% / 38px 38px no-repeat,
          /* Top (≈65%) and bottom (≈35–40%) thick accents that fade into the thin border. */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.84), rgba(var(--bc-cyan), 0.54), rgba(var(--bc-ice), 0.00)) 0 0 / 65% calc(var(--pillKernelBorderW) * 3) no-repeat,
          linear-gradient(90deg, rgba(var(--bc-ice), 0.56), rgba(var(--bc-cyan), 0.32), rgba(var(--bc-ice), 0.00)) 0 100% / 38% calc(var(--pillKernelBorderW) * 3) no-repeat;
        filter: drop-shadow(0 0 10px rgba(var(--bc-ice), 0.10));
        opacity: 0.94;
        pointer-events: none;
      }
      .pill.pillKernel {
        position: relative;
        z-index: 1;
        font-size: 16px;
        line-height: 1;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        padding: 9px 12px 9px 42px;
        border-radius: calc(var(--pillKernelRadius) - var(--pillKernelWrapPad));
        overflow: hidden;
        border: 0;
        background:
          radial-gradient(120px 64px at 0% 50%, rgba(var(--bc-ice), 0.16), rgba(var(--bc-ice), 0.00) 70%),
          radial-gradient(220px 90px at 25% 0%, rgba(var(--bc-accent), 0.18), transparent 62%),
          radial-gradient(220px 90px at 75% 0%, rgba(var(--bc-accent2), 0.16), transparent 62%),
          linear-gradient(180deg, rgba(11, 15, 23, 0.22), rgba(11, 15, 23, 0.10));
        color: rgba(255, 255, 255, 0.94);
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.14),
          inset 0 -18px 26px rgba(0, 0, 0, 0.22),
          inset 0 0 0 1px rgba(255, 255, 255, 0.06);
        backdrop-filter: blur(10px) saturate(1.18);
        -webkit-backdrop-filter: blur(10px) saturate(1.18);
      }
      .pill.pillKernel::after {
        content: "";
        position: absolute;
        left: 12px;
        top: 50%;
        width: 14px;
        height: 14px;
        transform: translateY(-50%);
        border-radius: 999px;
        z-index: 0;
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.78), rgba(255, 255, 255, 0.00) 54%),
          linear-gradient(180deg, rgba(var(--bc-accent2), 0.96), rgba(var(--bc-accent), 0.62));
        box-shadow:
          0 0 0 1px rgba(255, 255, 255, 0.16),
          0 0 18px rgba(var(--bc-accent2), 0.16),
          0 0 32px rgba(var(--bc-accent), 0.10);
        pointer-events: none;
      }
      .heroSub {
        margin: 16px 0 0;
        font-size: 17px;
        font-weight: 560;
        letter-spacing: 0.01em;
        color: rgba(231, 238, 252, 0.90);
        text-shadow: 0 1px 0 rgba(0, 0, 0, 0.72);
      }
      .heroSub .heroArrow {
        display: inline-block;
        margin: 0 6px;
        font-weight: 820;
        letter-spacing: 0.04em;
        color: rgba(var(--bc-ice), 0.92);
        text-shadow:
          0 0 12px rgba(var(--bc-ice), 0.16),
          0 0 26px rgba(var(--bc-accent2), 0.10),
          0 10px 28px rgba(0, 0, 0, 0.34);
      }
      .panel strong.overviewTitle {
        display: flex;
        align-items: center;
        gap: 10px;
        margin: 0 0 10px;
        font-size: 16px;
        font-weight: 900;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: rgba(231, 238, 252, 0.94);
        text-shadow: 0 1px 0 rgba(0, 0, 0, 0.78);
      }
      .panel strong.overviewTitle::before {
        content: "";
        width: 12px;
        height: 12px;
        border-radius: 999px;
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.65), rgba(255, 255, 255, 0.00) 48%),
          linear-gradient(180deg, rgba(var(--bc-ice), 0.95), rgba(var(--bc-accent), 0.55));
        box-shadow:
          0 0 0 1px rgba(255, 255, 255, 0.14),
          0 0 16px rgba(255, 255, 255, 0.10),
          0 0 20px rgba(var(--bc-ice), 0.16),
          0 0 40px rgba(var(--bc-accent), 0.12);
        flex: 0 0 12px;
      }
      .panel strong.overviewTitle::after {
        content: "";
        height: 2px;
        flex: 1 1 auto;
        order: 3;
        min-width: 24px;
        margin: 0 0 0 14px;
        background:
          radial-gradient(circle at 0 50%, rgba(var(--bc-ice), 0.50), rgba(var(--bc-ice), 0.00) 64%),
          linear-gradient(
            90deg,
            rgba(var(--bc-ice), 0.00) 0%,
            rgba(var(--bc-ice), 0.22) 10%,
            rgba(var(--bc-accent), 0.28) 45%,
            rgba(var(--bc-cyan), 0.18) 70%,
            rgba(var(--bc-ice), 0.10) 82%,
            rgba(255, 255, 255, 0.00) 100%
          );
        opacity: 0.90;
        box-shadow:
          0 0 12px rgba(var(--bc-accent), 0.10),
          0 0 26px rgba(var(--bc-ice), 0.06);
      }
      .overviewMeta {
        margin-left: 14px;
        order: 2;
        flex: 0 0 auto;
        font-size: 11px;
        letter-spacing: 0.06em;
        text-transform: none;
        color: rgba(231, 238, 252, 0.86);
        white-space: nowrap;
        padding: 0;
        border: 0;
        background: none;
        border-radius: 0;
        clip-path: none;
        box-shadow: none;
        backdrop-filter: none;
        -webkit-backdrop-filter: none;
        font-weight: 650;
        text-shadow:
          0 1px 0 rgba(0, 0, 0, 0.72),
          0 0 14px rgba(var(--bc-ice), 0.08);
      }
      @media (max-width: 980px) {
        .overviewMeta { display: none; }
      }
      .tokenRow {
        display: grid;
        grid-template-columns: 1fr;
        gap: 10px;
      }
      .tokenField {
        position: relative;
        min-width: 0;
      }
      .tokenField::before {
        content: "";
        position: absolute;
        left: 12px;
        top: 50%;
        width: 18px;
        height: 18px;
        transform: translateY(-50%);
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.65), rgba(255, 255, 255, 0.00) 52%),
          linear-gradient(180deg, rgba(var(--bc-amber), 0.92), rgba(var(--bc-accent), 0.50));
        -webkit-mask: var(--bc-mask-glyph-lock) center / contain no-repeat;
        mask: var(--bc-mask-glyph-lock) center / contain no-repeat;
        filter:
          drop-shadow(0 0 18px rgba(var(--bc-amber), 0.10))
          drop-shadow(0 14px 46px rgba(0, 0, 0, 0.34));
        opacity: 0.94;
        pointer-events: none;
      }
      .tokenInput {
        padding-left: 42px !important;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        letter-spacing: 0.08em;
      }
      .tokenInput::placeholder {
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        letter-spacing: 0.02em;
        color: rgba(159, 176, 208, 0.78);
      }
      .tokenActions {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 8px;
      }
      @media (max-width: 520px) {
        .tokenActions { grid-template-columns: 1fr; }
      }
      .tokenActions button { width: 100%; }
      .btnSecondary {
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.10), rgba(22, 35, 66, 0.78));
        border-color: rgba(255, 255, 255, 0.18);
        color: #d7e3ff;
      }
      .btnDanger {
        border-color: rgba(255, 123, 114, 0.35);
        background: linear-gradient(180deg, rgba(255, 123, 114, 0.14), rgba(22, 35, 66, 0.78));
      }
      .tokenStatus {
        --bc-tokenA: var(--bc-amber);
        --bc-tokenB: var(--bc-accent);
        margin-top: 12px;
        display: flex;
        gap: 10px;
        align-items: flex-start;
        flex-wrap: nowrap;
        padding: 10px 12px;
        border-radius: 14px;
        border: 1px solid transparent;
        background:
          linear-gradient(180deg, rgba(8, 10, 18, 0.22), rgba(8, 10, 18, 0.10)) padding-box,
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.14),
            rgba(var(--bc-tokenA), 0.34),
            rgba(var(--bc-tokenB), 0.26),
            rgba(var(--bc-tokenA), 0.18),
            rgba(255, 255, 255, 0.10)
          ) border-box;
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.06),
          inset 0 0 0 1px rgba(255, 255, 255, 0.04),
          0 14px 50px rgba(0, 0, 0, 0.20);
        backdrop-filter: blur(10px) saturate(1.12);
        -webkit-backdrop-filter: blur(10px) saturate(1.12);
      }
      #tokenStatusText { white-space: pre-line; min-width: 0; flex: 1 1 auto; }
      .tokenStatus::before {
        content: "";
        width: 10px;
        height: 10px;
        margin-top: 4px;
        border-radius: 999px;
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.65), rgba(255, 255, 255, 0.00) 48%),
          linear-gradient(180deg, rgba(var(--bc-tokenA), 0.95), rgba(var(--bc-tokenB), 0.55));
        box-shadow:
          0 0 18px rgba(var(--bc-tokenA), 0.12),
          0 0 34px rgba(var(--bc-tokenB), 0.10);
      }
      .tokenStatus.ok { --bc-tokenA: var(--bc-accent2); --bc-tokenB: var(--bc-ice); }
      .tokenStatus.ok::before {
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.65), rgba(255, 255, 255, 0.00) 48%),
          linear-gradient(180deg, rgba(var(--bc-accent2), 0.92), rgba(var(--bc-ice), 0.55));
        box-shadow:
          0 0 18px rgba(var(--bc-accent2), 0.14),
          0 0 34px rgba(var(--bc-ice), 0.10);
      }
      .tokenStatus.warn { --bc-tokenA: var(--bc-amber); --bc-tokenB: var(--bc-orange); }
      .tokenStatus.bad { --bc-tokenA: 255, 123, 114; --bc-tokenB: var(--bc-orange); }
      .tokenStatus.bad::before {
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.65), rgba(255, 255, 255, 0.00) 48%),
          linear-gradient(180deg, rgba(255, 123, 114, 0.92), rgba(var(--bc-orange), 0.55));
        box-shadow:
          0 0 18px rgba(255, 123, 114, 0.14),
          0 0 34px rgba(var(--bc-orange), 0.10);
      }
      .tokenHint {
        margin-left: auto;
        font-size: 11px;
        letter-spacing: 0.06em;
        color: rgba(159, 176, 208, 0.88);
        white-space: nowrap;
      }
      .tokenStatus .tokenHint { flex: 0 0 auto; margin: 0; text-align: right; }

      .miniCard {
        --bc-miniA: var(--bc-amber);
        --bc-miniB: var(--bc-accent);
        border-radius: 14px;
        border: 1px solid transparent;
        background:
          radial-gradient(420px 220px at 18% 0%, rgba(var(--bc-miniA), 0.10), transparent 70%) padding-box,
          radial-gradient(420px 220px at 82% 0%, rgba(var(--bc-miniB), 0.08), transparent 72%) padding-box,
          linear-gradient(180deg, rgba(8, 10, 18, 0.22), rgba(8, 10, 18, 0.10)) padding-box,
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.14),
            rgba(var(--bc-miniA), 0.28),
            rgba(var(--bc-miniB), 0.22),
            rgba(var(--bc-miniA), 0.16),
            rgba(255, 255, 255, 0.10)
          ) border-box;
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.06),
          inset 0 0 0 1px rgba(255, 255, 255, 0.04),
          0 16px 54px rgba(0, 0, 0, 0.20);
        backdrop-filter: blur(10px) saturate(1.10);
        -webkit-backdrop-filter: blur(10px) saturate(1.10);
        overflow: hidden;
      }
      .card.step .miniCard { --bc-miniA: var(--bc-step-glowB); --bc-miniB: var(--bc-step-glow); }
      .miniCardHeader {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 12px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        color: #c9d6f3;
        font-size: 11px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
      }
      .miniCardHeader::before {
        content: "";
        width: 10px;
        height: 10px;
        border-radius: 999px;
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.65), rgba(255, 255, 255, 0.00) 48%),
          linear-gradient(180deg, rgba(var(--bc-miniA), 0.92), rgba(var(--bc-miniB), 0.55));
        box-shadow:
          0 0 18px rgba(var(--bc-miniA), 0.10),
          0 0 34px rgba(var(--bc-miniB), 0.10);
      }
      .miniCardBody {
        padding: 10px 12px 12px;
        color: #9fb0d0;
      }
      .miniTree {
        margin: 0;
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.12);
        background: rgba(8, 10, 18, 0.26);
        color: #c9d6f3;
        font-size: 12px;
        overflow: auto;
      }
      .miniActions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-top: 10px;
      }
      .miniActions button { flex: 1 1 190px; }
      .inlineTip {
        margin-top: 10px;
        font-size: 12px;
        color: #9fb0d0;
      }
      .miniStack { display: grid; gap: 12px; grid-template-columns: 1fr; }
      @media (min-width: 560px) {
        .miniStack { grid-template-columns: 1fr 1.15fr; align-items: start; }
      }
      .overviewGrid {
        display: grid;
        /* Make the illustration column slightly more dominant (matches the intended “hero emblem” look). */
        grid-template-columns: minmax(320px, 1.15fr) 0.85fr;
        grid-template-areas: "art text";
        gap: 16px;
        align-items: center;
      }
      .overviewGrid > div:first-child { grid-area: text; }
      @media (max-width: 860px) {
        .overviewGrid { grid-template-columns: 1fr; }
      }
      .overviewArt {
        grid-area: art;
        border-radius: 18px;
        border: 1px solid transparent;
        background:
          /* Frame fill behind the image (kept subtle for clarity) */
          radial-gradient(520px 260px at 18% 0%, rgba(255, 255, 255, 0.06), transparent 66%) padding-box,
          radial-gradient(520px 260px at 82% 0%, rgba(var(--bc-accent2), 0.10), transparent 66%) padding-box,
          linear-gradient(180deg, rgba(11, 15, 23, 0.22), rgba(11, 15, 23, 0.10)) padding-box,
          /* Edge */
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.10),
            rgba(var(--bc-accent2), 0.32),
            rgba(var(--bc-accent), 0.26),
            rgba(var(--bc-violet), 0.22),
            rgba(255, 255, 255, 0.08)
          ) border-box;
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.10),
          inset 0 0 0 1px rgba(255, 255, 255, 0.05),
          0 26px 90px rgba(0, 0, 0, 0.40),
          0 0 48px rgba(var(--bc-accent2), 0.08);
        overflow: hidden;
        position: relative;
        aspect-ratio: 1 / 1;
        clip-path: polygon(50% 0%, 88% 14%, 88% 62%, 50% 100%, 12% 62%, 12% 14%);
      }
      .overviewArt img {
        width: 100%;
        height: 100%;
        object-fit: cover;
        display: block;
        opacity: 0.96;
        filter: saturate(1.08) contrast(1.08) brightness(1.06);
      }
      .overviewArt.isLogo {
        padding: 0;
        clip-path: none;
        border-radius: 18px;
        border: 0;
        background: transparent;
        box-shadow: none;
        backdrop-filter: none;
        -webkit-backdrop-filter: none;
        overflow: visible;
        display: grid;
        place-items: center;
        perspective: 900px;
        transform-style: preserve-3d;
      }
      .overviewArt.isLogo img {
        width: 96%;
        height: auto;
        max-height: 96%;
        object-fit: contain;
        opacity: 0.98;
        filter: none;
        transform: none;
        position: relative;
        z-index: 2;
        will-change: transform;
      }
      /* Keep ::before free for UI-map labels; use ::after for a subtle halo. */
      .overviewArt.isLogo::before { content: none; }
      .overviewArt.isLogo::after {
        content: "";
        position: absolute;
        inset: -26%;
        z-index: 1;
        pointer-events: none;
        /* Dark vignette to keep the logo “in the dark” (hide hard edges) while the panel
           keeps its light on the RIGHT side. */
        background: radial-gradient(
          closest-side at 50% 50%,
          rgba(0, 0, 0, 0.86) 0%,
          rgba(0, 0, 0, 0.12) 52%,
          rgba(0, 0, 0, 0.00) 74%
        );
        filter: blur(16px);
        opacity: 0.92;
        mix-blend-mode: multiply;
        transform: translate3d(0, 0, -1px);
      }
      @media (prefers-reduced-motion: no-preference) {
        .overviewArt.isLogo img {
          animation: bcLogoFloat 8.5s ease-in-out infinite;
          transform-style: preserve-3d;
        }
        /* Keep only the logo float; the dark vignette stays stable for “clean” readability. */
        .overviewArt.isLogo::after { animation: none; }
        @keyframes bcLogoFloat {
          0%, 100% { transform: translate3d(0, 0, 16px) rotateX(0deg) rotateY(0deg) scale(1); }
          50% { transform: translate3d(0, -6px, 18px) rotateX(2deg) rotateY(-2deg) scale(1.01); }
        }
        @keyframes bcLogoHalo {
          0%, 100% { opacity: 0.18; filter: blur(10px); transform: translate3d(0, 0, -1px) scale(0.995); }
          50% { opacity: 0.26; filter: blur(12px); transform: translate3d(0, -2px, -1px) scale(1.01); }
        }
      }
      .overviewArt::before {
        content: "";
        position: absolute;
        inset: 0;
        background:
          radial-gradient(420px 220px at 14% 12%, rgba(var(--bc-accent), 0.18), transparent 62%),
          radial-gradient(520px 260px at 86% 18%, rgba(var(--bc-accent2), 0.14), transparent 66%),
          radial-gradient(520px 260px at 52% 86%, rgba(var(--bc-violet), 0.10), transparent 68%),
          linear-gradient(180deg, rgba(11, 15, 23, 0.05), rgba(11, 15, 23, 0.55));
        opacity: 0.72;
        pointer-events: none;
      }
      .overviewArt::after {
        content: "";
        position: absolute;
        inset: -40%;
        background: linear-gradient(
          120deg,
          rgba(255, 255, 255, 0.00) 35%,
          rgba(255, 255, 255, 0.10) 50%,
          rgba(255, 255, 255, 0.00) 65%
        );
        transform: translateX(-38%) rotate(12deg);
        opacity: 0;
        pointer-events: none;
      }
      @media (prefers-reduced-motion: no-preference) {
        .overviewArt::after { animation: bcOverviewSheen 14.5s ease-in-out infinite; }
        @keyframes bcOverviewSheen {
          0%, 70% { opacity: 0; transform: translateX(-38%) rotate(12deg); }
          78% { opacity: 0.22; }
          100% { opacity: 0; transform: translateX(42%) rotate(12deg); }
        }
      }
      .panel strong.traitsTitle {
        display: flex;
        align-items: center;
        gap: 10px;
        /* Match Setup overview title styling. */
        margin: 0 0 18px;
        font-size: 16px;
        font-weight: 900;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: rgba(231, 238, 252, 0.94);
        text-shadow: 0 1px 0 rgba(0, 0, 0, 0.78);
      }
      .panel strong.traitsTitle::before {
        content: "";
        width: 12px;
        height: 12px;
        border-radius: 999px;
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.65), rgba(255, 255, 255, 0.00) 48%),
          linear-gradient(180deg, rgba(var(--bc-ice), 0.95), rgba(var(--bc-accent), 0.55));
        box-shadow:
          0 0 0 1px rgba(255, 255, 255, 0.14),
          0 0 16px rgba(255, 255, 255, 0.10),
          0 0 20px rgba(var(--bc-ice), 0.16),
          0 0 40px rgba(var(--bc-accent), 0.12);
        flex: 0 0 12px;
      }
      .panel strong.traitsTitle::after {
        content: "";
        height: 2px;
        flex: 1 1 auto;
        min-width: 24px;
        margin: 0 0 0 14px;
        background:
          radial-gradient(circle at 0 50%, rgba(var(--bc-ice), 0.50), rgba(var(--bc-ice), 0.00) 64%),
          linear-gradient(
            90deg,
            rgba(var(--bc-ice), 0.00) 0%,
            rgba(var(--bc-ice), 0.22) 10%,
            rgba(var(--bc-accent2), 0.26) 45%,
            rgba(var(--bc-cyan), 0.16) 70%,
            rgba(var(--bc-ice), 0.10) 82%,
            rgba(255, 255, 255, 0.00) 100%
          );
        opacity: 0.88;
        box-shadow:
          0 0 12px rgba(var(--bc-accent2), 0.10),
          0 0 26px rgba(var(--bc-ice), 0.06);
      }
      /* Step panels: reuse the same “premium title” pattern as the hero. */
      .steps .panel > strong:first-child {
        display: flex;
        align-items: center;
        gap: 10px;
        margin: 0 0 12px;
        font-size: 14px;
        font-weight: 900;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: rgba(231, 238, 252, 0.94);
        text-shadow: 0 1px 0 rgba(0, 0, 0, 0.78);
      }
      .steps .panel > strong:first-child::before {
        content: "";
        width: 11px;
        height: 11px;
        border-radius: 999px;
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.65), rgba(255, 255, 255, 0.00) 48%),
          linear-gradient(180deg, rgba(var(--bc-panelB), 0.92), rgba(var(--bc-panelA), 0.55));
        box-shadow:
          0 0 0 1px rgba(255, 255, 255, 0.14),
          0 0 14px rgba(255, 255, 255, 0.09),
          0 0 18px rgba(var(--bc-panelB), 0.14),
          0 0 34px rgba(var(--bc-panelA), 0.10);
        flex: 0 0 11px;
      }
      .steps .panel > strong:first-child::after {
        content: "";
        height: 2px;
        flex: 1 1 auto;
        min-width: 22px;
        margin: 0 0 0 14px;
        background:
          radial-gradient(circle at 0 50%, rgba(var(--bc-panelB), 0.48), rgba(var(--bc-panelB), 0.00) 64%),
          linear-gradient(
            90deg,
            rgba(var(--bc-panelB), 0.00) 0%,
            rgba(var(--bc-panelB), 0.20) 10%,
            rgba(var(--bc-panelA), 0.26) 45%,
            rgba(var(--bc-panelB), 0.16) 70%,
            rgba(var(--bc-panelB), 0.10) 82%,
            rgba(255, 255, 255, 0.00) 100%
          );
        opacity: 0.86;
        box-shadow:
          0 0 10px rgba(var(--bc-panelA), 0.08),
          0 0 22px rgba(var(--bc-panelB), 0.06);
      }
      /* (moved) Kernel Capabilities tile system lives in the hero override block below. */
      .heroDetails { margin-top: 10px; }
      .heroDetails summary {
        cursor: pointer;
        user-select: none;
        display: inline-flex;
        align-items: center;
        gap: 10px;
        padding: 8px 10px;
        border-radius: 14px;
        border: 1px solid rgba(31, 42, 68, 0.62);
        background: linear-gradient(180deg, rgba(11, 15, 23, 0.22), rgba(11, 15, 23, 0.12));
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.06),
          0 14px 50px rgba(0, 0, 0, 0.22);
      }
      .heroDetails summary::-webkit-details-marker { display: none; }
      .heroDetails summary::before { content: "▸"; display: inline-block; margin-right: 8px; color: #9fb0d0; }
      .heroDetails[open] summary::before { content: "▾"; }
      .heroDetails ul { margin: 10px 0 0 18px; padding: 0; }
      .heroDetails li { margin: 5px 0; }

      .illustration {
        margin-top: 12px;
        border-radius: 14px;
        overflow: hidden;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.35);
      }
      .illustration img { display: block; width: 100%; height: auto; }
      .illustration .cap {
        padding: 10px 12px;
        font-size: 12px;
        color: #9fb0d0;
        border-top: 1px solid rgba(31, 42, 68, 0.95);
      }

      .card {
        position: relative;
        border-radius: 18px;
        border: 1px solid rgba(31, 42, 68, 0.86);
        padding: 16px;
        margin: 12px 0;
        background:
          radial-gradient(900px 420px at 18% 0%, rgba(255, 255, 255, 0.07), transparent 62%),
          radial-gradient(900px 420px at 82% 0%, rgba(var(--bc-accent2), 0.10), transparent 66%),
          linear-gradient(180deg, rgba(15, 21, 36, 0.62), rgba(15, 21, 36, 0.30));
        backdrop-filter: blur(18px) saturate(1.25);
        -webkit-backdrop-filter: blur(18px) saturate(1.25);
        box-shadow:
          0 30px 100px rgba(0, 0, 0, 0.45),
          0 0 0 1px rgba(var(--bc-accent), 0.10),
          0 0 40px rgba(var(--bc-accent), 0.12),
          0 0 90px rgba(var(--bc-accent2), 0.06);
        overflow: hidden;
      }
      .cardBorder {
        position: absolute;
        inset: 0;
        border-radius: 18px;
        pointer-events: none;
        z-index: 0;
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
          rgba(var(--bc-accent), 0.28),
          rgba(var(--bc-accent2), 0.22),
          rgba(var(--bc-amber), 0.14),
          rgba(var(--bc-accent), 0.00)
        );
        -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask-composite: exclude;
        opacity: 0.9;
        transform-origin: 50% 50%;
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
      .card > *:not(.cardBorder) { position: relative; z-index: 1; }

      @media (prefers-reduced-motion: no-preference) {
        .cardBorder::before {
          animation: bcBorderSpin 46s linear infinite;
          will-change: transform;
        }
        @keyframes bcBorderSpin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      }

      h2 {
        margin: 0 0 10px;
        font-size: 16px;
        font-weight: 780;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #d7e3ff;
        text-shadow:
          0 1px 0 rgba(0, 0, 0, 0.72),
          0 18px 70px rgba(0, 0, 0, 0.42);
        padding-right: 52px;
      }
      h2::after {
        content: "";
        display: block;
        height: 1px;
        margin-top: 10px;
        background: linear-gradient(
          90deg,
          rgba(var(--bc-accent), 0.00),
          rgba(var(--bc-accent), 0.34),
          rgba(var(--bc-accent2), 0.24),
          rgba(var(--bc-accent2), 0.00)
        );
        opacity: 0.85;
      }

      .panel {
        /* Panel surface tokens (all panels) */
        --bc-panelA: var(--bc-accent);
        --bc-panelB: var(--bc-accent2);
        --bc-panel-border-w: 1px;
        --bc-panel-blur: 10px;
        margin-top: 12px;
        padding: 12px 14px;
        border-radius: 14px;
        border: var(--bc-panel-border-w) solid transparent;
        background:
          radial-gradient(520px 220px at 18% 0%, rgba(var(--bc-panelA), 0.11), transparent 70%) padding-box,
          radial-gradient(520px 220px at 82% 0%, rgba(var(--bc-panelB), 0.09), transparent 72%) padding-box,
          linear-gradient(180deg, rgba(8, 10, 18, 0.26), rgba(8, 10, 18, 0.10)) padding-box,
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.16),
            rgba(var(--bc-panelA), 0.30),
            rgba(var(--bc-panelB), 0.24),
            rgba(var(--bc-panelA), 0.18),
            rgba(255, 255, 255, 0.10)
          ) border-box;
        backdrop-filter: blur(var(--bc-panel-blur)) saturate(1.18);
        -webkit-backdrop-filter: blur(var(--bc-panel-blur)) saturate(1.18);
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.08),
          inset 0 0 0 1px rgba(255, 255, 255, 0.04),
          0 0 0 1px rgba(var(--bc-panelA), 0.07);
        position: relative;
        overflow: hidden;
      }
      /* Panels inside step cards inherit that step's palette. */
      .card.step .panel { --bc-panelA: var(--bc-step-glowB); --bc-panelB: var(--bc-step-glow); }
      .card.step .panel:first-of-type { margin-top: 0; }
      .panel::before {
        content: "";
        position: absolute;
        inset: -1px;
        background:
          linear-gradient(
            90deg,
            rgba(var(--bc-panelA), 0.00),
            rgba(var(--bc-panelA), 0.18),
            rgba(var(--bc-panelB), 0.14),
            rgba(var(--bc-panelB), 0.00)
          ),
          radial-gradient(520px 220px at 50% 0%, rgba(255, 255, 255, 0.06), transparent 64%);
        opacity: 0.34;
        pointer-events: none;
      }
      .panel::after {
        content: "";
        position: absolute;
        inset: 1px;
        border-radius: 13px;
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.10),
          inset 0 -18px 34px rgba(0, 0, 0, 0.18);
        opacity: 0.82;
        pointer-events: none;
      }
      .panel > * { position: relative; z-index: 1; }
	      /* Panel section headings: unify with the Setup Overview title (dot + rail). */
	      .panel > strong:not(.overviewTitle):not(.traitsTitle) {
	        display: flex;
	        align-items: center;
	        gap: 10px;
	        margin: 0 0 10px;
	        font-size: 16px;
	        font-weight: 900;
	        letter-spacing: 0.12em;
	        text-transform: uppercase;
	        color: rgba(231, 238, 252, 0.94);
	        text-shadow: 0 1px 0 rgba(0, 0, 0, 0.78);
	      }
	      .panel > strong:not(.overviewTitle):not(.traitsTitle)::before {
	        content: "";
	        width: 12px;
	        height: 12px;
	        border-radius: 999px;
	        background:
	          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.65), rgba(255, 255, 255, 0.00) 48%),
	          linear-gradient(180deg, rgba(var(--bc-ice), 0.95), rgba(var(--bc-accent), 0.55));
	        box-shadow:
	          0 0 0 1px rgba(255, 255, 255, 0.14),
	          0 0 16px rgba(255, 255, 255, 0.10),
	          0 0 20px rgba(var(--bc-ice), 0.16),
	          0 0 40px rgba(var(--bc-accent), 0.12);
	        flex: 0 0 12px;
	      }
	      .panel > strong:not(.overviewTitle):not(.traitsTitle)::after {
	        content: "";
	        height: 2px;
	        flex: 1 1 auto;
	        min-width: 24px;
	        margin: 0 0 0 14px;
	        background:
	          radial-gradient(circle at 0 50%, rgba(var(--bc-ice), 0.50), rgba(var(--bc-ice), 0.00) 64%),
	          linear-gradient(
	            90deg,
	            rgba(var(--bc-ice), 0.00) 0%,
	            rgba(var(--bc-ice), 0.22) 10%,
	            rgba(var(--bc-accent), 0.28) 45%,
	            rgba(var(--bc-cyan), 0.18) 70%,
	            rgba(var(--bc-ice), 0.10) 82%,
	            rgba(255, 255, 255, 0.00) 100%
	          );
	        opacity: 0.90;
	        box-shadow:
	          0 0 12px rgba(var(--bc-accent), 0.10),
	          0 0 26px rgba(var(--bc-ice), 0.06);
	      }

      .row { display: flex; gap: 12px; flex-wrap: wrap; }
      .row > * { flex: 1 1 320px; }

      .ok { color: #76e39d; }
      .bad { color: #ff7b72; }
      .muted { color: #9fb0d0; }
      .warn { color: #ffd46b; }

      button {
        position: relative;
        overflow: hidden;
        background: linear-gradient(180deg, rgba(var(--bc-accent), 0.26), rgba(22, 35, 66, 0.92));
        color: #e7eefc;
        border: 1px solid rgba(var(--bc-accent), 0.32);
        border-radius: 12px;
        padding: 10px 12px;
        cursor: pointer;
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.14),
          inset 0 -14px 22px rgba(0, 0, 0, 0.24),
          0 16px 52px rgba(0, 0, 0, 0.34),
          0 0 0 1px rgba(var(--bc-accent), 0.06);
        transition: transform .12s ease, filter .15s ease, border-color .15s ease, opacity .15s ease;
      }
      button::before {
        content: "";
        position: absolute;
        inset: -40% -20%;
        background: linear-gradient(120deg, rgba(255, 255, 255, 0.00), rgba(255, 255, 255, 0.16), rgba(255, 255, 255, 0.00));
        transform: translateX(-55%) rotate(12deg);
        opacity: 0.55;
        pointer-events: none;
      }
      button:hover { transform: translateY(-1px); filter: brightness(1.05) saturate(1.02); border-color: rgba(var(--bc-accent), 0.44); }
      button:hover::before { transform: translateX(10%) rotate(12deg); transition: transform .55s ease; }
      button:active { transform: translateY(0px); filter: brightness(1.0); }
      button:disabled { opacity: 0.55; cursor: not-allowed; }
      button:disabled::before { opacity: 0.0; }
      button:focus-visible {
        outline: none;
        box-shadow:
          0 0 0 3px rgba(var(--bc-accent), 0.22),
          0 16px 52px rgba(0, 0, 0, 0.34);
      }

      input, textarea, select {
        --bc-fieldA: var(--bc-accent);
        --bc-fieldB: var(--bc-ice);
        width: 100%;
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid transparent;
        background:
          radial-gradient(520px 220px at 18% 0%, rgba(var(--bc-fieldA), 0.10), transparent 70%) padding-box,
          radial-gradient(520px 220px at 82% 0%, rgba(var(--bc-fieldB), 0.08), transparent 72%) padding-box,
          linear-gradient(180deg, rgba(8, 10, 18, 0.26), rgba(8, 10, 18, 0.10)) padding-box,
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.14),
            rgba(var(--bc-fieldA), 0.26),
            rgba(var(--bc-fieldB), 0.20),
            rgba(var(--bc-fieldA), 0.14),
            rgba(255, 255, 255, 0.10)
          ) border-box;
        color: #e7eefc;
        outline: none;
        backdrop-filter: blur(9px) saturate(1.10);
        -webkit-backdrop-filter: blur(9px) saturate(1.10);
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.06),
          inset 0 0 0 1px rgba(255, 255, 255, 0.04),
          0 10px 38px rgba(0, 0, 0, 0.18);
      }
      /* In panels, inputs inherit the panel palette. */
      .panel input, .panel textarea, .panel select { --bc-fieldA: var(--bc-panelA); --bc-fieldB: var(--bc-panelB); }
      input:focus, textarea:focus, select:focus {
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.08),
          inset 0 0 0 1px rgba(255, 255, 255, 0.05),
          0 0 0 3px rgba(var(--bc-fieldA), 0.16),
          0 18px 70px rgba(0, 0, 0, 0.32),
          0 0 34px rgba(var(--bc-fieldA), 0.10);
      }
      textarea { min-height: 96px; }

	      .steps { display: flex; flex-direction: column; gap: 12px; }
	      .steps .card { margin: 0; }
	      /* “Path” spacing between panels */
	      .stepsLanes { display: flex; flex-direction: column; gap: 12px; }
	      .adventureGutter { display: none; }
	      .stepsLane {
	        display: flex;
	        flex-direction: column;
	        gap: 22px;
	        position: relative;
        padding: 14px 0;
        /* Path anchor (mobile centers; desktop overrides to a fixed “route” x). */
        --bc-path-left: 50%;
        --bc-path-shift: -50%;
      }
      .stepsLane > .card { position: relative; z-index: 1; }

      /* Decorative lane path: subtle neon line + nodes visible mainly in the gaps */
      .stepsLaneLeft { --bc-laneA: var(--bc-orange); --bc-laneB: var(--bc-ice); --bc-laneC: var(--bc-violet); --bc-pathW: 3px; }
      .stepsLaneRight { --bc-laneA: var(--bc-accent2); --bc-laneB: var(--bc-violet); --bc-laneC: var(--bc-orange); --bc-pathW: 3px; }

      .stepsLane::before {
        content: "";
        position: absolute;
        top: 0;
        bottom: 0;
        left: var(--bc-path-left);
        width: var(--bc-pathW, 3px);
        transform: translateX(var(--bc-path-shift));
        background:
          /* Overall color journey */
          linear-gradient(
            180deg,
            rgba(var(--bc-laneA), 0.00),
            rgba(var(--bc-laneA), 0.20) 16%,
            rgba(var(--bc-laneB), 0.16) 52%,
            rgba(var(--bc-laneC), 0.18) 86%,
            rgba(var(--bc-laneC), 0.00)
          ),
          /* “Trail” dashes (reads like a path between panels) */
          repeating-linear-gradient(
            180deg,
            rgba(255, 255, 255, 0.22) 0 7px,
            rgba(255, 255, 255, 0.00) 7px 18px
          );
        background-blend-mode: screen;
        opacity: 0.70;
        pointer-events: none;
        z-index: 0;
        filter:
          drop-shadow(0 0 10px rgba(var(--bc-laneB), 0.12))
          drop-shadow(0 0 20px rgba(var(--bc-laneA), 0.10));
        -webkit-mask-image: linear-gradient(180deg, transparent, #000 12%, #000 88%, transparent);
        mask-image: linear-gradient(180deg, transparent, #000 12%, #000 88%, transparent);
      }
      .stepsLane::after {
        content: "";
        position: absolute;
        top: 0;
        bottom: 0;
        left: var(--bc-path-left);
        width: 28px;
        transform: translateX(var(--bc-path-shift));
        pointer-events: none;
        z-index: 0;
        /* Waypoints: repeated beads + subtle sparkles */
        background:
          radial-gradient(9px 9px at 50% 52%, rgba(var(--bc-laneA), 0.32), rgba(var(--bc-laneA), 0.00) 72%) 0 0 / 100% 140px repeat-y,
          radial-gradient(9px 9px at 50% 52%, rgba(var(--bc-laneB), 0.28), rgba(var(--bc-laneB), 0.00) 72%) 0 40px / 100% 180px repeat-y,
          radial-gradient(9px 9px at 50% 52%, rgba(var(--bc-laneC), 0.26), rgba(var(--bc-laneC), 0.00) 72%) 0 90px / 100% 220px repeat-y,
          /* Micro sparkles */
          radial-gradient(1px 1px at 30% 22%, rgba(255, 255, 255, 0.18) 0 1px, transparent 2px) 0 0 / 180px 180px repeat,
          radial-gradient(1px 1px at 60% 44%, rgba(255, 255, 255, 0.14) 0 1px, transparent 2px) 0 0 / 260px 260px repeat;
        opacity: 0.86;
        filter: blur(0.1px);
      }

      /* “Adventure spacing”: intentionally varied gaps (reads like stages on a journey) */
      .stepsLaneLeft .step4 { margin-top: 16px; }
      .stepsLaneLeft .step5 { margin-top: 10px; }
      .stepsLaneRight .step6 { margin-top: 14px; }

      /* Note: we intentionally keep the “path” on the lane background only.
         If we render per-card bridges, they will appear “through” glass cards on some browsers. */
      .hudProgress {
        --hud-progress: 0;
        /* HUD tuning (easy to tweak) */
        /* Keep the fill mostly neutral + transparent so step colors do the talking. */
        --hud-glass-top: rgba(7, 11, 22, 0.052);
        --hud-glass-bottom: rgba(7, 11, 22, 0.018);
        /* Premium clarity: less blur so the grid stays readable (still glassy). */
        --hud-blur: 8px;
        --hud-saturate: 1.25;
        /* Edge palette: subtle spectrum (steps are the focus). */
        --hud-edge-soft: rgba(255, 255, 255, 0.10);
        --hud-edge-amber: rgba(var(--bc-amber), 0.62);
        --hud-edge-orange: rgba(var(--bc-orange), 0.58);
        --hud-edge-teal: rgba(var(--bc-accent2), 0.54);
        --hud-edge-violet: rgba(var(--bc-violet), 0.54);
        --hud-gap: 22px;
        --hud-gap-half: 11px;
        /* Small gap between the line end and the orb (kept tight; glow bridges it). */
        --hud-join-gap: 2px;
        --hud-orb: 10px;
        --hud-orb-half: 5px;
        --hud-line-h: 2.5px;
        margin: 2px 0 14px;
      }
      .hudFrame {
        position: relative;
        border-radius: 14px;
        /* A slightly thicker gradient border reads closer to the reference HUD. */
        border: 2px solid transparent;
        outline: none;
        background:
          /* Glass fill (premium clarity): keep it dark + transparent so the grid reads through. */
          radial-gradient(1200px 280px at 50% -40px, rgba(255, 255, 255, 0.035), transparent 72%) padding-box,
          radial-gradient(900px 320px at 50% 140%, rgba(0, 0, 0, 0.10), transparent 72%) padding-box,
          linear-gradient(180deg, var(--hud-glass-top), var(--hud-glass-bottom)) padding-box,
          /* HUD gradient edge (thin + premium, warm palette) */
          linear-gradient(
            90deg,
            var(--hud-edge-soft),
            rgba(var(--bc-amber), 0.58),
            var(--hud-edge-amber),
            var(--hud-edge-orange),
            var(--hud-edge-red),
            var(--hud-edge-orange),
            var(--hud-edge-amber),
            rgba(var(--bc-amber), 0.52),
            var(--hud-edge-soft)
          ) border-box;
        backdrop-filter: blur(var(--hud-blur)) saturate(var(--hud-saturate));
        -webkit-backdrop-filter: blur(var(--hud-blur)) saturate(var(--hud-saturate));
        box-shadow:
          /* Glass highlights */
          inset 0 1px 0 rgba(255, 255, 255, 0.18),
          inset 0 0 0 1px rgba(255, 255, 255, 0.06),
          /* Keep the base dark enough for readability, but not “muddy/opaque” */
          inset 0 -26px 90px rgba(0, 0, 0, 0.14),
          0 26px 110px rgba(0, 0, 0, 0.62),
          0 0 0 1px rgba(255, 255, 255, 0.06),
          /* Edge glow to “lift” the panel from the grid */
          0 0 14px rgba(255, 255, 255, 0.05),
          0 0 42px rgba(var(--bc-amber), 0.11),
          0 0 78px rgba(var(--bc-orange), 0.10),
          0 0 120px rgba(255, 92, 92, 0.06);
        /* Vivid but subtle outer neon (kept small for performance). */
        filter:
          drop-shadow(0 0 14px rgba(var(--bc-orange), 0.12))
          drop-shadow(0 0 18px rgba(var(--bc-amber), 0.08));
        overflow: hidden;
      }
      .hudFrame::before {
        content: "";
        position: absolute;
        /* Do not cover the gradient edge. */
        inset: 2px;
        border-radius: 12px;
        background:
          /* ultra-subtle speckle + top highlight only (avoid tinting the whole bar) */
          radial-gradient(circle at 22px 18px, rgba(255, 255, 255, 0.14) 0 1px, transparent 2px) 0 0 / 180px 180px,
          radial-gradient(circle at 130px 160px, rgba(255, 255, 255, 0.10) 0 1px, transparent 2px) 0 0 / 280px 280px,
          /* Edge light blooms (kept near edges so the center stays transparent) */
          radial-gradient(600px 220px at 8% 40%, rgba(var(--bc-orange), 0.06), transparent 66%),
          radial-gradient(650px 240px at 92% 44%, rgba(var(--bc-amber), 0.05), transparent 68%),
          radial-gradient(900px 300px at 50% 0%, rgba(255, 255, 255, 0.08), transparent 70%),
          linear-gradient(180deg, rgba(255, 255, 255, 0.06), transparent 60%);
        opacity: 0.07;
        mix-blend-mode: screen;
        pointer-events: none;
      }
      .hudFrame::after {
        content: "";
        position: absolute;
        inset: 2px;
        border-radius: 12px;
        background:
          /* Inner highlight */
          linear-gradient(180deg, rgba(255, 255, 255, 0.12), rgba(255, 255, 255, 0.00) 42%),
          /* Slim “rail” with color hints */
          linear-gradient(
            90deg,
            rgba(var(--bc-amber), 0.00),
            rgba(var(--bc-amber), 0.22),
            rgba(var(--bc-orange), 0.22),
            rgba(255, 92, 92, 0.18),
            rgba(var(--bc-orange), 0.16),
            rgba(var(--bc-amber), 0.00)
          ) 0 78% / 100% 2px no-repeat,
          /* Slow sheen sweep */
          linear-gradient(115deg, rgba(255, 255, 255, 0.00) 0 26%, rgba(255, 255, 255, 0.10) 42%, rgba(255, 255, 255, 0.00) 62%);
        opacity: 0.12;
        transform: translateX(-22%);
        pointer-events: none;
      }
      @media (prefers-reduced-motion: no-preference) {
        .hudFrame::after { animation: bcHudSweep 7.2s ease-in-out infinite; }
        @keyframes bcHudSweep {
          0%, 100% { transform: translateX(-28%); opacity: 0.24; }
          50% { transform: translateX(8%); opacity: 0.36; }
        }
      }
      .hudTrack {
        list-style: none;
        margin: 0;
        padding: 12px 18px;
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: var(--hud-gap);
        position: relative;
        align-items: center;
      }
      @media (max-width: 920px) {
        .hudProgress { --hud-gap: 18px; --hud-gap-half: 9px; }
        .hudTrack { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      }
      @media (max-width: 520px) {
        .hudTrack { grid-template-columns: 1fr; }
      }
	      /* Disable the old full-width rail. We render per-step segments instead (closer to the reference). */
	      /* A subtle “spectrum rail” sits behind the per-step segments, and it “fills” with progress. */
	      .hudTrack { position: relative; z-index: 1; }
	      .hudTrack::before,
	      .hudTrack::after {
	        content: "";
	        position: absolute;
	        /* Turn the old 2px rail into a subtle “progress bed” behind the steps. */
	        inset: 8px 14px;
	        border-radius: 14px;
	        background: linear-gradient(
	          90deg,
	          rgba(var(--bc-amber), 0.00) 0%,
	          rgba(var(--bc-amber), 0.32) 12%,
	          rgba(var(--bc-orange), 0.30) 42%,
	          rgba(var(--bc-accent2), 0.26) 68%,
	          rgba(var(--bc-violet), 0.28) 92%,
	          rgba(var(--bc-violet), 0.00) 100%
	        );
	        pointer-events: none;
	        z-index: 0;
	        mix-blend-mode: screen;
	      }
	      .hudTrack::before {
	        /* Ambient: keep it subtle so the background stays readable. */
	        opacity: 0.14;
	        filter: blur(1.2px);
	      }
	      .hudTrack::after {
	        /* Progress fill: brighter + “glassier”, scaled by --hud-progress. */
	        opacity: 0.46;
	        transform: scaleX(var(--hud-progress));
	        transform-origin: 0 50%;
	        filter:
	          drop-shadow(0 0 16px rgba(var(--bc-amber), 0.14))
	          drop-shadow(0 0 26px rgba(var(--bc-accent2), 0.10));
	      }
	      @media (prefers-reduced-motion: no-preference) {
	        .hudTrack::after { animation: bcHudPulse 5.6s ease-in-out infinite; }
	        @keyframes bcHudPulse {
	          0%, 100% { opacity: 0.85; filter: drop-shadow(0 0 12px rgba(var(--bc-accent), 0.14)) drop-shadow(0 0 22px rgba(var(--bc-accent2), 0.08)); }
	          50% { opacity: 1.0; filter: drop-shadow(0 0 18px rgba(var(--bc-accent), 0.18)) drop-shadow(0 0 34px rgba(var(--bc-accent2), 0.12)); }
	        }
	      }
	      @media (max-width: 920px) { .hudTrack::before, .hudTrack::after { inset: 10px 12px; } }
	      @media (max-width: 520px) { .hudTrack::before, .hudTrack::after { inset: 10px 10px; } }
	      .hudItem {
	        --hud-step-glow: var(--bc-accent);
	        --hud-glyph-mask: var(--bc-mask-glyph-lock);
        --hud-step-line-a: 0.18;
        --hud-step-line-b: 0.12;
        --hud-step-line-strong: 0.28;
        --hud-step-bg-a: rgba(11, 15, 23, 0.16);
        --hud-step-bg-b: rgba(11, 15, 23, 0.06);
        /* Current-only “L” border sweep (top/bottom fade from the left) */
        --hud-step-edgeTop-len: 0%;
        --hud-step-edgeBot-len: 0%;
        --hud-step-edgeTop-h: 0px;
        --hud-step-edgeBot-h: 0px;
        --hud-step-edgeTop-a1: 0.00;
        --hud-step-edgeTop-a2: 0.00;
        --hud-step-edgeBot-a1: 0.00;
        --hud-step-edgeBot-a2: 0.00;
        --hud-step-edgeWhite-a: 0.00;
        /* Strong left border + subtle “emit” glow */
        /* Default (non-current): disabled */
        --hud-step-left-w: 0px;
        --hud-step-left-glow-w: 0px;
        --hud-step-left-a-edge: 0.00;
        --hud-step-left-a: 0.00;
        --hud-step-left-a-peak: 0.00;
        --hud-step-left-glow-a: 0.00;
        --hud-step-left-highlight-a: 0.00;
        --hud-step-left-cap-a: 0.00;
        --hud-step-left-arc-a: 0.00;
        --hud-step-left-shadow-a1: 0.00;
        --hud-step-left-shadow-a2: 0.00;
        /* Border “strength” is state-driven (current > ready > locked). */
        --hud-step-border-strong: 0.34;
        --hud-step-border-weak: 0.18;
        --hud-step-border-white: 0.12;
        /* Layout tuning: bring the icon closer to the edge without making tiles taller. */
        --hud-step-pad-y: 7px;
        --hud-step-pad-left: 6px;
        --hud-step-pad-right: 10px;
        --hud-icon-size: 54px;
	        display: flex;
	        gap: 12px;
	        align-items: center;
	        padding: var(--hud-step-pad-y) var(--hud-step-pad-right) var(--hud-step-pad-y) var(--hud-step-pad-left);
	        border-radius: 12px;
	        /* Steps are intentionally “borderless” here: the progress bed lives under them. */
	        border: 0;
	        background: none;
	        box-shadow: none;
	        backdrop-filter: none;
	        -webkit-backdrop-filter: none;
	        position: relative;
	        overflow: visible;
	        min-width: 0;
	      }
      .hudItem > * { position: relative; z-index: 1; }
      /* Per-step connector segments (reference-style): each step connects to the next orb only when completed. */
      .hudItem:not(:last-child)::before {
        content: "";
        position: absolute;
        top: 50%;
        transform: translate3d(0, -50%, 0);
        /* Geometry starts at the icon edge; the left half is faded out via gradients below. */
        left: calc(var(--hud-step-pad-left) + var(--hud-icon-size));
        right: calc(-1 * var(--hud-gap) + var(--hud-orb) + var(--hud-join-gap)); /* default: stop before the orb */
        /* Reserve enough height so the line can “thicken” towards the orb. */
        height: max(var(--hud-line-h), 6px);
        border-radius: 999px;
        background:
          /* Bright node at end (feeds into the orb glow) */
          radial-gradient(
            16px 16px at 100% 50%,
            rgba(255, 255, 255, 0.99),
            rgba(var(--hud-step-glow), 0.98) 44%,
            rgba(var(--hud-step-glow), 0.00) 76%
          ) 100% 50% / 16px 16px no-repeat,
          /* Base line (thin): invisible until ~55%, then ramps into the orb */
          linear-gradient(
            90deg,
            rgba(var(--hud-step-glow), 0.00) 0%,
            rgba(var(--hud-step-glow), 0.00) 55%,
            rgba(var(--hud-step-glow), 0.22) 66%,
            rgba(var(--hud-step-glow), 0.38) 78%,
            rgba(var(--hud-step-glow), 0.62) 92%,
            rgba(var(--hud-step-glow), 0.66) 100%
          ) 0 50% / 100% var(--hud-line-h) no-repeat,
          /* Mid boost A (thicker, starts later) */
          linear-gradient(
            90deg,
            rgba(var(--hud-step-glow), 0.00) 0%,
            rgba(var(--hud-step-glow), 0.00) 40%,
            rgba(var(--hud-step-glow), 0.34) 70%,
            rgba(var(--hud-step-glow), 0.62) 100%
          ) 100% 50% / 72% 3px no-repeat,
          /* Mid boost B (stronger near the end) */
          linear-gradient(
            90deg,
            rgba(var(--hud-step-glow), 0.00) 0%,
            rgba(var(--hud-step-glow), 0.00) 34%,
            rgba(var(--hud-step-glow), 0.24) 56%,
            rgba(var(--hud-step-glow), 0.54) 84%,
            rgba(var(--hud-step-glow), 0.00) 100%
          ) 100% 50% / 58% 4px no-repeat,
          /* End boost (thickest + brightest right at the orb) */
          linear-gradient(
            90deg,
            rgba(var(--hud-step-glow), 0.00) 0%,
            rgba(var(--hud-step-glow), 0.00) 42%,
            rgba(var(--hud-step-glow), 0.44) 62%,
            rgba(var(--hud-step-glow), 0.92) 100%
          ) 100% 50% / 34% 6px no-repeat,
          /* White highlight, ramps into the orb */
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.00) 0%,
            rgba(255, 255, 255, 0.00) 60%,
            rgba(255, 255, 255, 0.10) 76%,
            rgba(255, 255, 255, 0.38) 100%
          ) 0 50% / 100% 1px no-repeat;
        opacity: 0.0; /* default: not connected */
        filter:
          drop-shadow(0 0 18px rgba(var(--hud-step-glow), 0.46))
          drop-shadow(0 0 40px rgba(var(--hud-step-glow), 0.26))
          drop-shadow(0 0 78px rgba(var(--hud-step-glow), 0.16))
          drop-shadow(0 0 28px rgba(255, 255, 255, 0.12));
        mix-blend-mode: screen;
        pointer-events: none;
        z-index: 0;
      }

      /* Orb in the middle between steps (endpoint). */
      .hudItem:not(:last-child)::after {
        content: "";
        position: absolute;
        top: 50%;
        /* Place the orb close to the next step (end of the gap), like the reference. */
        right: calc(-1 * var(--hud-gap));
        transform: translate3d(0, -50%, 0);
        width: var(--hud-orb);
        height: var(--hud-orb);
        border-radius: 999px;
        background:
          /* Core orb highlight */
          radial-gradient(
            circle at 35% 30%,
            rgba(255, 255, 255, 0.97),
            rgba(255, 255, 255, 0.28) 18%,
            rgba(var(--hud-step-glow), 1.00) 42%,
            rgba(var(--hud-step-glow), 0.28) 66%,
            rgba(var(--hud-step-glow), 0.00) 82%
          );
        box-shadow:
          0 0 0 1px rgba(var(--hud-step-glow), 0.36),
          0 0 22px rgba(var(--hud-step-glow), 0.58),
          0 0 62px rgba(var(--hud-step-glow), 0.42),
          0 0 108px rgba(var(--hud-step-glow), 0.22),
          /* Tail glow to the LEFT (merges with the segment) */
          -10px 0 28px rgba(var(--hud-step-glow), 0.30),
          -18px 0 62px rgba(var(--hud-step-glow), 0.22),
          0 0 20px rgba(255, 255, 255, 0.12);
        opacity: 0.44;
        pointer-events: none;
        z-index: 2;
        mix-blend-mode: screen;
      }

      /* Segment states:
         - READY: connected to the orb (full segment)
         - CURRENT / IN PROGRESS: shows a partial segment (stops before orb)
         - LOCKED: no segment, dim orb
      */
      .hudItem.is-ready:not(:last-child)::before { opacity: 0.90; }
      .hudItem.is-ready:not(:last-child)::after { opacity: 1.00; }

      .hudItem.is-current:not(:last-child)::before,
      .hudItem.is-progress:not(:last-child)::before {
        right: calc(-1 * var(--hud-gap) + var(--hud-orb) + var(--hud-join-gap)); /* stop before the orb */
      }
      .hudItem.is-current:not(:last-child)::before { opacity: 0.84; }
      .hudItem.is-progress:not(:last-child)::before { opacity: 0.76; }
      .hudItem.is-current:not(:last-child)::after { opacity: 0.82; }
      .hudItem.is-progress:not(:last-child)::after { opacity: 0.72; }

      .hudItem.is-locked:not(:last-child)::before { opacity: 0.0; }
      .hudItem.is-locked:not(:last-child)::after { opacity: 0.22; filter: saturate(0.70); }

      /* When a step is READY, connect the segment all the way to the orb. */
      .hudItem.is-ready:not(:last-child)::before {
        right: calc(-1 * var(--hud-gap) + var(--hud-orb-half));
      }

      .hudItem.is-current {
        filter: saturate(1.12) brightness(1.06);
      }
      .hudItem.is-current {
        --hud-step-line-a: 0.28;
        --hud-step-line-b: 0.20;
        --hud-step-line-strong: 0.40;
        --hud-step-bg-a: rgba(var(--hud-step-glow), 0.11);
        --hud-step-bg-b: rgba(11, 15, 23, 0.05);
        --hud-step-border-strong: 0.46;
        --hud-step-border-weak: 0.26;
        --hud-step-border-white: 0.16;
        /* Left edge highlight (CURRENT only): use inset shadows to keep perfect rounded corners. */
        --hud-step-left-w: 0px;
        --hud-step-left-glow-w: 0px;
        --hud-step-left-a-edge: 0.00;
        --hud-step-left-a: 0.00;
        --hud-step-left-a-peak: 0.00;
        --hud-step-left-glow-a: 0.00;
        --hud-step-left-highlight-a: 0.00;
        --hud-step-left-cap-a: 0.00;
        --hud-step-left-arc-a: 0.00;
        --hud-step-left-shadow-a1: 0.10;
        --hud-step-left-shadow-a2: 0.07;
        /* Top/bottom sweep to “round” the left corner and fade into the step */
        --hud-step-edgeTop-len: 72%;
        --hud-step-edgeBot-len: 40%;
        --hud-step-edgeTop-h: 3px;
        --hud-step-edgeBot-h: 3px;
        --hud-step-edgeTop-a1: 0.72;
        --hud-step-edgeTop-a2: 0.26;
        --hud-step-edgeBot-a1: 0.66;
        --hud-step-edgeBot-a2: 0.22;
        --hud-step-edgeWhite-a: 0.10;
        border-color: transparent;
        box-shadow: none;
      }
      .hudItem.is-current .hudTitle { color: rgba(231, 238, 252, 0.98); }
      .hudItem.is-current .hudIcon::before {
        filter:
          drop-shadow(0 0 22px rgba(var(--hud-step-glow), 0.26))
          drop-shadow(0 0 48px rgba(var(--hud-step-glow), 0.16))
          drop-shadow(0 18px 70px rgba(0, 0, 0, 0.44));
      }
      .hudItem.is-locked {
        opacity: 0.78;
        filter: saturate(0.80);
      }
      .hudItem.is-locked {
        --hud-step-line-a: 0.06;
        --hud-step-line-b: 0.05;
        --hud-step-line-strong: 0.08;
        --hud-step-bg-a: rgba(11, 15, 23, 0.12);
        --hud-step-bg-b: rgba(11, 15, 23, 0.04);
        --hud-step-border-strong: 0.10;
        --hud-step-border-weak: 0.07;
        --hud-step-border-white: 0.06;
        border-color: transparent;
      }
      @media (prefers-reduced-motion: no-preference) {
        .hudItem.is-current:not(:last-child)::after { animation: bcHudOrbPulse 2.2s ease-in-out infinite; }
        .hudItem.is-progress:not(:last-child)::after { animation: bcHudOrbPulse 2.8s ease-in-out infinite; }
        .hudItem.is-current:not(:last-child)::before { animation: bcHudLinkPulse 3.8s ease-in-out infinite; }
        .hudItem.is-progress:not(:last-child)::before { animation: bcHudLinkPulse 4.6s ease-in-out infinite; }
        @keyframes bcHudOrbPulse {
          0%, 100% { transform: translate3d(0, -50%, 0) scale(1.0); opacity: 0.74; }
          50% { transform: translate3d(0, -50%, 0) scale(1.10); opacity: 0.96; }
        }
        @keyframes bcHudLinkPulse {
          0%, 100% { filter: drop-shadow(0 0 12px rgba(var(--hud-step-glow), 0.12)) drop-shadow(0 0 18px rgba(var(--hud-step-glow), 0.08)); }
          50% { filter: drop-shadow(0 0 16px rgba(var(--hud-step-glow), 0.16)) drop-shadow(0 0 26px rgba(var(--hud-step-glow), 0.10)); }
        }
      }
      @media (max-width: 920px) {
        .hudItem::before,
        .hudItem::after { content: none; }
      }
      .hudIcon {
        width: var(--hud-icon-size);
        height: var(--hud-icon-size);
        flex: 0 0 var(--hud-icon-size);
        position: relative;
        transform: translateZ(0) translateY(-1px);
        margin-left: -1px; /* tiny nudge towards the left edge (premium alignment) */
        border-radius: 16px;
        border: 0;
        background:
          radial-gradient(circle at 32% 26%, rgba(255, 255, 255, 0.16), rgba(255, 255, 255, 0.00) 62%),
          radial-gradient(circle at 55% 130%, rgba(var(--hud-step-glow), 0.14), rgba(var(--hud-step-glow), 0.00) 70%),
          linear-gradient(180deg, rgba(11, 15, 23, 0.18), rgba(11, 15, 23, 0.03));
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.16),
          inset 0 -18px 36px rgba(0, 0, 0, 0.22),
          0 18px 60px rgba(0, 0, 0, 0.52),
          0 0 30px rgba(var(--hud-step-glow), 0.16),
          0 0 62px rgba(var(--hud-step-glow), 0.10);
      }
      .hudItem.is-current .hudIcon { transform: translateZ(0) translateY(-1px) scale(1.06); }
      .hudItem.is-locked .hudIcon { opacity: 0.76; }
      .hudIcon::before {
        content: "";
        position: absolute;
        inset: 0;
        background:
          radial-gradient(circle at 35% 30%, rgba(255, 255, 255, 0.22), rgba(255, 255, 255, 0.00) 58%),
          radial-gradient(circle at 50% 120%, rgba(var(--hud-step-glow), 0.12), rgba(var(--hud-step-glow), 0.00) 70%),
          linear-gradient(180deg, rgba(10, 14, 26, 0.82), rgba(10, 14, 26, 0.42));
        -webkit-mask: var(--bc-mask-glyph-shield) center / contain no-repeat;
        mask: var(--bc-mask-glyph-shield) center / contain no-repeat;
        filter:
          drop-shadow(0 0 20px rgba(var(--hud-step-glow), 0.26))
          drop-shadow(0 0 44px rgba(var(--hud-step-glow), 0.16))
          drop-shadow(0 18px 70px rgba(0, 0, 0, 0.44));
        opacity: 0.96;
      }
      .hudIcon::after {
        content: "";
        position: absolute;
        inset: 12px;
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.78), rgba(255, 255, 255, 0.00) 56%),
          linear-gradient(180deg, rgba(var(--hud-step-glow), 0.88), rgba(var(--hud-step-glow), 0.28));
        -webkit-mask: var(--hud-glyph-mask) center / contain no-repeat;
        mask: var(--hud-glyph-mask) center / contain no-repeat;
        filter:
          drop-shadow(0 0 14px rgba(var(--hud-step-glow), 0.14))
          drop-shadow(0 14px 52px rgba(0, 0, 0, 0.34));
        opacity: 0.96;
      }
      .hudItem[data-hud="chain"] .hudIcon::after {
        content: "3";
        inset: 0;
        display: grid;
        place-items: center;
        background: none;
        -webkit-mask: none;
        mask: none;
        font-weight: 950;
        font-size: 20px;
        letter-spacing: 0.02em;
        color: rgba(231, 238, 252, 0.96);
        text-shadow:
          0 0 18px rgba(var(--hud-step-glow), 0.18),
          0 18px 70px rgba(0, 0, 0, 0.45);
      }
      .hudText { min-width: 0; }
      .hudTitle {
        font-weight: 760;
        font-size: 16px;
        letter-spacing: 0.02em;
        text-transform: none;
        line-height: 1.2;
        color: #e7eefc;
        text-shadow:
          0 1px 0 rgba(0, 0, 0, 0.78),
          0 18px 70px rgba(0, 0, 0, 0.42);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .hudBadge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 4px 10px;
        margin-top: 6px;
        border-radius: 10px;
        border: 1px solid transparent;
        position: relative;
        overflow: hidden;
        background:
          linear-gradient(180deg, rgba(11, 15, 23, 0.18), rgba(11, 15, 23, 0.06)) padding-box,
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.12),
            rgba(var(--hud-step-glow), 0.22),
            rgba(255, 255, 255, 0.08)
          ) border-box;
        font-weight: 900;
        font-size: 10px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: #9fb0d0;
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.08),
          0 0 18px rgba(var(--hud-step-glow), 0.08);
      }
      .hudItem.is-current .hudBadge::before {
        content: "";
        position: absolute;
        inset: -80% -90%;
        background: linear-gradient(
          115deg,
          rgba(255, 255, 255, 0.00) 0%,
          rgba(255, 255, 255, 0.00) 38%,
          rgba(255, 255, 255, 0.22) 50%,
          rgba(255, 255, 255, 0.00) 62%,
          rgba(255, 255, 255, 0.00) 100%
        );
        opacity: 0.42;
        transform: translateX(-18%) rotate(8deg);
        pointer-events: none;
      }
      @media (prefers-reduced-motion: no-preference) {
        .hudItem.is-current .hudBadge::before { animation: bcHudBadgeSheen 4.8s ease-in-out infinite; }
        @keyframes bcHudBadgeSheen {
          0%, 100% { transform: translateX(-22%) rotate(8deg); opacity: 0.34; }
          50% { transform: translateX(18%) rotate(8deg); opacity: 0.52; }
        }
      }
      .hudItem.is-locked .hudBadge { color: #9fb0d0; }
      .hudItem.is-ready .hudBadge {
        color: rgba(var(--hud-step-glow), 0.98);
        background:
          linear-gradient(180deg, rgba(var(--hud-step-glow), 0.12), rgba(11, 15, 23, 0.08)) padding-box,
          linear-gradient(90deg, rgba(255, 255, 255, 0.14), rgba(var(--hud-step-glow), 0.34), rgba(255, 255, 255, 0.08)) border-box;
      }
      .hudItem.is-progress .hudBadge {
        color: rgba(var(--hud-step-glow), 0.98);
        background:
          linear-gradient(180deg, rgba(var(--hud-step-glow), 0.14), rgba(11, 15, 23, 0.08)) padding-box,
          linear-gradient(90deg, rgba(255, 255, 255, 0.14), rgba(var(--hud-step-glow), 0.36), rgba(255, 255, 255, 0.08)) border-box;
      }
      .hudItem.is-current .hudBadge {
        color: rgba(var(--hud-step-glow), 1.0);
        background:
          linear-gradient(180deg, rgba(var(--hud-step-glow), 0.18), rgba(11, 15, 23, 0.08)) padding-box,
          linear-gradient(90deg, rgba(255, 255, 255, 0.18), rgba(var(--hud-step-glow), 0.44), rgba(255, 255, 255, 0.10)) border-box;
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.10),
          0 0 22px rgba(var(--hud-step-glow), 0.14);
      }
      .hudItem[data-hud="unlock"] { --hud-step-glow: var(--bc-amber); --hud-glyph-mask: var(--bc-mask-glyph-key); }
      .hudItem[data-hud="integrity"] { --hud-step-glow: var(--bc-orange); --hud-glyph-mask: var(--bc-mask-glyph-layers); }
      .hudItem[data-hud="chain"] { --hud-step-glow: var(--bc-accent2); --hud-glyph-mask: var(--bc-mask-glyph-chain); }
      .hudItem[data-hud="done"] { --hud-step-glow: var(--bc-violet); --hud-glyph-mask: var(--bc-mask-glyph-lock); }

	      .step {
	        isolation: isolate;
	        /* Per-step accent used across badges + borders. */
	        --bc-step-glow: var(--bc-accent);
	        --bc-step-glowB: var(--bc-ice);
	      }
	      .step[data-lane="chain"] { --bc-step-glow: var(--bc-accent2); --bc-step-glowB: var(--bc-cyan); }
	      .step[data-step="1"] { --bc-step-glow: var(--bc-amber); --bc-step-glowB: var(--bc-orange); }
	      .step[data-step="2"] { --bc-step-glow: var(--bc-orange); --bc-step-glowB: var(--bc-amber); }
	      .step[data-step="4"] { --bc-step-glow: var(--bc-ice); --bc-step-glowB: var(--bc-cyan); }
	      .step[data-step="5"] { --bc-step-glow: var(--bc-violet); --bc-step-glowB: var(--bc-cyan); }
	      .step[data-step="6"] { --bc-step-glow: 255, 123, 114; --bc-step-glowB: var(--bc-orange); }

	      /* STEP cards: match the Setup Overview “black glass” feel + premium edge lines.
	         Colors are driven by --bc-step-glow / --bc-step-glowB. */
	      .card.step {
	        border: 1px solid transparent;
	        border-color: transparent !important;
	        background:
	          radial-gradient(900px 420px at 86% 16%, rgba(255, 255, 255, 0.045), transparent 72%),
	          radial-gradient(720px 420px at 14% 100%, rgba(var(--bc-step-glow), 0.06), transparent 68%),
	          linear-gradient(180deg, rgba(0, 0, 0, 0.18), rgba(0, 0, 0, 0.06));
	        box-shadow:
	          inset 0 1px 0 rgba(255, 255, 255, 0.10),
	          inset 0 0 0 1px rgba(255, 255, 255, 0.04),
	          inset 0 0 18px rgba(0, 0, 0, 0.34),
	          0 22px 70px rgba(0, 0, 0, 0.44),
	          0 0 0 1px rgba(var(--bc-step-glowB), 0.06),
	          0 0 46px rgba(var(--bc-step-glow), 0.05);
	      }
	      .card.step > .cardBorder { display: block !important; }
	      .card.step > .cardBorder { border-radius: 18px; z-index: 0; }
	      .card.step > .cardBorder::before,
	      .card.step > .cardBorder::after {
	        animation: none !important;
	        transform: none !important;
	        will-change: auto;
	      }
	      /* Thin ring */
	      .card.step > .cardBorder::before {
	        content: "";
	        position: absolute;
	        inset: 0;
	        border-radius: inherit;
	        padding: 1px;
	        -webkit-mask:
	          linear-gradient(#000 0 0) content-box,
	          linear-gradient(#000 0 0);
	        -webkit-mask-composite: xor;
	        mask:
	          linear-gradient(#000 0 0) content-box,
	          linear-gradient(#000 0 0);
	        mask-composite: exclude;
	        background: linear-gradient(
	          90deg,
	          rgba(255, 255, 255, 0.14),
	          rgba(var(--bc-step-glowB), 0.22),
	          rgba(var(--bc-step-glow), 0.30),
	          rgba(var(--bc-step-glowB), 0.18),
	          rgba(255, 255, 255, 0.10)
	        );
	        opacity: 0.98;
	        pointer-events: none;
	      }
	      /* Thickness variation (left arc + top/bottom segments) */
	      .card.step > .cardBorder::after {
	        content: "";
	        position: absolute;
	        inset: -2px;
	        border-radius: calc(18px + 1px);
	        padding: 4px;
	        -webkit-mask:
	          linear-gradient(#000 0 0) content-box,
	          linear-gradient(#000 0 0);
	        -webkit-mask-composite: xor;
	        mask:
	          linear-gradient(#000 0 0) content-box,
	          linear-gradient(#000 0 0);
	        mask-composite: exclude;
	        background:
	          /* Left arc (thick) */
	          linear-gradient(90deg, rgba(var(--bc-step-glow), 0.78), rgba(var(--bc-step-glowB), 0.36), rgba(var(--bc-step-glow), 0.00)) 0 0 / 150px 100% no-repeat,
	          /* Top (~62%) + bottom (~40%) accents */
	          linear-gradient(90deg, rgba(var(--bc-step-glow), 0.64), rgba(var(--bc-step-glowB), 0.30), rgba(var(--bc-step-glow), 0.00)) 0 0 / 62% 100% no-repeat,
	          linear-gradient(90deg, rgba(var(--bc-step-glowB), 0.44), rgba(var(--bc-step-glow), 0.20), rgba(var(--bc-step-glowB), 0.00)) 0 100% / 40% 100% no-repeat,
	          /* Bottom-left tint (subtle) */
	          radial-gradient(44px 44px at 0 100%, rgba(var(--bc-step-glow), 0.22), rgba(var(--bc-step-glowB), 0.12) 42%, rgba(var(--bc-step-glowB), 0.00) 78%) 0 100% / 190px 190px no-repeat,
	          /* Nodes */
	          radial-gradient(6px 6px at 22% 0%, rgba(var(--bc-step-glowB), 0.58), rgba(var(--bc-step-glowB), 0.00) 70%),
	          radial-gradient(6px 6px at 40% 100%, rgba(var(--bc-step-glow), 0.54), rgba(var(--bc-step-glow), 0.00) 70%);
	        filter:
	          drop-shadow(0 0 14px rgba(var(--bc-step-glowB), 0.10))
	          drop-shadow(0 0 20px rgba(var(--bc-step-glow), 0.06));
	        opacity: 0.90;
	        pointer-events: none;
	      }

	      /* STEP 1 (Unlock installer): match the Setup Overview "black glass" feel + premium edge lines. */
	      .card.step.step1 {
	        border: 1px solid transparent;
	        border-color: transparent !important;
	        background:
	          radial-gradient(900px 420px at 86% 16%, rgba(255, 255, 255, 0.045), transparent 72%),
	          linear-gradient(180deg, rgba(0, 0, 0, 0.18), rgba(0, 0, 0, 0.06));
	        box-shadow:
	          inset 0 1px 0 rgba(255, 255, 255, 0.10),
	          inset 0 0 0 1px rgba(255, 255, 255, 0.04),
	          inset 0 0 18px rgba(0, 0, 0, 0.34),
	          0 22px 70px rgba(0, 0, 0, 0.44),
	          0 0 0 1px rgba(var(--bc-amber), 0.06),
	          0 0 46px rgba(var(--bc-orange), 0.05);
	      }
	      .card.step.step1 > .cardBorder { display: block !important; }
	      .card.step.step1 > .cardBorder { border-radius: 18px; z-index: 0; }
	      .card.step.step1 > .cardBorder::before,
	      .card.step.step1 > .cardBorder::after {
	        animation: none !important;
	        transform: none !important;
	        will-change: auto;
	      }
	      /* Thin ring */
	      .card.step.step1 > .cardBorder::before {
	        content: "";
	        position: absolute;
	        inset: 0;
	        border-radius: inherit;
	        padding: 1px;
	        -webkit-mask:
	          linear-gradient(#000 0 0) content-box,
	          linear-gradient(#000 0 0);
	        -webkit-mask-composite: xor;
	        mask:
	          linear-gradient(#000 0 0) content-box,
	          linear-gradient(#000 0 0);
	        mask-composite: exclude;
	        background: linear-gradient(
	          90deg,
	          rgba(255, 255, 255, 0.14),
	          rgba(var(--bc-amber), 0.30),
	          rgba(var(--bc-orange), 0.24),
	          rgba(var(--bc-amber), 0.18),
	          rgba(255, 255, 255, 0.10)
	        );
	        opacity: 0.98;
	        pointer-events: none;
	      }
	      /* Thickness variation (left arc + top/bottom segments) */
	      .card.step.step1 > .cardBorder::after {
	        content: "";
	        position: absolute;
	        inset: -2px;
	        border-radius: calc(18px + 1px);
	        padding: 4px;
	        -webkit-mask:
	          linear-gradient(#000 0 0) content-box,
	          linear-gradient(#000 0 0);
	        -webkit-mask-composite: xor;
	        mask:
	          linear-gradient(#000 0 0) content-box,
	          linear-gradient(#000 0 0);
	        mask-composite: exclude;
	        background:
	          /* Left arc: full thickness across the rounding, then fade into the thin ring */
	          linear-gradient(90deg, rgba(var(--bc-amber), 0.78), rgba(var(--bc-orange), 0.36), rgba(var(--bc-amber), 0.00)) 0 0 / 150px 100% no-repeat,
	          /* Top (~62%) accent */
	          linear-gradient(90deg, rgba(var(--bc-amber), 0.64), rgba(var(--bc-orange), 0.30), rgba(var(--bc-amber), 0.00)) 0 0 / 62% 100% no-repeat,
	          /* Bottom (~40%) accent */
	          linear-gradient(90deg, rgba(var(--bc-amber), 0.44), rgba(var(--bc-orange), 0.22), rgba(var(--bc-amber), 0.00)) 0 100% / 40% 100% no-repeat,
	          /* Bottom-left warm tint (ties into the overall HERO palette) */
	          radial-gradient(44px 44px at 0 100%, rgba(255, 123, 114, 0.24), rgba(var(--bc-orange), 0.14) 40%, rgba(var(--bc-orange), 0.00) 78%) 0 100% / 190px 190px no-repeat,
	          /* Nodes */
	          radial-gradient(6px 6px at 22% 0%, rgba(var(--bc-amber), 0.58), rgba(var(--bc-amber), 0.00) 70%),
	          radial-gradient(6px 6px at 40% 100%, rgba(var(--bc-orange), 0.54), rgba(var(--bc-orange), 0.00) 70%);
	        filter:
	          drop-shadow(0 0 14px rgba(var(--bc-amber), 0.10))
	          drop-shadow(0 0 20px rgba(var(--bc-orange), 0.06));
	        opacity: 0.90;
	        pointer-events: none;
	      }
      /* Step corner badge removed (titles live inside the panels; keep cards clean). */

	      @media (min-width: 1100px) {
        /* Two independent lanes: avoid CSS grid “row coupling” so the left lane does not get pushed down
           when the right lane is taller. This keeps Finalize directly below Runtime config. */
        .stepsLanes {
          display: grid;
          position: relative;
          /* Narrower left lane, plus a dedicated “adventure gutter” between lanes for visuals. */
          grid-template-columns: minmax(360px, 0.77fr) minmax(56px, 110px) minmax(460px, 1.04fr);
          gap: 22px;
          align-items: start;
        }
	        .stepsLaneLeft { grid-column: 1; padding-left: 44px; --bc-path-left: 18px; --bc-path-shift: 0px; }
	        .stepsLaneRight { grid-column: 3; padding-left: 52px; --bc-path-left: 24px; --bc-path-shift: 0px; }

	        /* Desktop: the adventure route is the connection; hide the per-lane vertical “trail”. */
	        .stepsLane::before,
	        .stepsLane::after { content: none; }

	        /* “Adventure route” overlay (spans across both lanes; drawn behind cards). */
	        .adventureGutter {
	          display: block;
	          position: absolute;
	          inset: 0;
	          z-index: 0;
	          overflow: visible;
	          pointer-events: none;
	        }

	        /* Curved route + progress: rendered as SVG so we can do real curves + arrow. */
	        .adventureSvg {
	          position: absolute;
	          inset: 0;
	          width: 100%;
	          height: 100%;
	          display: block;
	          pointer-events: none;
	        }
	        .adventureSvg #adventureStopA { stop-color: rgb(var(--bc-adventure-from)); }
	        .adventureSvg #adventureStopB { stop-color: rgb(var(--bc-adventure-to)); }
	        .adventureSvg .adventureArrow { fill: rgba(var(--bc-adventure-to), 0.60); }
	        .adventureSvg .routeTrack {
	          fill: none;
	          stroke: rgba(255, 255, 255, 0.26);
	          stroke-width: 2.4;
	          stroke-linecap: round;
	          stroke-dasharray: 6 14;
	          opacity: 0.82;
	          filter:
	            drop-shadow(0 0 10px rgba(255, 255, 255, 0.08))
	            drop-shadow(0 0 22px rgba(var(--bc-ice), 0.10));
	        }
	        .adventureSvg .routeProgress {
	          fill: none;
	          stroke: url(#bcAdventureGrad);
	          stroke-width: 3.2;
	          stroke-linecap: round;
	          /* Show only the first “progress” fraction of the route. */
	          stroke-dasharray: var(--bc-adventure-progress, 0) 1;
	          opacity: 0.96;
	          filter:
	            drop-shadow(0 0 10px rgba(var(--bc-adventure-from), 0.22))
	            drop-shadow(0 0 24px rgba(var(--bc-adventure-to), 0.16));
	          transition: stroke-dasharray .38s ease;
	        }
	        @media (prefers-reduced-motion: no-preference) {
	          .adventureSvg .routeTrack { animation: bc_route_dash 9s linear infinite; }
	        }
	        @keyframes bc_route_dash {
	          from { stroke-dashoffset: 0; }
	          to { stroke-dashoffset: -48; }
	        }

	        /* “Where you are” marker: cat emblem that follows the progress. */
	        .adventureGutter::after {
	          content: "";
	          position: absolute;
	          left: calc(var(--bc-adventure-marker-x, 50) * 1%);
	          top: calc(var(--bc-adventure-marker-y, 12) * 1%);
	          transform: translate(-50%, -50%);
	          width: 26px;
	          height: 26px;
	          background:
	            radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.70), rgba(255, 255, 255, 0.00) 48%),
	            linear-gradient(180deg, rgba(var(--bc-adventure-from), 0.92), rgba(var(--bc-adventure-to), 0.52));
	          -webkit-mask: var(--bc-mask-cat-head) center / contain no-repeat;
	          mask: var(--bc-mask-cat-head) center / contain no-repeat;
	          filter:
	            drop-shadow(0 0 12px rgba(var(--bc-adventure-from), 0.26))
	            drop-shadow(0 0 26px rgba(var(--bc-adventure-to), 0.18))
	            drop-shadow(0 18px 60px rgba(0, 0, 0, 0.35));
	          opacity: 0.96;
	          pointer-events: none;
	          transition: top .38s ease;
	        }
	      }

      .k { font-weight: 650; }

      .pill {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        background: linear-gradient(180deg, rgba(var(--bc-accent), 0.30), rgba(var(--bc-accent), 0.12));
        border: 1px solid rgba(var(--bc-accent), 0.44);
        color: rgba(var(--bc-accent), 0.95);
        letter-spacing: 0.03em;
        text-shadow:
          0 1px 0 rgba(0, 0, 0, 0.72),
          0 10px 40px rgba(0, 0, 0, 0.35);
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.18),
          inset 0 -12px 20px rgba(0, 0, 0, 0.36),
          0 0 0 1px rgba(var(--bc-accent), 0.08),
          0 16px 52px rgba(0, 0, 0, 0.34);
      }
      .pill.ok {
        background: linear-gradient(180deg, rgba(118, 227, 157, 0.22), rgba(118, 227, 157, 0.10));
        border-color: rgba(118, 227, 157, 0.34);
        color: #76e39d;
      }
      .pill.bad {
        background: linear-gradient(180deg, rgba(255, 123, 114, 0.22), rgba(255, 123, 114, 0.10));
        border-color: rgba(255, 123, 114, 0.34);
        color: #ff7b72;
      }

      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      .small { font-size: 12px; }

      .tlsBar {
        position: fixed;
        left: 0;
        right: 0;
        bottom: 0;
        z-index: 9999;
        padding: 10px 14px;
        background: rgba(255, 123, 114, 0.14);
        border-top: 1px solid rgba(255, 123, 114, 0.35);
        color: #ffb4ae;
        text-align: center;
        backdrop-filter: blur(10px);
      }
      .tlsBar strong { color: #ff7b72; }

      /* =========================
         RESET: WHITE GLASS SURFACES
         We’re rebuilding the UI from a clean, consistent baseline:
         - white/translucent backgrounds
         - white border lines
         ========================= */
      /* Remove “rainbow/aurora” background blooms so we can rebuild calmly. */
      body {
        background: linear-gradient(180deg, #050712 0%, #070b18 52%, #050614 100%) !important;
      }
      body::after,
      .wrap::before { opacity: 0 !important; }

      /* Kill iridescent container borders/banners in reset mode (we're rebuilding). */
      .cardBorder { display: none !important; }
      .heroBanner { display: none !important; }
      body[data-ui-map="1"] .hudFrame { filter: none !important; }

      /* HERO edge accents (top teal/blue, bottom orange/red with blue separators).
         Use the existing `.cardBorder` element as a pure “edge overlay” only for the HERO card. */
      header.card.hero {
        --heroCardRadius: 22px;
        border-radius: var(--heroCardRadius);
      }
      header.card.hero > .cardBorder { display: block !important; }
      header.card.hero > .cardBorder { border-radius: var(--heroCardRadius); }
      /* Ensure HERO edge lines sit above the HERO border rings. */
      header.card.hero > .cardBorder { z-index: 1; }
      header.card.hero > .cardBorder::before,
      header.card.hero > .cardBorder::after {
        /* Override legacy `.cardBorder::*` that used `inset: 1px` etc. */
        top: auto;
        right: auto;
        bottom: auto;
        left: auto;
        animation: none !important;
        will-change: auto;
        -webkit-mask: none !important;
        mask: none !important;
        -webkit-mask-composite: unset !important;
      }
      header.card.hero > .cardBorder::before {
        content: "";
        position: absolute;
        left: 0;
        right: 0;
        top: 0;
        height: 2.5px;
        border-radius: 22px 22px 16px 16px;
        background:
          /* Main highlight (slightly off-center for a more “alive” feel) */
          radial-gradient(380px 10px at 60% 50%, rgba(var(--bc-cyan), 0.92), rgba(var(--bc-cyan), 0.00) 72%),
          /* Secondary micro-bursts (very subtle; avoids perfect symmetry) */
          radial-gradient(160px 8px at 26% 50%, rgba(var(--bc-ice), 0.20), rgba(var(--bc-ice), 0.00) 72%),
          radial-gradient(140px 8px at 84% 50%, rgba(var(--bc-accent), 0.16), rgba(var(--bc-accent), 0.00) 72%),
          /* Thin “energy line” that fades to edges */
          linear-gradient(
            90deg,
            rgba(var(--bc-accent), 0.00) 0%,
            rgba(var(--bc-ice), 0.22) 18%,
            rgba(var(--bc-cyan), 0.76) 60%,
            rgba(var(--bc-ice), 0.22) 86%,
            rgba(var(--bc-accent), 0.00) 100%
          );
        opacity: 0.92;
        filter: blur(0.10px);
        box-shadow:
          0 0 0 1px rgba(var(--bc-cyan), 0.14),
          0 0 14px rgba(255, 255, 255, 0.08),
          0 0 28px rgba(var(--bc-cyan), 0.30),
          0 0 60px rgba(var(--bc-accent), 0.18);
        pointer-events: none;
        mix-blend-mode: screen;
      }

      /* HERO outer border rings (border-only; no background/shadow changes). */
      header.card.hero {
        position: relative;
        border: 1px solid transparent;
        border-color: transparent !important;
      }
      header.card.hero::after {
        content: "";
        position: absolute;
        inset: 0;
        border-radius: inherit;
        z-index: 0;
        padding: 1px; /* thin base ring */
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        background:
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.10),
            rgba(var(--bc-ice), 0.18),
            rgba(var(--bc-cyan), 0.22),
            rgba(var(--bc-accent2), 0.22),
            rgba(var(--bc-violet), 0.18),
            rgba(var(--bc-ice), 0.14),
            rgba(255, 255, 255, 0.08)
          );
        opacity: 0.82;
        pointer-events: none;
      }
      /* Thick accent segments (no UI-map label conflict: only in normal mode). */
      body[data-ui-map="0"] header.card.hero::before {
        content: "";
        position: absolute;
        inset: 0;
        border-radius: inherit;
        z-index: 0;
        padding: 3px; /* thicker accents */
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        background:
          /* Left arc emphasis (thicker in the rounding, fades inwards) */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.62), rgba(var(--bc-cyan), 0.28), rgba(var(--bc-ice), 0.00)) 0 0 / 160px 100% no-repeat,
          /* Top segment (~62%) */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.50), rgba(var(--bc-cyan), 0.22), rgba(var(--bc-ice), 0.00)) 0 0 / 62% 100% no-repeat,
          /* Bottom warm segment (~38%) */
          linear-gradient(90deg, rgba(var(--bc-orange), 0.00), rgba(var(--bc-orange), 0.24), rgba(255, 123, 114, 0.28), rgba(var(--bc-orange), 0.00)) 0 100% / 38% 100% no-repeat,
          /* Subtle right-top cool segment */
          linear-gradient(90deg, rgba(var(--bc-violet), 0.00), rgba(var(--bc-violet), 0.22), rgba(var(--bc-violet), 0.00)) 100% 0 / 26% 100% no-repeat,
          /* Nodes (connector beads) */
          radial-gradient(6px 6px at 18% 0%, rgba(var(--bc-ice), 0.60), rgba(var(--bc-ice), 0.00) 70%),
          radial-gradient(6px 6px at 62% 0%, rgba(var(--bc-cyan), 0.60), rgba(var(--bc-cyan), 0.00) 70%),
          radial-gradient(6px 6px at 38% 100%, rgba(var(--bc-orange), 0.56), rgba(var(--bc-orange), 0.00) 70%),
          radial-gradient(6px 6px at 82% 100%, rgba(var(--bc-ice), 0.40), rgba(var(--bc-ice), 0.00) 70%);
        opacity: 0.70;
        pointer-events: none;
      }
      header.card.hero > .cardBorder::after {
        content: "";
        position: absolute;
        left: 0;
        right: 0;
        bottom: 0;
        height: 2.5px;
        border-radius: 16px 16px 22px 22px;
        background:
          /* “Energy line”: fades in → peaks in the middle → fades out.
             Add a few warm/cool “bursts” (no vertical separators). */
          radial-gradient(360px 12px at 58% 50%, rgba(255, 123, 114, 0.76), rgba(255, 123, 114, 0.00) 72%),
          radial-gradient(170px 12px at 34% 50%, rgba(var(--bc-orange), 0.56), rgba(var(--bc-orange), 0.00) 72%),
          radial-gradient(170px 12px at 72% 50%, rgba(var(--bc-orange), 0.50), rgba(var(--bc-orange), 0.00) 72%),
          radial-gradient(120px 12px at 44% 50%, rgba(var(--bc-accent), 0.32), rgba(var(--bc-accent), 0.00) 72%),
          radial-gradient(120px 12px at 82% 50%, rgba(var(--bc-ice), 0.24), rgba(var(--bc-ice), 0.00) 72%),
          linear-gradient(
            90deg,
            rgba(var(--bc-orange), 0.00) 0%,
            rgba(var(--bc-orange), 0.18) 18%,
            rgba(255, 123, 114, 0.30) 50%,
            rgba(var(--bc-orange), 0.18) 82%,
            rgba(var(--bc-orange), 0.00) 100%
          );
        opacity: 0.94;
        filter: blur(0.10px);
        box-shadow:
          0 0 0 1px rgba(var(--bc-orange), 0.14),
          0 0 14px rgba(255, 255, 255, 0.06),
          0 0 26px rgba(var(--bc-orange), 0.22),
          0 0 56px rgba(255, 123, 114, 0.16),
          0 0 30px rgba(var(--bc-accent), 0.12);
        pointer-events: none;
        mix-blend-mode: screen;
      }
      @media (prefers-reduced-motion: no-preference) {
        header.card.hero > .cardBorder::before { animation: bcHeroEdgeTop 9.5s ease-in-out infinite; }
        header.card.hero > .cardBorder::after { animation: bcHeroEdgeBottom 11.5s ease-in-out infinite; }
        @keyframes bcHeroEdgeTop {
          0%, 100% { opacity: 0.86; }
          50% { opacity: 0.98; }
        }
        @keyframes bcHeroEdgeBottom {
          0%, 100% { opacity: 0.88; }
          50% { opacity: 1; }
        }
      }

      .card,
      .illustration,
      pre,
      .traitChip,
      .heroDetails summary {
        border-color: var(--bc-border-1) !important;
        background:
          radial-gradient(900px 420px at 50% -40px, rgba(255, 255, 255, 0.10), transparent 72%),
          linear-gradient(180deg, var(--bc-surface-1), var(--bc-surface-2));
        box-shadow:
          inset 0 1px 0 var(--bc-inset-1),
          inset 0 0 0 1px var(--bc-border-2),
          var(--bc-shadow-1),
          var(--bc-shadow-2);
        backdrop-filter: blur(var(--bc-blur-1)) saturate(var(--bc-saturate-1));
        -webkit-backdrop-filter: blur(var(--bc-blur-1)) saturate(var(--bc-saturate-1));
      }

      /* HUD Progress: step colors are “the show”.
         The frame stays neutral glass; the border is a masked spectrum ring (so it doesn't tint the fill). */
      .hudProgress .hudFrame {
        border: 1px solid transparent;
        border-color: transparent !important; /* border ring is rendered by ::before */
        background:
          radial-gradient(1200px 280px at 50% -40px, rgba(255, 255, 255, 0.028), transparent 72%) padding-box,
          radial-gradient(900px 320px at 50% 140%, rgba(0, 0, 0, 0.12), transparent 72%) padding-box,
          linear-gradient(180deg, var(--hud-glass-top), var(--hud-glass-bottom)) padding-box;
        backdrop-filter: blur(var(--hud-blur)) saturate(var(--hud-saturate));
        -webkit-backdrop-filter: blur(var(--hud-blur)) saturate(var(--hud-saturate));
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.16),
          inset 0 0 0 1px rgba(255, 255, 255, 0.05),
          inset 0 -26px 90px rgba(0, 0, 0, 0.12),
          0 20px 90px rgba(0, 0, 0, 0.56),
          0 0 0 1px rgba(255, 255, 255, 0.06);
        filter: none;
      }
      .hudProgress .hudFrame::before {
        content: "";
        position: absolute;
        inset: 0;
        border-radius: inherit;
        padding: 2px;
        background: linear-gradient(
          90deg,
          rgba(255, 255, 255, 0.10),
          var(--hud-edge-amber),
          var(--hud-edge-orange),
          var(--hud-edge-teal),
          var(--hud-edge-violet),
          rgba(255, 255, 255, 0.10)
        );
        /* Show only the ring (not the fill) so the spectrum never tints the interior. */
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask-composite: exclude;
        pointer-events: none;
        /* Prevent inherited blend/animations from the generic .hudFrame::* rules. */
        mix-blend-mode: normal;
        opacity: 0.98;
        filter:
          drop-shadow(0 0 10px rgba(255, 255, 255, 0.07))
          drop-shadow(0 0 16px rgba(var(--bc-amber), 0.08))
          drop-shadow(0 0 20px rgba(var(--bc-accent2), 0.09));
      }
      .hudProgress .hudFrame::after {
        content: "";
        position: absolute;
        inset: 2px;
        border-radius: calc(14px - 2px);
        transform: none;
        animation: none;
        /* Accent edges (variable thickness feel) + soft “current step” glow that slides with progress. */
        background:
          /* Top hairline (always on) */
          linear-gradient(90deg, rgba(255, 255, 255, 0.00), rgba(255, 255, 255, 0.14), rgba(255, 255, 255, 0.00)) 0 0 / 100% 1px no-repeat,
          /* Top edge accents (varied widths + thicknesses) */
          linear-gradient(
            90deg,
            rgba(var(--bc-amber), 0.00) 0%,
            rgba(var(--bc-amber), 0.54) 22%,
            rgba(var(--bc-orange), 0.34) 58%,
            rgba(var(--bc-amber), 0.00) 100%
          ) 0 0 / 62% 4px no-repeat,
          linear-gradient(
            90deg,
            rgba(var(--bc-accent2), 0.00) 0%,
            rgba(var(--bc-accent2), 0.30) 36%,
            rgba(var(--bc-accent2), 0.00) 100%
          ) 16% 0 / 18% 2px no-repeat,
          linear-gradient(
            90deg,
            rgba(var(--bc-orange), 0.00) 0%,
            rgba(var(--bc-orange), 0.40) 28%,
            rgba(var(--bc-accent2), 0.26) 72%,
            rgba(var(--bc-orange), 0.00) 100%
          ) 52% 0 / 34% 3px no-repeat,
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.00) 0%,
            rgba(var(--bc-amber), 0.00) 8%,
            rgba(var(--bc-amber), 0.46) 22%,
            rgba(var(--bc-orange), 0.40) 52%,
            rgba(var(--bc-accent2), 0.30) 78%,
            rgba(255, 255, 255, 0.00) 100%
          ) 100% 0 / 22% 2px no-repeat,
          /* Bottom hairline */
          linear-gradient(90deg, rgba(255, 255, 255, 0.00), rgba(255, 255, 255, 0.12), rgba(255, 255, 255, 0.00)) 0 100% / 100% 1px no-repeat,
          /* Bottom edge accents (varied) */
          linear-gradient(
            90deg,
            rgba(var(--bc-violet), 0.00) 0%,
            rgba(var(--bc-violet), 0.26) 26%,
            rgba(var(--bc-accent2), 0.22) 68%,
            rgba(var(--bc-violet), 0.00) 100%
          ) 0 100% / 46% 2px no-repeat,
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.00) 0%,
            rgba(255, 92, 92, 0.00) 10%,
            rgba(255, 92, 92, 0.34) 28%,
            rgba(var(--bc-orange), 0.30) 58%,
            rgba(var(--bc-amber), 0.22) 82%,
            rgba(255, 255, 255, 0.00) 100%
          ) 100% 100% / 64% 3px no-repeat,
          linear-gradient(
            90deg,
            rgba(var(--bc-amber), 0.00) 0%,
            rgba(var(--bc-amber), 0.22) 40%,
            rgba(var(--bc-amber), 0.00) 100%
          ) 78% 100% / 20% 2px no-repeat,
          radial-gradient(
            240px 180px at calc(var(--hud-progress) * 100%) 50%,
            rgba(255, 255, 255, 0.08),
            transparent 62%
          ),
          radial-gradient(
            520px 220px at calc(var(--hud-progress) * 100%) 50%,
            rgba(var(--bc-accent2), 0.045),
            transparent 70%
          );
        opacity: 0.42;
        pointer-events: none;
        mix-blend-mode: screen;
      }

      /* Hero panel (Setup Overview): use a much darker, more transparent “black glass”. */
      header.card.hero .panel:first-of-type {
        /* Keep background unchanged; only adjust border via pseudo-elements below. */
        background:
          /* keep the center clear: minimal highlight, pushed to the RIGHT */
          radial-gradient(900px 420px at 86% 16%, rgba(255, 255, 255, 0.045), transparent 72%),
          linear-gradient(180deg, rgba(0, 0, 0, 0.18), rgba(0, 0, 0, 0.06));
        /* 3D edge: subtle inward shadow that fades quickly (no extra “background layer”). */
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.10),
          inset 0 0 0 1px rgba(255, 255, 255, 0.04),
          inset 0 0 18px rgba(0, 0, 0, 0.34),
          0 22px 70px rgba(0, 0, 0, 0.44),
          0 0 0 1px rgba(var(--bc-ice), 0.08),
          0 0 42px rgba(var(--bc-accent2), 0.06);
      }

      /* Setup Overview border ring (blue tones) — separate from background. */
      header.card.hero .panel:first-of-type {
        position: relative;
        border: 1px solid transparent;
        border-color: transparent !important; /* override the global !important border-color reset */
      }
      header.card.hero .panel:first-of-type::before {
        content: "";
        position: absolute;
        inset: 0;
        border-radius: inherit;
        z-index: 1;
        padding: 1px; /* base thin ring */
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        background:
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.16),
            rgba(var(--bc-ice), 0.26),
            rgba(var(--bc-cyan), 0.18),
            rgba(var(--bc-accent2), 0.30),
            rgba(var(--bc-violet), 0.24),
            rgba(var(--bc-ice), 0.20),
            rgba(255, 255, 255, 0.12)
          );
        opacity: 0.98;
        pointer-events: none;
      }
      /* Thickness variation: a thicker left/top/bottom accent that fades into the thin ring. */
      header.card.hero .panel:first-of-type::after {
        content: "";
        position: absolute;
        inset: -2px;
        border-radius: calc(var(--hero-radius-lg) + 1px);
        z-index: 2;
        padding: 4px; /* thicker accents */
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        background:
          /* Warm transition (bottom-left): match HERO bottom edge (orange → soft red), fading into the blue ring. */
          linear-gradient(
            180deg,
            rgba(var(--bc-orange), 0.00) 0%,
            rgba(var(--bc-orange), 0.00) 54%,
            rgba(var(--bc-orange), 0.18) 74%,
            rgba(255, 123, 114, 0.26) 88%,
            rgba(255, 123, 114, 0.34) 100%
          ) 0 0 / 110px 100% no-repeat,
          radial-gradient(40px 40px at 0 100%, rgba(255, 123, 114, 0.36), rgba(var(--bc-orange), 0.18) 40%, rgba(var(--bc-orange), 0.00) 76%) 0 100% / 180px 180px no-repeat,
          /* Left arc: full thickness across the rounding, then fade into thin ring */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.78), rgba(var(--bc-cyan), 0.42), rgba(var(--bc-ice), 0.00)) 0 0 / 150px 100% no-repeat,
          /* Top (~66%) and bottom (~40%) accents */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.74), rgba(var(--bc-accent2), 0.40), rgba(var(--bc-ice), 0.00)) 0 0 / 66% 100% no-repeat,
          linear-gradient(90deg, rgba(var(--bc-ice), 0.54), rgba(var(--bc-accent2), 0.26), rgba(var(--bc-ice), 0.00)) 0 100% / 40% 100% no-repeat,
          /* Nodes */
          radial-gradient(6px 6px at 18% 0%, rgba(var(--bc-ice), 0.62), rgba(var(--bc-ice), 0.00) 70%),
          radial-gradient(6px 6px at 64% 0%, rgba(var(--bc-cyan), 0.62), rgba(var(--bc-cyan), 0.00) 70%),
          radial-gradient(6px 6px at 38% 100%, rgba(var(--bc-orange), 0.60), rgba(var(--bc-orange), 0.00) 70%);
        filter:
          drop-shadow(0 0 14px rgba(var(--bc-ice), 0.10))
          drop-shadow(0 0 18px rgba(var(--bc-orange), 0.06))
          drop-shadow(0 0 26px rgba(var(--bc-accent2), 0.06));
        opacity: 0.88;
        pointer-events: none;
      }
      header.card.hero .panel:first-of-type > * { position: relative; z-index: 3; }

      /* Hero panel (Kernel Capabilities): no extra background/blur — border-only frame like Setup Overview. */
      header.card.hero .panel:last-of-type {
        position: relative;
        border: 1px solid transparent;
        border-color: transparent !important;
        background: transparent !important;
        box-shadow: none !important;
        backdrop-filter: none !important;
        -webkit-backdrop-filter: none !important;
        /* Keep tile spacing consistent: top/bottom padding == grid gap. */
        --traitsGap: 14px;
        padding: var(--traitsGap);
      }
      header.card.hero .panel:last-of-type::before {
        content: "";
        position: absolute;
        inset: 0;
        border-radius: inherit;
        z-index: 1;
        padding: 1px;
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        background:
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.14),
            rgba(var(--bc-ice), 0.22),
            rgba(var(--bc-cyan), 0.16),
            rgba(var(--bc-accent2), 0.26),
            rgba(var(--bc-violet), 0.22),
            rgba(var(--bc-ice), 0.16),
            rgba(255, 255, 255, 0.10)
          );
        opacity: 0.96;
        pointer-events: none;
      }
      header.card.hero .panel:last-of-type::after {
        content: "";
        position: absolute;
        inset: -2px;
        border-radius: calc(var(--hero-radius-lg) + 1px);
        z-index: 2;
        padding: 4px;
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        background:
          /* Left arc emphasis + subtle top/bottom segments (no warm tone here). */
          linear-gradient(90deg, rgba(var(--bc-ice), 0.72), rgba(var(--bc-cyan), 0.32), rgba(var(--bc-ice), 0.00)) 0 0 / 140px 100% no-repeat,
          linear-gradient(90deg, rgba(var(--bc-ice), 0.58), rgba(var(--bc-accent2), 0.28), rgba(var(--bc-ice), 0.00)) 0 0 / 58% 100% no-repeat,
          linear-gradient(90deg, rgba(var(--bc-ice), 0.44), rgba(var(--bc-accent2), 0.18), rgba(var(--bc-ice), 0.00)) 0 100% / 34% 100% no-repeat,
          /* Right segment (purple hint) */
          linear-gradient(90deg, rgba(var(--bc-violet), 0.00), rgba(var(--bc-violet), 0.22), rgba(var(--bc-violet), 0.00)) 100% 0 / 26% 100% no-repeat,
          /* Nodes */
          radial-gradient(6px 6px at 22% 0%, rgba(var(--bc-ice), 0.56), rgba(var(--bc-ice), 0.00) 70%),
          radial-gradient(6px 6px at 58% 0%, rgba(var(--bc-cyan), 0.56), rgba(var(--bc-cyan), 0.00) 70%),
          radial-gradient(6px 6px at 78% 100%, rgba(var(--bc-violet), 0.46), rgba(var(--bc-violet), 0.00) 70%);
        filter:
          drop-shadow(0 0 12px rgba(var(--bc-ice), 0.08))
          drop-shadow(0 0 22px rgba(var(--bc-accent2), 0.06));
        opacity: 0.82;
        pointer-events: none;
      }
      header.card.hero .panel:last-of-type > * { position: relative; z-index: 3; }

      /* Kernel Capabilities tiles: override reset “white glass” surfaces.
         Goal: no grey fill, tight spacing, and per-tile colored borders (sizes + gradients). */
      header.card.hero .panel:last-of-type .traitsGrid {
        display: grid;
        grid-template-columns: 1fr;
        margin-top: 0;
        gap: var(--traitsGap, 14px);
      }
      header.card.hero .panel:last-of-type .traitsTitle { margin-bottom: var(--traitsGap, 14px); }

      header.card.hero .panel:last-of-type .traitChip {
        /* Override global reset “white glass” rules: tiles should be border-only (no fill). */
        --tileA: var(--bc-accent);
        --tileB: var(--bc-ice);
        --bc-trait-glow: var(--tileA);
        --bc-glyph-mask: var(--bc-mask-glyph-lock);
        --tileThin: 1px;
        --tileThick: 3px;
        --tileLeftW: 86px;
        --tileTopW: 60%;
        --tileBottomW: 34%;
        display: flex;
        align-items: center;
        padding: 10px 12px;
        border-radius: 16px;
        position: relative;
        overflow: hidden;
        transition: transform .12s ease, filter .18s ease;
        /* A touch more left inset: icons should not hug the edge. */
        padding-left: 16px;
        gap: 12px;
        border: 0 !important;
        /* Extremely subtle per-tile “light” (barely visible), tinted by the border colors. */
        background:
          radial-gradient(120px 88px at 14% 50%, rgba(var(--tileA), 0.095), rgba(var(--tileA), 0.00) 72%),
          radial-gradient(180px 120px at 92% 30%, rgba(var(--tileB), 0.075), rgba(var(--tileB), 0.00) 74%),
          /* “Bridge” between border tones so the interior doesn't look too black. */
          linear-gradient(
            90deg,
            rgba(var(--tileA), 0.090) 0%,
            rgba(var(--tileB), 0.065) 55%,
            rgba(var(--tileA), 0.038) 100%
          ),
          linear-gradient(180deg, rgba(255, 255, 255, 0.030), rgba(255, 255, 255, 0.000)) !important;
        box-shadow: none !important;
        backdrop-filter: blur(2px) saturate(1.03) !important;
        -webkit-backdrop-filter: blur(2px) saturate(1.03) !important;
      }
      /* Per-tile border palette (must live here to override the base defaults above). */
      header.card.hero .panel:last-of-type .traitChip[data-trait="https"] {
        --tileA: var(--bc-amber);
        --tileB: var(--bc-orange);
        --bc-trait-glow: var(--bc-amber);
        --bc-glyph-mask: var(--bc-mask-glyph-lock);
        --tileSweepDur: 19.5s;
        --tileSweepDelay: -3.7s;
      }
      header.card.hero .panel:last-of-type .traitChip[data-trait="stage"] {
        --tileA: var(--bc-accent);
        --tileB: var(--bc-violet);
        --bc-trait-glow: var(--bc-accent);
        --bc-glyph-mask: var(--bc-mask-glyph-layers);
        --tileSweepDur: 23s;
        --tileSweepDelay: -11.2s;
      }
      header.card.hero .panel:last-of-type .traitChip[data-trait="keyless"] {
        --tileA: var(--bc-accent2);
        --tileB: var(--bc-cyan);
        --bc-trait-glow: var(--bc-accent2);
        --bc-glyph-mask: var(--bc-mask-glyph-key);
        --tileSweepDur: 17.4s;
        --tileSweepDelay: -6.1s;
      }
      header.card.hero .panel:last-of-type .traitChip[data-trait="registry"] {
        --tileA: var(--bc-violet);
        --tileB: var(--bc-ice);
        --bc-trait-glow: var(--bc-violet);
        --bc-glyph-mask: var(--bc-mask-glyph-shield);
        --tileSweepDur: 21.2s;
        --tileSweepDelay: -14.8s;
      }
      header.card.hero .panel:last-of-type .traitChip[data-trait="signed"] {
        --tileA: var(--bc-cyan);
        --tileB: var(--bc-accent2);
        --bc-trait-glow: var(--bc-cyan);
        --bc-glyph-mask: var(--bc-mask-glyph-wallet);
        --tileSweepDur: 18.8s;
        --tileSweepDelay: -9.4s;
      }
      header.card.hero .panel:last-of-type .traitChip[data-trait="chain"] {
        --tileA: var(--bc-orange);
        --tileB: var(--bc-cyan);
        --bc-trait-glow: var(--bc-orange);
        --bc-glyph-mask: var(--bc-mask-glyph-chain);
        --tileSweepDur: 16.6s;
        --tileSweepDelay: -4.9s;
      }
      header.card.hero .panel:last-of-type .traitChip::before {
        content: "";
        position: absolute;
        inset: 0;
        border-radius: inherit;
        z-index: 1;
        padding: var(--tileThin);
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        /* Keep the sweep away from rounded corners so we don't “paint” the right edge. */
        clip-path: inset(0 14px 0 14px round 16px);
        /* Use per-layer positions so we can animate only the sweep layer (no corner artifacts). */
        background:
          /* Sweep layer (animated). */
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.00) 0%,
            rgba(255, 255, 255, 0.00) 22%,
            rgba(var(--tileA), 0.82) 48%,
            rgba(var(--tileB), 0.52) 56%,
            rgba(255, 255, 255, 0.00) 84%,
            rgba(255, 255, 255, 0.00) 100%
          ) var(--bcTileSweepX, -120%) 0 / 240% 100% no-repeat,
          linear-gradient(transparent, transparent) 0 0 / 100% 100% no-repeat;
        pointer-events: none;
      }
      header.card.hero .panel:last-of-type .traitChip::after {
        content: "";
        position: absolute;
        inset: 0;
        border-radius: inherit;
        z-index: 0;
        padding: var(--tileThick);
        -webkit-mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask:
          linear-gradient(#000 0 0) content-box,
          linear-gradient(#000 0 0);
        mask-composite: exclude;
        background:
          /* Left arc / bar (strong) */
          linear-gradient(90deg, rgba(var(--tileA), 0.82), rgba(var(--tileB), 0.26), rgba(var(--tileA), 0.00)) 0 0 / var(--tileLeftW) 100% no-repeat,
          /* Top sweep */
          linear-gradient(90deg, rgba(var(--tileB), 0.50), rgba(var(--tileB), 0.00)) 0 0 / var(--tileTopW) 100% no-repeat,
          /* Bottom sweep */
          linear-gradient(90deg, rgba(var(--tileA), 0.42), rgba(var(--tileA), 0.00)) 0 100% / var(--tileBottomW) 100% no-repeat,
          /* Beads (connectors) */
          radial-gradient(6px 6px at 22% 0%, rgba(var(--tileB), 0.58), rgba(var(--tileB), 0.00) 70%),
          radial-gradient(6px 6px at 58% 0%, rgba(var(--tileA), 0.52), rgba(var(--tileA), 0.00) 70%),
          radial-gradient(6px 6px at 38% 100%, rgba(var(--tileA), 0.56), rgba(var(--tileA), 0.00) 70%),
          /* Base ring (static): keeps the outline stable while the sweep animates above it. */
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.10),
            rgba(var(--tileA), 0.22),
            rgba(var(--tileB), 0.20),
            rgba(255, 255, 255, 0.08)
          ) 0 0 / 100% 100% no-repeat;
        pointer-events: none;
      }
      header.card.hero .panel:last-of-type .traitChip > * { z-index: 2; }
      header.card.hero .panel:last-of-type .traitChip:hover {
        box-shadow:
          none !important;
      }

      header.card.hero .panel:last-of-type .traitIcon {
        width: 38px;
        height: 38px;
        position: relative;
        flex: 0 0 38px;
        border-radius: 13px;
        border: 1px solid rgba(var(--bc-trait-glow), 0.22);
        /* Keep icon “floating” and close to the left edge (no grey fill). */
        background: transparent !important;
        margin-left: 0;
        transform: translateY(-1px);
        /* Tie the icon “pop” to the tile border palette (subtle halo). */
        border-color: rgba(var(--tileA), 0.30);
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.06),
          0 14px 54px rgba(0, 0, 0, 0.34),
          0 0 0 1px rgba(var(--tileA), 0.12),
          0 0 18px rgba(var(--tileA), 0.14),
          0 0 34px rgba(var(--tileB), 0.09);
      }
      header.card.hero .panel:last-of-type .traitIcon::before {
        content: "";
        position: absolute;
        inset: 0;
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.62), rgba(255, 255, 255, 0.00) 48%),
          linear-gradient(180deg, rgba(var(--bc-trait-glow), 0.92), rgba(var(--bc-trait-glow), 0.52));
        -webkit-mask: var(--bc-mask-cat-head) center / contain no-repeat;
        mask: var(--bc-mask-cat-head) center / contain no-repeat;
        filter:
          drop-shadow(0 0 14px rgba(var(--bc-trait-glow), 0.16))
          drop-shadow(0 14px 52px rgba(0, 0, 0, 0.34));
        opacity: 0.96;
        pointer-events: none;
      }
      header.card.hero .panel:last-of-type .traitIcon::after {
        content: "";
        position: absolute;
        width: 16px;
        height: 16px;
        right: -2px;
        bottom: -2px;
        background:
          radial-gradient(circle at 35% 35%, rgba(255, 255, 255, 0.85), rgba(255, 255, 255, 0.00) 48%),
          linear-gradient(180deg, rgba(var(--bc-trait-glow), 0.92), rgba(var(--bc-trait-glow), 0.40));
        -webkit-mask: var(--bc-glyph-mask) center / contain no-repeat;
        mask: var(--bc-glyph-mask) center / contain no-repeat;
        filter:
          drop-shadow(0 0 14px rgba(var(--bc-trait-glow), 0.16))
          drop-shadow(0 10px 40px rgba(0, 0, 0, 0.34));
        opacity: 0.92;
        pointer-events: none;
      }

      /* Kernel Capabilities tile text: premium sci‑fi type with subtle per-tile accent. */
      header.card.hero .panel:last-of-type .traitText {
        position: relative;
        padding-left: 2px;
        min-width: 0;
      }
      header.card.hero .panel:last-of-type .traitMain {
        position: relative;
        font-weight: 900;
        font-size: 13px;
        letter-spacing: 0.09em;
        text-transform: uppercase;
        line-height: 1.15;
        color: rgba(252, 254, 255, 0.94);
        /* Crisp “outline/inner glow” feel without dark shadows. */
        -webkit-text-stroke: 0.35px rgba(var(--tileA), 0.35);
        text-shadow:
          0 0 10px rgba(var(--tileA), 0.18),
          0 0 20px rgba(var(--tileB), 0.10);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      header.card.hero .panel:last-of-type .traitSub {
        margin-top: 3px;
        font-size: 12px;
        letter-spacing: 0.02em;
        color: rgba(226, 236, 252, 0.86);
        -webkit-text-stroke: 0.25px rgba(var(--tileB), 0.20);
        text-shadow:
          0 0 12px rgba(var(--tileB), 0.10),
          0 0 22px rgba(var(--tileA), 0.06);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      /* Subtle sci‑fi motion: slow border “sweep” (no-op on prefers-reduced-motion).
         Animate only the sweep layer via a typed custom property (keeps corner fixes static). */
      @property --bcTileSweepX { syntax: "<percentage>"; inherits: false; initial-value: -120%; }
      @media (prefers-reduced-motion: no-preference) {
        body[data-ui-map="0"] header.card.hero .panel:last-of-type .traitChip::before {
          animation: bcTileSweep var(--tileSweepDur, 18s) linear infinite;
          animation-delay: var(--tileSweepDelay, 0s);
        }
        @keyframes bcTileSweep {
          0% { --bcTileSweepX: -120%; }
          100% { --bcTileSweepX: 220%; }
        }
      }

      /* Outer HERO card (the area behind the two hero panels + the gap between them).
         Make it “black glass” too, so we don't get a white/bright bleed between panels. */
      header.card.hero {
        background:
          radial-gradient(1200px 420px at 78% 10%, rgba(255, 255, 255, 0.022), transparent 72%),
          linear-gradient(180deg, rgba(0, 0, 0, 0.14), rgba(0, 0, 0, 0.05));
      }

      /* Premium clarity: reduce blur so the space grid stays visible. */
      header.card.hero,
      header.card.hero .panel:first-of-type {
        backdrop-filter: blur(8px) saturate(1.05);
        -webkit-backdrop-filter: blur(8px) saturate(1.05);
      }
      /* Reduce colored blooms inside containers for a true “reset” baseline. */
      body[data-ui-map="0"] .panel::before,
      body[data-ui-map="0"] .panel::after,
      body[data-ui-map="0"] .traitChip::before,
      body[data-ui-map="0"] .traitChip::after,
      body[data-ui-map="0"] .overviewArt:not(.isLogo)::before,
      body[data-ui-map="0"] .overviewArt:not(.isLogo)::after { opacity: 0.0 !important; }
      /* Keep the Setup Overview border ring visible in normal mode. */
      body[data-ui-map="0"] header.card.hero .panel:first-of-type::before,
      body[data-ui-map="0"] header.card.hero .panel:first-of-type::after { opacity: 1 !important; }
      /* Keep the Kernel Capabilities border ring visible in normal mode. */
      body[data-ui-map="0"] header.card.hero .panel:last-of-type::before,
      body[data-ui-map="0"] header.card.hero .panel:last-of-type::after { opacity: 1 !important; }
      /* Keep the Kernel Capabilities tile rings visible in normal mode (the global reset hides them). */
      body[data-ui-map="0"] header.card.hero .panel:last-of-type .traitChip::before,
      body[data-ui-map="0"] header.card.hero .panel:last-of-type .traitChip::after { opacity: 1 !important; }

      /* Setup Overview: “What is Stage 3?” — make it a clean, full-width info control. */
      header.card.hero .panel:first-of-type .heroDetails summary {
        display: flex;
        align-items: center;
        width: 100%;
        padding: 12px 0;
        border: 0;
        background: transparent !important;
        box-shadow: none;
        backdrop-filter: none;
        -webkit-backdrop-filter: none;
        color: rgba(255, 255, 255, 0.98);
        font-weight: 900;
        font-size: 17px;
        letter-spacing: 0.02em;
        text-shadow:
          0 1px 0 rgba(0, 0, 0, 0.72),
          0 0 18px rgba(var(--bc-ice), 0.10);
      }
      header.card.hero .panel:first-of-type .heroDetails summary::before {
        color: rgba(var(--bc-accent), 0.95);
        font-size: 18px;
        text-shadow:
          0 1px 0 rgba(0, 0, 0, 0.65),
          0 0 12px rgba(var(--bc-accent), 0.28),
          0 0 26px rgba(var(--bc-accent), 0.16);
      }
      header.card.hero .panel:first-of-type .heroDetails summary::after {
        content: "";
        flex: 1 1 auto;
        height: 2px;
        margin-left: 14px;
        background: linear-gradient(
          90deg,
          rgba(var(--bc-ice), 0.28),
          rgba(var(--bc-accent), 0.22),
          rgba(var(--bc-cyan), 0.16),
          rgba(255, 255, 255, 0.00)
        );
        opacity: 0.9;
        filter: drop-shadow(0 0 12px rgba(var(--bc-accent), 0.10));
      }
      header.card.hero .panel:first-of-type .heroDetails summary:focus-visible {
        outline: none;
        text-decoration: none;
      }
      header.card.hero .panel:first-of-type .heroDetails summary:focus-visible::after {
        opacity: 1;
        filter: drop-shadow(0 0 14px rgba(var(--bc-accent2), 0.14));
      }

      /* =========================
         UI MAP (debug labels)
         Add lightweight labels so you can give precise feedback.
         Enable via: ?ui_map=1
         ========================= */
      body[data-ui-map="1"] { counter-reset: bcCard bcPanel bcTile; }
      body[data-ui-map="1"] .card,
      body[data-ui-map="1"] .panel,
      body[data-ui-map="1"] .hudProgress,
      body[data-ui-map="1"] .hudFrame,
      body[data-ui-map="1"] .overviewArt,
      body[data-ui-map="1"] .traitChip { position: relative; }

      body[data-ui-map="1"] .card { counter-increment: bcCard; }
      body[data-ui-map="1"] .panel { counter-increment: bcPanel; }
      body[data-ui-map="1"] .traitChip { counter-increment: bcTile; }

      body[data-ui-map="1"] .card::before,
      body[data-ui-map="1"] .panel::before,
      body[data-ui-map="1"] .hudProgress::before,
      body[data-ui-map="1"] .overviewArt::before,
      body[data-ui-map="1"] .traitChip::before {
        content: "";
        position: absolute;
        top: 10px;
        left: 10px;
        z-index: 50;
        padding: 6px 10px;
        border-radius: 999px;
        border: 1px solid rgba(255, 255, 255, 0.28);
        background: rgba(0, 0, 0, 0.52);
        color: rgba(255, 255, 255, 0.92);
        font: 10px/1.1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        pointer-events: none;
        box-shadow:
          inset 0 1px 0 rgba(255, 255, 255, 0.10),
          0 12px 44px rgba(0, 0, 0, 0.28);
        white-space: nowrap;
      }

      /* CARD labels */
      body[data-ui-map="1"] header.card.hero::before { content: "CARD: HERO"; }
      body[data-ui-map="1"] .card.step::before {
        content: "CARD: STEP " attr(data-step) " / " attr(data-lane);
      }
      body[data-ui-map="1"] .card:not(.hero):not(.step)::before { content: "CARD " counter(bcCard); }

      /* PANEL labels */
      body[data-ui-map="1"] header.card.hero .panel:first-of-type::before { content: "PANEL: SETUP OVERVIEW"; }
      body[data-ui-map="1"] header.card.hero .panel:last-of-type::before { content: "PANEL: KERNEL CAPABILITIES"; }
      body[data-ui-map="1"] .panel::before { content: "PANEL " counter(bcPanel); left: auto; right: 10px; }

      /* HUD / stepper label */
      body[data-ui-map="1"] .hudProgress::before { content: "HUD: PROGRESS"; left: auto; right: 10px; top: -10px; }

      /* Illustration label */
      body[data-ui-map="1"] .overviewArt::before { content: "ILLUSTRATION"; left: 12px; top: 12px; }

      /* Capability tile label (use data-trait; place in a corner so it doesn't cover title) */
      body[data-ui-map="1"] .traitChip::before {
        content: "TILE: " attr(data-trait);
        left: auto;
        right: 10px;
        top: 10px;
        padding: 5px 8px;
        opacity: 0.75;
      }
    </style>
  </head>
  <body data-ui-map="__BLACKCAT_UI_MAP__">
	    <div class="wrap">
	      <header class="card hero">
	        <div class="cardBorder"></div>
	        <div class="heroBanner" aria-hidden="true"></div>
	        <div class="heroGrid">
	          <div class="panel">
		            <strong class="overviewTitle">Setup Overview <span class="overviewMeta">wallet-signed • on-chain integrity</span></strong>
	            <div class="overviewGrid">
	              <div>
	                <h1 class="heroTitle"><span class="heroBrand">BlackCat</span><span class="heroTitleLine2"><span class="heroTitleAccent">Kernel Bootstrap</span> <span class="pillKernelWrap"><span class="pill mono pillKernel">Kernel Minimal</span></span></span></h1>
	                <p class="heroSub">FTP upload <span class="heroArrow">→</span> integrity manifest <span class="heroArrow">→</span> wallet-signed approvals <span class="heroArrow">→</span> installer locks itself.</p>
	              </div>
	              __BLACKCAT_OVERVIEW_ILLUSTRATION__
	            </div>
	            <details class="heroDetails">
	              <summary class="muted">What is Stage 3?</summary>
	              <div class="small muted">
	                Stage 3 bootstraps the <strong>kernel-minimal</strong> bundle for constrained hosting: generate an integrity manifest, anchor trust on-chain, write runtime config, then permanently disable setup.
	              </div>
	              <ul class="small muted">
	                <li><span class="mono">HTTPS-only</span> setup (MITM-resistant).</li>
	                <li><span class="mono">Wallet-signed</span> approvals (<span class="mono">no</span> server private keys).</li>
	                <li><span class="mono">No</span> Composer required on the server.</li>
	                <li>Fail-closed when trust cannot be established.</li>
	              </ul>
	            </details>
	          </div>

	          <div class="panel">
		            <strong class="traitsTitle">Kernel Capabilities</strong>
	            <div class="traitsGrid" role="list">
	              <div class="traitChip" data-trait="https" role="listitem">
	                <div class="traitIcon" aria-hidden="true"></div>
	                <div class="traitText">
	                  <div class="traitMain">HTTPS required</div>
	                  <div class="traitSub">setup is TLS-only</div>
	                </div>
	              </div>
	              <div class="traitChip" data-trait="stage" role="listitem">
	                <div class="traitIcon" aria-hidden="true"></div>
	                <div class="traitText">
	                  <div class="traitMain">Stage 3</div>
	                  <div class="traitSub">kernel-minimal bootstrap</div>
	                </div>
	              </div>
	              <div class="traitChip" data-trait="keyless" role="listitem">
	                <div class="traitIcon" aria-hidden="true"></div>
	                <div class="traitText">
	                  <div class="traitMain">Keyless boundary</div>
	                  <div class="traitSub">no raw key export</div>
	                </div>
	              </div>
	              <div class="traitChip" data-trait="registry" role="listitem">
	                <div class="traitIcon" aria-hidden="true"></div>
	                <div class="traitText">
	                  <div class="traitMain">Release registry</div>
	                  <div class="traitSub">root trust on-chain</div>
	                </div>
	              </div>
	              <div class="traitChip" data-trait="signed" role="listitem">
	                <div class="traitIcon" aria-hidden="true"></div>
	                <div class="traitText">
	                  <div class="traitMain">Wallet-signed</div>
	                  <div class="traitSub">no server private keys</div>
	                </div>
	              </div>
	              <div class="traitChip" data-trait="chain" role="listitem">
	                <div class="traitIcon" aria-hidden="true"></div>
	                <div class="traitText">
	                  <div class="traitMain">Edgen (4207)</div>
	                  <div class="traitSub">EVM-compatible</div>
	                </div>
	              </div>
	            </div>
	          </div>
	        </div>
	      </header>

      <nav class="hudProgress" id="hudProgress" aria-label="Setup progress">
        <div class="hudFrame">
          <ol class="hudTrack" role="list">
            <li class="hudItem is-current" data-hud="unlock" role="listitem">
              <div class="hudIcon" aria-hidden="true"></div>
              <div class="hudText">
                <div class="hudTitle">Unlock</div>
                <span class="hudBadge" id="hudBadge_unlock">CURRENT</span>
              </div>
            </li>
            <li class="hudItem is-locked" data-hud="integrity" role="listitem">
              <div class="hudIcon" aria-hidden="true"></div>
              <div class="hudText">
                <div class="hudTitle">Upload / Integrity</div>
                <span class="hudBadge" id="hudBadge_integrity">LOCKED</span>
              </div>
            </li>
            <li class="hudItem is-locked" data-hud="chain" role="listitem">
              <div class="hudIcon" aria-hidden="true"></div>
              <div class="hudText">
                <div class="hudTitle">On-Chain Controller</div>
                <span class="hudBadge" id="hudBadge_chain">LOCKED</span>
              </div>
            </li>
            <li class="hudItem is-locked" data-hud="done" role="listitem">
              <div class="hudIcon" aria-hidden="true"></div>
              <div class="hudText">
                <div class="hudTitle">Lockdown / Done</div>
                <span class="hudBadge" id="hudBadge_done">LOCKED</span>
              </div>
            </li>
          </ol>
        </div>
      </nav>

    <div class="steps">
      <div class="card step step1" data-step="1" data-lane="server">
        <div class="cardBorder"></div>
        <div class="panel">
          <strong>Install token (out-of-band)</strong>
          <div class="row">
            <div>
              <p class="muted">This is the safety gate for setup. BlackCat writes a random token to a file <strong>outside</strong> the web docroot, so you must retrieve it via FTP/SFTP.</p>
              <ul class="muted">
                <li>Find <span class="mono">.blackcat/install.token</span> at the <strong>bundle root</strong> (next to <span class="mono">site/</span>).</li>
                <li>Open it in a plain text editor and copy the <strong>64‑hex</strong> token.</li>
                <li>Paste below and click <strong>Save</strong> to unlock API calls for this browser.</li>
              </ul>
              <div class="inlineTip">If you don’t see <span class="mono">.blackcat/</span>, your upload is incomplete or the server can’t write to the bundle root.</div>
              <div class="miniActions">
                <button id="copyTokenPath" class="btnSecondary">Copy token path</button>
                <button id="copyFtpChecklist" class="btnSecondary">Copy FTP checklist</button>
              </div>
            </div>
            <div style="flex: 1 1 360px">
              <div class="miniStack">
                <div class="miniCard">
                  <div class="miniCardHeader">Bundle layout</div>
                  <div class="miniCardBody">
                    <pre class="miniTree"><code>bundle-root/
  .blackcat/
    install.token
  site/
    public/
    vendor/</code></pre>
                  </div>
                </div>

                <div class="miniCard">
                  <div class="miniCardHeader">Paste token</div>
                  <div class="miniCardBody">
                    <div class="tokenRow">
                      <div class="tokenField">
                        <input id="token" class="tokenInput" type="password" placeholder="Install token (64‑hex)" autocomplete="off" autocapitalize="off" spellcheck="false" />
                      </div>
                      <div class="tokenActions">
                        <button id="saveToken">Save</button>
                        <button id="toggleToken" class="btnSecondary">Show</button>
                        <button id="clearToken" class="btnSecondary btnDanger">Clear</button>
                      </div>
                    </div>
                    <div id="tokenStatus" class="tokenStatus bad">
                      <span id="tokenStatusText">Token not set yet.</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

	      <div class="stepsLanes">
	        <div class="stepsLane stepsLaneLeft">
          <div class="card step step2" data-step="2" data-lane="server">
            <div class="cardBorder"></div>
            <div class="panel">
              <strong>Manifest</strong>
              <p>This scans <code>site/</code> (immutable code root) and writes:</p>
              <pre><code>.blackcat/integrity.manifest.json</code></pre>
              <div class="row">
                <div style="flex: 0 0 220px">
                  <button id="buildManifest">Build manifest</button>
                  <button id="verifyRelease" style="margin-left:8px">Verify release root</button>
                </div>
                <div>
                  <div class="small muted">Release trust: <span id="releaseTrust" class="pill mono">unknown</span></div>
                  <div class="small muted">
                    Registry:
                    <a id="releaseRegistryLink" href="https://edgenscan.io" target="_blank" rel="noreferrer">open explorer</a>
                  </div>
                </div>
              </div>
            </div>
            __BLACKCAT_TRUST_ILLUSTRATION__
            <pre id="manifestOut" style="display:none"></pre>
            <pre id="releaseOut" style="display:none"></pre>
          </div>

          <div class="card step step4" data-step="4" data-lane="server">
            <div class="cardBorder"></div>
            <div class="panel">
              <strong>Runtime config</strong>
              <p>Writes:</p>
              <pre><code>config.runtime.json</code></pre>
              <div class="row">
                <div>
                  <label class="k">InstanceController address</label>
                  <input id="instanceController" placeholder="0x..." autocomplete="off" />
                </div>
                <div>
                  <label class="k">RPC quorum</label>
                  <input id="rpcQuorum" type="number" min="1" value="2" />
                </div>
              </div>
            </div>

            <div class="panel">
              <strong>RPC + trust</strong>
              <label class="k">RPC endpoints (one per line, HTTPS)</label>
              <textarea id="rpcEndpoints" spellcheck="false"></textarea>
              <div class="row">
                <div>
                  <label class="k">Trust mode</label>
                  <select id="trustMode">
                    <option value="full" selected>full (recommended)</option>
                    <option value="root_uri">root_uri</option>
                  </select>
                </div>
                <div>
                  <label class="k">max_stale_sec</label>
                  <input id="maxStale" type="number" min="1" value="180" />
                </div>
              </div>
              <label class="k">Allowed hosts (optional, one per line)</label>
              <textarea id="allowedHosts" spellcheck="false" placeholder="example.com&#10;*.example.com"></textarea>
            </div>

            <div class="panel">
              <strong>Write</strong>
              <button id="writeConfig">Write config</button>
              <pre id="configOut" style="display:none"></pre>
            </div>
          </div>

          <div class="card step step5" data-step="5" data-lane="chain">
            <div class="cardBorder"></div>
            <div class="panel">
              <strong>Attestation lock</strong>
              <p class="muted">After writing <code>config.runtime.json</code>, lock the runtime config attestation on-chain:</p>
              <div class="small muted">Required signer: <span class="mono">rootAuthority</span></div>
              <div class="small muted"><strong>Option A:</strong> broadcast via browser wallet. <strong>Option B:</strong> generate tx intent and sign elsewhere.</div>
              <button id="lockAttestation">Broadcast lock tx (browser wallet)</button>
              <button id="lockAttestationManual" style="margin-left:8px">Generate tx intent (manual)</button>
              <pre id="attOut" style="display:none"></pre>
            </div>
          </div>
	        </div>

	        <div class="adventureGutter" aria-hidden="true">
	          <svg class="adventureSvg" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
	            <defs>
	              <linearGradient id="bcAdventureGrad" x1="0" y1="0" x2="0" y2="1">
	                <stop id="adventureStopA" offset="0%" />
	                <stop id="adventureStopB" offset="100%" />
	              </linearGradient>
	              <marker id="bcAdventureArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
	                <path class="adventureArrow" d="M0,0 L10,5 L0,10 z" />
	              </marker>
	            </defs>
	            <!-- Curvy “route” with an arrow: purely decorative. -->
	            <path
	              class="routeTrack"
	              d="M94 8 L72 8 A56 56 0 0 0 10 28 C 22 36 30 40 36 44 C 48 52 66 54 62 66 C 58 78 40 82 44 92 C 48 98 50 100 50 100"
	              marker-end="url(#bcAdventureArrow)"
	            />
	            <!-- Progress highlight: same curve, revealed by dasharray (pathLength=1 for easy 0..1 math). -->
	            <path
	              class="routeProgress"
	              d="M94 8 L72 8 A56 56 0 0 0 10 28 C 22 36 30 40 36 44 C 48 52 66 54 62 66 C 58 78 40 82 44 92 C 48 98 50 100 50 100"
	              pathLength="1"
	            />
	          </svg>
	        </div>

	        <div class="stepsLane stepsLaneRight">
          <div class="card step step3" data-step="3" data-lane="chain">
            <div class="cardBorder"></div>

            <div class="panel">
              <strong>Overview</strong>
              <p class="muted">No private keys are stored on the server. Broadcast from <strong>any</strong> EVM wallet (hardware wallet recommended): browser wallet (MetaMask/Rabby), explorer “Write contract”, or CLI (cast).</p>
              <p class="small muted">Network: <span class="mono">Edgen Chain</span> (<span class="mono">chain_id=4207</span>)</p>
              <p class="small muted"><strong>Option A:</strong> use a browser wallet (below). <strong>Option B:</strong> click <span class="mono">Generate tx intent (manual)</span> and send from another device / hardware wallet.</p>
            </div>

            <div class="panel">
              <strong>Wallet + registries</strong>
              <div class="row">
                <div>
                  <label class="k">Wallet</label>
                  <div class="small muted">Account: <span id="walletAccount" class="mono">not connected</span></div>
                  <div class="small muted">Chain: <span id="walletChain" class="mono">unknown</span></div>
                </div>
                <div style="flex: 0 0 240px">
                  <button id="connectWallet">Connect browser wallet</button>
                  <button id="switchChain" style="margin-left:8px">Switch/Add chain</button>
                </div>
              </div>

              <div class="row">
                <div>
                  <label class="k">InstanceFactory address</label>
                  <input id="instanceFactory" placeholder="0x..." autocomplete="off" readonly />
                  <div class="small muted">This factory is also the on-chain registry of trusted installations (<span class="mono">isInstance</span>).</div>
                </div>
                <div>
                  <label class="k">ReleaseRegistry address</label>
                  <input id="releaseRegistry" placeholder="0x..." autocomplete="off" readonly />
                  <div class="small muted">Must already trust your bundle root (official releases are published by the registry owner).</div>
                </div>
              </div>
            </div>

            <div class="panel">
              <strong>Authorities + policy</strong>
              <div class="row">
                <div>
                  <label class="k">Root authority (cold wallet recommended)</label>
                  <input id="rootAuthority" placeholder="0x..." autocomplete="off" />
                </div>
                <div>
                  <label class="k">Upgrade authority</label>
                  <input id="upgradeAuthority" placeholder="0x..." autocomplete="off" />
                </div>
              </div>
              <div class="row">
                <div>
                  <label class="k">Emergency authority</label>
                  <input id="emergencyAuthority" placeholder="0x..." autocomplete="off" />
                </div>
                <div>
                  <label class="k">Enforcement</label>
                  <select id="enforcement">
                    <option value="strict" selected>strict (production)</option>
                    <option value="less-strict">less-strict (hosting waiver)</option>
                    <option value="warn">warn (dev/compat)</option>
                  </select>
                  <div class="small muted">Enforcement is committed on-chain via the policy hash.</div>
                </div>
              </div>

              <div class="row">
                <div>
                  <label class="k">Policy hash (v3)</label>
                  <input id="policyHash" placeholder="0x... (computed)" autocomplete="off" readonly />
                </div>
                <div>
                  <label class="k">Policy version</label>
                  <div class="small muted"><span class="mono">v3</span> (runtime-config attestation)</div>
                </div>
              </div>
            </div>

            <div class="panel">
              <strong>Broadcast</strong>
              <p class="small muted">This step will create a new InstanceController bound to: <span class="mono">manifest.root</span> + <span class="mono">manifest.uri_hash</span> + <span class="mono">policy_hash_v3</span> (selected enforcement).</p>
              <button id="computePolicy">Compute policy hash</button>
              <button id="createInstance" style="margin-left:8px">Broadcast create tx (browser wallet)</button>
              <button id="createInstanceManual" style="margin-left:8px">Generate tx intent (manual)</button>
            </div>

            <pre id="chainOut" style="display:none"></pre>
          </div>

          <div class="card step step6" data-step="6" data-lane="server">
            <div class="cardBorder"></div>
            <div class="panel">
              <strong>Finalize</strong>
              <p>When everything is working, permanently disable this setup UI (recommended for production).</p>
              <button id="finish">Create installed.flag (disable setup)</button>
              <pre id="finishOut" style="display:none"></pre>
            </div>
          </div>
        </div>
      </div>
    </div>

      <script src="/_blackcat/ethers.umd.min.js" nonce="__BLACKCAT_CSP_NONCE__"></script>
      <script nonce="__BLACKCAT_CSP_NONCE__">
      const $ = (id) => document.getElementById(id);
      const api = async (path, opts = {}) => {
        const token = localStorage.getItem("bc_install_token") || "";
        const headers = Object.assign({ "Accept": "application/json" }, opts.headers || {});
        if (token) headers["X-BlackCat-Install-Token"] = token;
        const res = await fetch(path, Object.assign({}, opts, { headers }));
        const text = await res.text();
        let data = null;
        try { data = JSON.parse(text); } catch (e) { data = { ok: false, error: "non-json response", raw: text }; }
        if (!res.ok) return Object.assign({ http_status: res.status }, data);
        return data;
      };

	      const TOKEN_RE = /^[a-fA-F0-9]{64}$/;
      const copyText = async (text) => {
        const t = String(text || "");
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(t);
            return true;
          }
        } catch (_) {}
        try {
          const ta = document.createElement("textarea");
          ta.value = t;
          ta.setAttribute("readonly", "readonly");
          ta.style.position = "fixed";
          ta.style.left = "-9999px";
          ta.style.top = "0";
          document.body.appendChild(ta);
          ta.select();
          const ok = document.execCommand("copy");
          document.body.removeChild(ta);
          return Boolean(ok);
        } catch (_) {}
        return false;
      };
      const getStoredToken = () => localStorage.getItem("bc_install_token") || "";
	      const setTokenStatusUi = (typedToken, storedToken) => {
        const statusEl = $("tokenStatus");
        const textEl = $("tokenStatusText");
        const saveBtn = $("saveToken");
        const clearBtn = $("clearToken");

        const t = (typedToken || "").trim();
        const stored = (storedToken || "").trim();

        statusEl.classList.remove("ok", "warn", "bad");

        if (!t) {
          statusEl.classList.add("bad");
          textEl.textContent = stored ? "Token is saved in this browser." : "Token not set yet.";
          saveBtn.disabled = true;
          clearBtn.disabled = !stored;
          return;
        }

        if (!TOKEN_RE.test(t)) {
          statusEl.classList.add("warn");
          textEl.textContent = "Invalid token format.\nPaste 64‑hex from .blackcat/install.token.";
          saveBtn.disabled = true;
          clearBtn.disabled = !stored && !t;
          return;
        }

        if (t === stored && stored) {
          statusEl.classList.add("ok");
          textEl.textContent = "Token saved in this browser.";
          saveBtn.disabled = true;
        } else {
          statusEl.classList.add("warn");
          textEl.textContent = "Token looks valid. Click Save to use it for this setup session.";
          saveBtn.disabled = false;
        }
        clearBtn.disabled = !stored && !t;
	      };

	      const cssRgb = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
	      const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
	      const setAdventureMarker = (progress) => {
	        try {
	          const gutter = document.querySelector(".adventureGutter");
	          const path = document.querySelector(".adventureSvg .routeProgress");
	          if (!gutter || !path) return;
	          // Hidden on mobile: avoid NaNs + forced layouts.
	          const gr = gutter.getBoundingClientRect();
	          if (!gr || gr.height <= 0) return;

	          const total = path.getTotalLength();
	          if (!isFinite(total) || total <= 0) return;
	          const t = clamp(Number(progress || 0), 0, 1) * total;
	          const pt = path.getPointAtLength(t);
	          // viewBox is 0..100, so coords map directly to percentages.
	          const x = clamp(pt.x, 6, 94);
	          const y = clamp(pt.y, 6, 94);
	          const root = document.documentElement;
	          root.style.setProperty("--bc-adventure-marker-x", String(x));
	          root.style.setProperty("--bc-adventure-marker-y", String(y));
	        } catch (_) {}
	      };
	      const updateAdventureRoute = () => {
	        try {
	          const gutter = document.querySelector(".adventureGutter");
	          const track = document.querySelector(".adventureSvg .routeTrack");
	          const prog = document.querySelector(".adventureSvg .routeProgress");
	          const manifest = document.querySelector(".card.step.step2");
	          const rightLane = document.querySelector(".stepsLane.stepsLaneRight");
	          if (!gutter || !track || !prog) return;
	          const gr = gutter.getBoundingClientRect();
	          if (!gr || gr.height <= 0) return;

	          // Anchor: 60% height of the Manifest card (step 2 / server).
	          let yStart = 12;
	          let yAnchor = 36;
	          let xStart = 88;
	          let xEnd = 16;
	          if (manifest) {
	            const mr = manifest.getBoundingClientRect();
	            const yStartPx = mr.top + mr.height * 0.10; // start near top of Manifest region
	            const yEndPx = mr.top + mr.height * 0.60;   // end at 60% height of Manifest
	            const relStart = (yStartPx - gr.top) / gr.height;
	            const relEnd = (yEndPx - gr.top) / gr.height;
	            if (isFinite(relStart)) yStart = clamp(relStart * 100, 6, 94);
	            if (isFinite(relEnd)) yAnchor = clamp(relEnd * 100, 8, 96);

	            // Keep the route inside the gap between lanes: from the right lane's inner edge -> the Manifest edge.
	            if (rightLane) {
	              const rr = rightLane.getBoundingClientRect();
	              const gapRightPx = rr.left - gr.left; // left edge of right lane (overlay coords)
	              const gapLeftPx = mr.right - gr.left; // right edge of Manifest card (overlay coords)
	              const startPx = gapRightPx - 18; // a bit into the gap (not on the lane itself)
	              const endPx = gapLeftPx + 14;    // slightly past the Manifest border
	              const relStartX = startPx / gr.width;
	              const relEndX = endPx / gr.width;
	              if (isFinite(relStartX)) xStart = clamp(relStartX * 100, 10, 98);
	              if (isFinite(relEndX)) xEnd = clamp(relEndX * 100, 2, 90);
	            }
	          }

	          // Route request: “top-right” of the gap, then a clean half-arc down into the Manifest anchor.
	          const xLine = xStart - 10; // short horizontal “entry” so it reads like it comes from the right.
	          const yEnd = yAnchor;
	          const dx = xLine - xEnd;

	          const d = [
	            `M${xStart.toFixed(1)} ${yStart.toFixed(1)}`,
	            `L${xLine.toFixed(1)} ${yStart.toFixed(1)}`,
	            // “Semi-arc” into the Manifest anchor: start + end tangents are horizontal for a clean half-circle feel.
	            `C${(xLine - dx * 0.34).toFixed(1)} ${yStart.toFixed(1)} ${(xEnd + dx * 0.22).toFixed(1)} ${yEnd.toFixed(1)} ${xEnd.toFixed(1)} ${yEnd.toFixed(1)}`,
	          ].join(" ");

	          track.setAttribute("d", d);
	          prog.setAttribute("d", d);
	        } catch (_) {}
	      };
	      const setAdventure = (progress, fromVar, toVar) => {
	        const root = document.documentElement;
	        root.style.setProperty("--bc-adventure-progress", String(progress));
	        const from = cssRgb(fromVar);
	        const to = cssRgb(toVar);
	        if (from) root.style.setProperty("--bc-adventure-from", from);
	        if (to) root.style.setProperty("--bc-adventure-to", to);
	        updateAdventureRoute();
	        setAdventureMarker(progress);
	      };

		      const refreshStatus = async () => {
	        const token = getStoredToken();
	        $("token").value = token;
	        setTokenStatusUi(token, token);

	        // === HUD progress (best-effort, no secrets) ===
	        const setHud = (id, cls, label) => {
	          const el = document.querySelector(`.hudItem[data-hud="${id}"]`);
	          const badge = document.getElementById(`hudBadge_${id}`);
	          if (!el || !badge) return;
	          el.classList.remove("is-locked", "is-ready", "is-progress", "is-current");
	          el.classList.add(cls);
	          badge.textContent = label;
	        };
	        const tokenOk = TOKEN_RE.test(String(token || "").trim());
		        if (!tokenOk) {
		          setHud("unlock", "is-current", "CURRENT");
		          setHud("integrity", "is-locked", "LOCKED");
		          setHud("chain", "is-locked", "LOCKED");
		          setHud("done", "is-locked", "LOCKED");
		          const hud = document.getElementById("hudProgress");
		          if (hud) hud.style.setProperty("--hud-progress", "0");
		          setAdventure(0, "--bc-amber", "--bc-orange");
		          return;
		        }

	        const st = await api("/_blackcat/setup/api/status");
		        if (!st || !st.ok) {
	          // Token is syntactically valid, but the server rejected it (not the correct install token).
	          setHud("unlock", "is-current", "CURRENT");
	          setHud("integrity", "is-locked", "LOCKED");
	          setHud("chain", "is-locked", "LOCKED");
		          setHud("done", "is-locked", "LOCKED");
		          const hud = document.getElementById("hudProgress");
		          if (hud) hud.style.setProperty("--hud-progress", "0");
		          setAdventure(0, "--bc-amber", "--bc-orange");
		          return;
		        }

	        if (st.ok) {
	          const hasManifest = Boolean(st.exists && st.exists.manifest);
	          const hasConfig = Boolean(st.exists && st.exists.config);

	          // Stage mapping (4 HUD steps):
	          // - unlock: token gate
	          // - integrity: build/verify manifest
	          // - chain: create IC + config + attestation (best-effort)
	          // - done: finish/lockdown (setup becomes unavailable)
		          if (!hasManifest) {
	            setHud("unlock", "is-ready", "READY");
	            setHud("integrity", "is-progress", "IN PROGRESS");
	            setHud("chain", "is-locked", "LOCKED");
	            setHud("done", "is-locked", "LOCKED");
		            const hud = document.getElementById("hudProgress");
		            if (hud) hud.style.setProperty("--hud-progress", "0.33");
		            setAdventure(0.33, "--bc-orange", "--bc-accent2");
		          } else {
	            setHud("unlock", "is-ready", "READY");
	            setHud("integrity", "is-ready", "READY");
	            setHud("chain", "is-current", hasConfig ? "IN PROGRESS" : "CURRENT");
	            setHud("done", "is-locked", "LOCKED");
		            const hud = document.getElementById("hudProgress");
		            if (hud) hud.style.setProperty("--hud-progress", "0.66");
		            setAdventure(0.66, "--bc-accent2", "--bc-violet");
		          }

          if (st.suggested && st.suggested.rpc_endpoints) {
            $("rpcEndpoints").value = st.suggested.rpc_endpoints.join("\\n");
          }
          if (st.suggested && st.suggested.allowed_hosts) {
            $("allowedHosts").value = st.suggested.allowed_hosts.join("\\n");
          }
          if (st.summary && st.summary.root) {
            // Best-effort: show root in the manifest output panel for convenience.
            $("manifestOut").style.display = "block";
            $("manifestOut").textContent = JSON.stringify(st.summary, null, 2);
          }
        }
      };

      const CHAIN_ID_DEC = 4207;
      const CHAIN_ID_HEX = "0x106f";
      const DEFAULT_FACTORY = "0x92C80Cff5d75dcD3846EFb5DF35957D5Aed1c7C5";
      const DEFAULT_REGISTRY = "0x22681Ee2153B7B25bA6772B44c160BB60f4C333E";
      const EXPLORER_BASE = "https://edgenscan.io";
      const DEFAULT_ENFORCEMENT = "__BLACKCAT_ENFORCEMENT__";

      const isHexAddress = (v) => typeof v === "string" && /^0x[a-fA-F0-9]{40}$/.test(v.trim());
      const isBytes32 = (v) => typeof v === "string" && /^0x[a-fA-F0-9]{64}$/.test(v.trim());

      const wallet = {
        provider: null,
        signer: null,
        account: null,
        chainId: null,
      };

      const setWalletUi = () => {
        $("walletAccount").textContent = wallet.account || "not connected";
        $("walletChain").textContent = wallet.chainId ? `${wallet.chainId}` : "unknown";
      };

	      const requireEthereum = () => {
	        const eth = window.ethereum;
	        if (!eth || !eth.request) {
	          throw new Error("Browser wallet not found (window.ethereum). Install MetaMask/Rabby (or use the manual tx intent buttons).");
	        }
	        if (!window.ethers) {
	          throw new Error("ethers.js failed to load. Ensure /_blackcat/ethers.umd.min.js is reachable.");
	        }
	        return eth;
	      };

      const connectWallet = async () => {
        const eth = requireEthereum();
        await eth.request({ method: "eth_requestAccounts" });
        wallet.provider = new window.ethers.providers.Web3Provider(eth, "any");
        wallet.signer = wallet.provider.getSigner();
        wallet.account = (await wallet.signer.getAddress()) || null;
        wallet.chainId = (await wallet.provider.getNetwork()).chainId || null;
        setWalletUi();

        // Default authorities to the connected account (user can override).
        if (wallet.account && isHexAddress(wallet.account)) {
          if (!isHexAddress($("rootAuthority").value)) $("rootAuthority").value = wallet.account;
          if (!isHexAddress($("upgradeAuthority").value)) $("upgradeAuthority").value = wallet.account;
          if (!isHexAddress($("emergencyAuthority").value)) $("emergencyAuthority").value = wallet.account;
          saveAuthorities();
        }
      };

      const ensureChain = async () => {
        const eth = requireEthereum();
        try {
          await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_ID_HEX }] });
        } catch (e) {
          // 4902 = unknown chain
          const code = e && typeof e === "object" ? e.code : null;
          if (code !== 4902) throw e;
          await eth.request({
            method: "wallet_addEthereumChain",
            params: [
              {
                chainId: CHAIN_ID_HEX,
                chainName: "Edgen Chain",
                rpcUrls: ["https://rpc.layeredge.io"],
                nativeCurrency: { name: "EDGEN", symbol: "EDGEN", decimals: 18 },
                blockExplorerUrls: ["https://edgenscan.io"],
              },
            ],
          });
        }

        if (wallet.provider) {
          wallet.chainId = (await wallet.provider.getNetwork()).chainId || null;
          setWalletUi();
        }
      };

      const readManifestSummary = async () => {
        const st = await api("/_blackcat/setup/api/status");
        if (!st || !st.ok) throw new Error(st && st.error ? st.error : "Unable to read /status");
        if (!st.summary || !st.summary.root || !st.summary.uri_hash) {
          throw new Error("Missing manifest summary. Run 'Build manifest' first.");
        }
        const root = String(st.summary.root || "").trim();
        const uriHash = String(st.summary.uri_hash || "").trim();
        if (!isBytes32(root) || !isBytes32(uriHash)) throw new Error("Invalid manifest summary bytes32 values.");
        return { root, uriHash };
      };

      const setReleaseRegistryLink = () => {
        const addr = $("releaseRegistry").value.trim();
        const href = isHexAddress(addr) ? `${EXPLORER_BASE}/address/${addr}` : EXPLORER_BASE;
        $("releaseRegistryLink").setAttribute("href", href);
      };

      const setReleaseTrustUi = (trusted, error = null) => {
        const el = $("releaseTrust");
        if (error) {
          el.textContent = "error";
          el.classList.remove("ok");
          el.classList.add("bad");
          el.setAttribute("title", String(error));
          $("createInstance").disabled = true;
          return;
        }
        if (trusted === true) {
          el.textContent = "trusted";
          el.classList.remove("bad");
          el.classList.add("ok");
          el.removeAttribute("title");
          $("createInstance").disabled = false;
          return;
        }
        if (trusted === false) {
          el.textContent = "untrusted";
          el.classList.remove("ok");
          el.classList.add("bad");
          el.setAttribute("title", "ReleaseRegistry does not trust this root (tampered/unpublished).");
          $("createInstance").disabled = true;
          return;
        }
        el.textContent = "unknown";
        el.classList.remove("ok");
        el.classList.remove("bad");
        el.removeAttribute("title");
        $("createInstance").disabled = true;
      };

      const verifyReleaseRoot = async () => {
        const { root } = await readManifestSummary();
        const registry = $("releaseRegistry").value.trim();
        if (!isHexAddress(registry)) throw new Error("Invalid ReleaseRegistry address.");

	        if (!wallet.provider) {
	          throw new Error("Connect a browser wallet first to verify on-chain release trust (or verify in the block explorer).");
	        }
	        if (wallet.chainId !== CHAIN_ID_DEC) {
	          throw new Error("Switch to Edgen Chain (chain_id=4207) first.");
	        }

        const registryAbi = [
          "function isTrustedRoot(bytes32 root) view returns (bool)",
        ];
        const rr = new window.ethers.Contract(registry, registryAbi, wallet.provider);
        const ok = await rr.isTrustedRoot(root);
        setReleaseTrustUi(Boolean(ok));
        return Boolean(ok);
      };

      const normalizeEnforcement = (raw) => {
        const v = (typeof raw === "string" ? raw : "").trim();
        if (v === "strict" || v === "less-strict" || v === "warn") return v;
        return "strict";
      };
      const getEnforcement = () => normalizeEnforcement($("enforcement").value);
      const loadEnforcement = () => {
        const fromUrl = normalizeEnforcement(DEFAULT_ENFORCEMENT);
        if (fromUrl !== "strict") return fromUrl;
        try {
          const raw = localStorage.getItem("bc_enforcement");
          if (raw) return normalizeEnforcement(raw);
        } catch (_) {}
        return fromUrl;
      };
      const applyEnforcement = () => {
        $("enforcement").value = loadEnforcement();
      };

      const computePolicyHash = async () => {
        const mode = $("trustMode").value;
        const maxStale = parseInt($("maxStale").value || "180", 10);
        const enforcement = getEnforcement();
        const res = await api("/_blackcat/setup/api/policy-v3", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode, max_stale_sec: maxStale, enforcement }),
        });
        if (!res || !res.ok) throw new Error(res && res.error ? res.error : "policy-v3 failed");
        const policyHash = res.policy_hash_v3 || res.policy_hash_v3_strict;
        if (!policyHash || !isBytes32(policyHash)) throw new Error("Invalid policy hash.");
        $("policyHash").value = policyHash;
        return policyHash;
      };

      const saveAuthorities = () => {
        const data = {
          root: $("rootAuthority").value.trim(),
          upgrade: $("upgradeAuthority").value.trim(),
          emergency: $("emergencyAuthority").value.trim(),
        };
        localStorage.setItem("bc_authorities", JSON.stringify(data));
      };
      const loadAuthorities = () => {
        try {
          const raw = localStorage.getItem("bc_authorities");
          if (!raw) return;
          const parsed = JSON.parse(raw);
          if (parsed && typeof parsed === "object") {
            if (typeof parsed.root === "string") $("rootAuthority").value = parsed.root;
            if (typeof parsed.upgrade === "string") $("upgradeAuthority").value = parsed.upgrade;
            if (typeof parsed.emergency === "string") $("emergencyAuthority").value = parsed.emergency;
          }
        } catch (_) {}
      };

      $("saveToken").addEventListener("click", async () => {
        const t = $("token").value.trim();
        if (!TOKEN_RE.test(t)) {
          setTokenStatusUi(t, getStoredToken());
          return;
        }
        localStorage.setItem("bc_install_token", t);
        await refreshStatus();
      });

      $("token").addEventListener("input", () => {
        setTokenStatusUi($("token").value, getStoredToken());
      });

      $("rootAuthority").addEventListener("change", saveAuthorities);
      $("upgradeAuthority").addEventListener("change", saveAuthorities);
      $("emergencyAuthority").addEventListener("change", saveAuthorities);
      $("clearToken").addEventListener("click", async () => {
        localStorage.removeItem("bc_install_token");
        $("token").value = "";
        await refreshStatus();
      });

      $("toggleToken").addEventListener("click", () => {
        const input = $("token");
        const isPassword = input.type === "password";
        input.type = isPassword ? "text" : "password";
        $("toggleToken").textContent = isPassword ? "Hide" : "Show";
        // Refresh status styling for the current typed value.
        setTokenStatusUi(input.value, getStoredToken());
      });

      $("copyTokenPath").addEventListener("click", async () => {
        const ok = await copyText(".blackcat/install.token");
        $("tokenStatusText").textContent = ok ? "Copied: .blackcat/install.token" : "Copy failed. Manually copy: .blackcat/install.token";
      });

      $("copyFtpChecklist").addEventListener("click", async () => {
        const checklist =
          "BlackCat setup token (FTP/SFTP checklist)\\n"
          + "1) Go to the bundle root (the folder that contains 'site/').\\n"
          + "2) Open '.blackcat/install.token' in a text editor (plain text).\\n"
          + "3) Copy the 64-hex token (one line).\\n"
          + "4) Paste it into the Setup page and click Save.\\n"
          + "Security: keep the token private and delete setup after install.";
        const ok = await copyText(checklist);
        $("tokenStatusText").textContent = ok ? "Copied FTP checklist to clipboard." : "Copy failed. Use the on-page instructions.";
      });

      $("buildManifest").addEventListener("click", async () => {
        $("manifestOut").style.display = "block";
        $("manifestOut").textContent = "Working...";
        $("releaseOut").style.display = "none";
        const res = await api("/_blackcat/setup/api/build-manifest", { method: "POST" });
        $("manifestOut").textContent = JSON.stringify(res, null, 2);
        setReleaseTrustUi(null);
        try {
          if (wallet.provider && wallet.chainId === CHAIN_ID_DEC) {
            const ok = await verifyReleaseRoot();
            $("releaseOut").style.display = "block";
            $("releaseOut").textContent = JSON.stringify({ ok: true, trusted: ok }, null, 2);
          }
        } catch (_) {
          // ignore here; user can click "Verify release root" after connecting wallet.
        }
      });

      $("verifyRelease").addEventListener("click", async () => {
        $("releaseOut").style.display = "block";
        $("releaseOut").textContent = "Working...";
        try {
          const ok = await verifyReleaseRoot();
          $("releaseOut").textContent = JSON.stringify({ ok: true, trusted: ok }, null, 2);
        } catch (e) {
          setReleaseTrustUi(null);
          $("releaseOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
        }
      });

      $("connectWallet").addEventListener("click", async () => {
        $("chainOut").style.display = "block";
        $("chainOut").textContent = "Working...";
        try {
          await connectWallet();
          setReleaseRegistryLink();
          if (wallet.chainId === CHAIN_ID_DEC) {
            try {
              const ok = await verifyReleaseRoot();
              $("releaseOut").style.display = "block";
              $("releaseOut").textContent = JSON.stringify({ ok: true, trusted: ok }, null, 2);
            } catch (_) {}
          }
          $("chainOut").textContent = JSON.stringify({ ok: true, account: wallet.account, chain_id: wallet.chainId }, null, 2);
        } catch (e) {
          $("chainOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
        }
      });
      $("switchChain").addEventListener("click", async () => {
        $("chainOut").style.display = "block";
        $("chainOut").textContent = "Working...";
        try {
          await ensureChain();
          setReleaseRegistryLink();
          if (wallet.chainId === CHAIN_ID_DEC) {
            try {
              const ok = await verifyReleaseRoot();
              $("releaseOut").style.display = "block";
              $("releaseOut").textContent = JSON.stringify({ ok: true, trusted: ok }, null, 2);
            } catch (_) {}
          }
          $("chainOut").textContent = JSON.stringify({ ok: true, chain_id: wallet.chainId }, null, 2);
        } catch (e) {
          $("chainOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
        }
      });

      $("computePolicy").addEventListener("click", async () => {
        $("chainOut").style.display = "block";
        $("chainOut").textContent = "Working...";
        try {
          const policy = await computePolicyHash();
          const enforcement = getEnforcement();
          $("chainOut").textContent = JSON.stringify({ ok: true, enforcement, policy_hash_v3: policy }, null, 2);
        } catch (e) {
          $("chainOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
        }
      });

	      $("createInstance").addEventListener("click", async () => {
	        $("chainOut").style.display = "block";
	        $("chainOut").textContent = "Working...";
	        try {
	          if (!wallet.signer) await connectWallet();
          if (wallet.chainId !== CHAIN_ID_DEC) {
            await ensureChain();
            wallet.chainId = (await wallet.provider.getNetwork()).chainId || null;
            setWalletUi();
          }
          if (wallet.chainId !== CHAIN_ID_DEC) throw new Error("Wrong chain. Expected chain_id=4207 (Edgen).");

          const factoryAddress = $("instanceFactory").value.trim();
          if (!isHexAddress(factoryAddress)) throw new Error("Invalid InstanceFactory address.");
          const rootAuthority = $("rootAuthority").value.trim();
          const upgradeAuthority = $("upgradeAuthority").value.trim();
          const emergencyAuthority = $("emergencyAuthority").value.trim();
          if (!isHexAddress(rootAuthority)) throw new Error("Invalid root authority address.");
          if (!isHexAddress(upgradeAuthority)) throw new Error("Invalid upgrade authority address.");
          if (!isHexAddress(emergencyAuthority)) throw new Error("Invalid emergency authority address.");

          const { root, uriHash } = await readManifestSummary();
          const releaseOk = await verifyReleaseRoot();
          if (!releaseOk) {
            throw new Error("Release root is NOT trusted by ReleaseRegistry. Upload an official bundle or wait for the registry to be updated.");
          }
          const policyHash = await computePolicyHash();

          const factoryAbi = [
            "function createInstance(address rootAuthority,address upgradeAuthority,address emergencyAuthority,bytes32 genesisRoot,bytes32 genesisUriHash,bytes32 genesisPolicyHash) returns (address)",
            "event InstanceCreated(address indexed instance,address indexed rootAuthority,address indexed upgradeAuthority,address emergencyAuthority,address createdBy)",
          ];

          const factory = new window.ethers.Contract(factoryAddress, factoryAbi, wallet.signer);
          const predicted = await factory.callStatic.createInstance(
            rootAuthority,
            upgradeAuthority,
            emergencyAuthority,
            root,
            uriHash,
            policyHash
          );

          const tx = await factory.createInstance(
            rootAuthority,
            upgradeAuthority,
            emergencyAuthority,
            root,
            uriHash,
            policyHash
          );

          $("chainOut").textContent = JSON.stringify(
            {
              ok: true,
              stage: "broadcasted",
              tx_hash: tx.hash,
              tx_link: `${EXPLORER_BASE}/tx/${tx.hash}`,
              predicted_instance: predicted,
              instance_link: `${EXPLORER_BASE}/address/${predicted}`,
            },
            null,
            2
          );
          const receipt = await tx.wait();

          $("instanceController").value = predicted;
          localStorage.setItem("bc_instance_controller", predicted);

          $("chainOut").textContent = JSON.stringify(
            {
              ok: true,
              stage: "mined",
              tx_hash: tx.hash,
              tx_link: `${EXPLORER_BASE}/tx/${tx.hash}`,
              block: receipt.blockNumber,
              instance_controller: predicted,
              instance_link: `${EXPLORER_BASE}/address/${predicted}`,
              manifest_root: root,
              manifest_uri_hash: uriHash,
              enforcement: getEnforcement(),
              policy_hash_v3: policyHash,
            },
            null,
            2
          );
        } catch (e) {
          $("chainOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
	        }
	      });

	      $("createInstanceManual").addEventListener("click", async () => {
	        $("chainOut").style.display = "block";
	        $("chainOut").textContent = "Working...";
	        try {
	          if (!window.ethers) throw new Error("ethers.js failed to load. Ensure /_blackcat/ethers.umd.min.js is reachable.");

	          const factoryAddress = $("instanceFactory").value.trim();
	          if (!isHexAddress(factoryAddress)) throw new Error("Invalid InstanceFactory address.");
	          const rootAuthority = $("rootAuthority").value.trim();
	          const upgradeAuthority = $("upgradeAuthority").value.trim();
	          const emergencyAuthority = $("emergencyAuthority").value.trim();
	          if (!isHexAddress(rootAuthority)) throw new Error("Invalid root authority address.");
	          if (!isHexAddress(upgradeAuthority)) throw new Error("Invalid upgrade authority address.");
	          if (!isHexAddress(emergencyAuthority)) throw new Error("Invalid emergency authority address.");

	          const { root, uriHash } = await readManifestSummary();
	          const policyHash = await computePolicyHash();

	          const abi = [
	            "function createInstance(address rootAuthority,address upgradeAuthority,address emergencyAuthority,bytes32 genesisRoot,bytes32 genesisUriHash,bytes32 genesisPolicyHash) returns (address)",
	          ];
	          const iface = new window.ethers.utils.Interface(abi);
	          const data = iface.encodeFunctionData("createInstance", [
	            rootAuthority,
	            upgradeAuthority,
	            emergencyAuthority,
	            root,
	            uriHash,
	            policyHash,
	          ]);

	          const cast = [
	            "cast send --rpc-url https://rpc.layeredge.io \\",
	            `  ${factoryAddress} \\`,
	            "  \"createInstance(address,address,address,bytes32,bytes32,bytes32)\" \\",
	            `  ${rootAuthority} ${upgradeAuthority} ${emergencyAuthority} ${root} ${uriHash} ${policyHash}`,
	          ].join("\n");

	          $("chainOut").textContent = JSON.stringify(
	            {
	              ok: true,
	              mode: "manual_tx_intent",
	              chain_id: CHAIN_ID_DEC,
	              to: factoryAddress,
	              value: "0x0",
	              data,
	              args: {
	                root_authority: rootAuthority,
	                upgrade_authority: upgradeAuthority,
	                emergency_authority: emergencyAuthority,
	                manifest_root: root,
	                manifest_uri_hash: uriHash,
	                enforcement: getEnforcement(),
	                policy_hash_v3: policyHash,
	              },
	              notes: [
	                "Send this transaction from a separate device / hardware wallet if desired.",
	                "If the bundle root is not trusted by ReleaseRegistry, the tx is expected to REVERT (fail-closed).",
	                "After it is mined, copy the InstanceCreated event 'instance' address and paste it into step 4.",
	              ],
	              explorer_factory: `${EXPLORER_BASE}/address/${factoryAddress}`,
	              cli_example_cast: cast,
	            },
	            null,
	            2
	          );
	        } catch (e) {
	          $("chainOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
	        }
	      });

	      $("writeConfig").addEventListener("click", async () => {
	        $("configOut").style.display = "block";
	        $("configOut").textContent = "Working...";
        const endpoints = $("rpcEndpoints").value.split(/\\r?\\n/).map(s => s.trim()).filter(Boolean);
        const hosts = $("allowedHosts").value.split(/\\r?\\n/).map(s => s.trim()).filter(Boolean);
        const payload = {
          instance_controller: $("instanceController").value.trim(),
          rpc_endpoints: endpoints,
          rpc_quorum: parseInt($("rpcQuorum").value || "1", 10),
          mode: $("trustMode").value,
          max_stale_sec: parseInt($("maxStale").value || "180", 10),
          enforcement: getEnforcement(),
          allowed_hosts: hosts,
        };
        const res = await api("/_blackcat/setup/api/write-config", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        $("configOut").textContent = JSON.stringify(res, null, 2);
        if (res && res.ok && res.runtime_config_attestation) {
          localStorage.setItem("bc_runtime_attestation", JSON.stringify(res.runtime_config_attestation));
        }
      });

	      $("lockAttestation").addEventListener("click", async () => {
	        $("attOut").style.display = "block";
	        $("attOut").textContent = "Working...";
	        try {
	          if (!wallet.signer) await connectWallet();
          if (wallet.chainId !== CHAIN_ID_DEC) {
            await ensureChain();
            wallet.chainId = (await wallet.provider.getNetwork()).chainId || null;
            setWalletUi();
          }
          if (wallet.chainId !== CHAIN_ID_DEC) throw new Error("Wrong chain. Expected chain_id=4207 (Edgen).");

	          const instance = $("instanceController").value.trim();
	          if (!isHexAddress(instance)) throw new Error("Invalid InstanceController address.");
	
	          const rootAuthority = $("rootAuthority").value.trim();
	          if (isHexAddress(rootAuthority) && wallet.account && rootAuthority.toLowerCase() !== wallet.account.toLowerCase()) {
	            throw new Error("Connect the ROOT authority account in your browser wallet to lock the attestation.");
	          }

          const raw = localStorage.getItem("bc_runtime_attestation");
          if (!raw) throw new Error("No runtime attestation found. Write config first.");
          const att = JSON.parse(raw);
          const key = String(att.key || "").trim();
          const value = String(att.value || "").trim();
          if (!isBytes32(key) || !isBytes32(value)) throw new Error("Invalid attestation key/value.");

          const controllerAbi = [
            "function setAttestationAndLock(bytes32 key,bytes32 value)",
          ];
          const controller = new window.ethers.Contract(instance, controllerAbi, wallet.signer);
          const tx = await controller.setAttestationAndLock(key, value);
          $("attOut").textContent = JSON.stringify({ ok: true, stage: "broadcasted", tx_hash: tx.hash, key, value }, null, 2);
          const receipt = await tx.wait();
          $("attOut").textContent = JSON.stringify({ ok: true, stage: "mined", tx_hash: tx.hash, block: receipt.blockNumber, key, value }, null, 2);
        } catch (e) {
          $("attOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
	        }
	      });

	      $("lockAttestationManual").addEventListener("click", async () => {
	        $("attOut").style.display = "block";
	        $("attOut").textContent = "Working...";
	        try {
	          if (!window.ethers) throw new Error("ethers.js failed to load. Ensure /_blackcat/ethers.umd.min.js is reachable.");

	          const instance = $("instanceController").value.trim();
	          if (!isHexAddress(instance)) throw new Error("Invalid InstanceController address.");

	          const raw = localStorage.getItem("bc_runtime_attestation");
	          if (!raw) throw new Error("No runtime attestation found. Write config first.");
	          const att = JSON.parse(raw);
	          const key = String(att.key || "").trim();
	          const value = String(att.value || "").trim();
	          if (!isBytes32(key) || !isBytes32(value)) throw new Error("Invalid attestation key/value.");

	          const abi = ["function setAttestationAndLock(bytes32 key,bytes32 value)"];
	          const iface = new window.ethers.utils.Interface(abi);
	          const data = iface.encodeFunctionData("setAttestationAndLock", [key, value]);

	          const cast = [
	            "cast send --rpc-url https://rpc.layeredge.io \\",
	            `  ${instance} \\`,
	            "  \"setAttestationAndLock(bytes32,bytes32)\" \\",
	            `  ${key} ${value}`,
	          ].join("\n");

	          $("attOut").textContent = JSON.stringify(
	            {
	              ok: true,
	              mode: "manual_tx_intent",
	              chain_id: CHAIN_ID_DEC,
	              to: instance,
	              value: "0x0",
	              data,
	              args: { key, value },
	              notes: [
	                "This must be signed by the ROOT authority (cold wallet recommended).",
	                "After it is mined, the attestation key is locked on-chain.",
	              ],
	              explorer_instance: `${EXPLORER_BASE}/address/${instance}`,
	              cli_example_cast: cast,
	            },
	            null,
	            2
	          );
	        } catch (e) {
	          $("attOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
	        }
	      });

	      $("finish").addEventListener("click", async () => {
	        $("finishOut").style.display = "block";
	        $("finishOut").textContent = "Working...";
	        const res = await api("/_blackcat/setup/api/finish", { method: "POST" });
	        $("finishOut").textContent = JSON.stringify(res, null, 2);
		        if (res && res.ok) {
		          const hud = document.getElementById("hudProgress");
		          if (hud) hud.style.setProperty("--hud-progress", "1");
		          setAdventure(1, "--bc-violet", "--bc-violet");
		          const doneEl = document.querySelector('.hudItem[data-hud="done"]');
		          const doneBadge = document.getElementById("hudBadge_done");
		          if (doneEl && doneBadge) {
		            doneEl.classList.remove("is-locked", "is-current", "is-progress");
		            doneEl.classList.add("is-ready");
		            doneBadge.textContent = "DONE";
		          }
		        }
		      });

	      refreshStatus();
	      // Keep the “adventure path” anchored to the Manifest card even if layout changes (resize).
	      let bcAdventureResizeTimer = null;
	      window.addEventListener("resize", () => {
	        if (bcAdventureResizeTimer) clearTimeout(bcAdventureResizeTimer);
	        bcAdventureResizeTimer = setTimeout(() => {
	          try {
	            updateAdventureRoute();
	            const hud = document.getElementById("hudProgress");
	            const p = hud ? Number(getComputedStyle(hud).getPropertyValue("--hud-progress")) : 0;
	            setAdventureMarker(isFinite(p) ? p : 0);
	          } catch (_) {}
	        }, 90);
	      });
      // Keep the HUD + status panels in sync when files are created via FTP or other out-of-band actions.
      // This is best-effort and lightweight (local JSON endpoint).
      setInterval(() => {
        if (document.hidden) return;
        refreshStatus().catch(() => {});
      }, 4500);

      // Defaults + local cache restore
      $("instanceFactory").value = DEFAULT_FACTORY;
      $("releaseRegistry").value = DEFAULT_REGISTRY;
      setReleaseRegistryLink();
      applyEnforcement();
      $("enforcement").addEventListener("change", () => {
        const v = getEnforcement();
        try { localStorage.setItem("bc_enforcement", v); } catch (_) {}
        $("policyHash").value = "";
      });
      const cachedIc = localStorage.getItem("bc_instance_controller");
      if (cachedIc && isHexAddress(cachedIc)) $("instanceController").value = cachedIc;
      loadAuthorities();
      setReleaseTrustUi(null);
      </script>
    </div>

    __BLACKCAT_TLS_BAR__
  </body>
</html>
HTML;

    echo str_replace(
        ['__BLACKCAT_TLS_BAR__', '__BLACKCAT_TRUST_ILLUSTRATION__', '__BLACKCAT_OVERVIEW_ILLUSTRATION__', '__BLACKCAT_CSP_NONCE__', '__BLACKCAT_ENFORCEMENT__', '__BLACKCAT_UI_MAP__'],
        [$tlsBarHtml, $trustIllustrationHtml, $overviewIllustrationHtml, $nonce, blackcat_setup_policy(), $uiMapValue],
        $page,
    );
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_api(array $paths, string $endpoint): void
{
    if (!blackcat_is_https_request()) {
        blackcat_json(['ok' => false, 'error' => 'HTTPS is required for setup.'], 400);
        return;
    }

    if (blackcat_setup_is_disabled($paths['state_dir'])) {
        $hostPort = blackcat_normalize_http_host($_SERVER['HTTP_HOST'] ?? null);
        $isDev = blackcat_is_dev_host($hostPort['host']);
        if ($isDev) {
            blackcat_json(['ok' => false, 'error' => 'Setup is disabled (installed.flag present).'], 403);
            return;
        }
        blackcat_json(['ok' => false, 'error' => 'Not found.'], 404);
        return;
    }

    $tlsGate = blackcat_setup_tls_gate($paths['state_dir']);
    if ($tlsGate['mode'] === 'prod' && $tlsGate['trusted'] !== true) {
        blackcat_json([
            'ok' => false,
            'error' => 'Trusted TLS is required for production setup (CA verification failed).',
        ], 400);
        return;
    }

    if (blackcat_setup_is_disabled($paths['state_dir'])) {
        blackcat_json(['ok' => false, 'error' => 'Setup is disabled (installed.flag present).'], 403);
        return;
    }

    $token = blackcat_read_install_token($paths['state_dir']);
    if ($token === null) {
        blackcat_json(['ok' => false, 'error' => 'Missing install token file (.blackcat/install.token).'], 500);
        return;
    }

    $provided = blackcat_read_provided_token();
    if ($provided === null || !hash_equals($token, $provided)) {
        blackcat_json(['ok' => false, 'error' => 'Invalid or missing install token.'], 401);
        return;
    }

    $endpoint = trim($endpoint, "/ \t\r\n");
    if ($endpoint === 'status') {
        blackcat_setup_api_status($paths);
        return;
    }

    if ($endpoint === 'build-manifest') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            blackcat_json(['ok' => false, 'error' => 'Method not allowed.'], 405);
            return;
        }
        blackcat_setup_api_build_manifest($paths);
        return;
    }

    if ($endpoint === 'write-config') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            blackcat_json(['ok' => false, 'error' => 'Method not allowed.'], 405);
            return;
        }
        blackcat_setup_api_write_config($paths);
        return;
    }

    if ($endpoint === 'policy-v3') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            blackcat_json(['ok' => false, 'error' => 'Method not allowed.'], 405);
            return;
        }
        blackcat_setup_api_policy_v3();
        return;
    }

    if ($endpoint === 'finish') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            blackcat_json(['ok' => false, 'error' => 'Method not allowed.'], 405);
            return;
        }
        blackcat_setup_api_finish($paths);
        return;
    }

    blackcat_json(['ok' => false, 'error' => 'Unknown endpoint: ' . $endpoint], 404);
}

/**
 * Production safety gate: require CA-trusted TLS for the setup flow.
 *
 * Why:
 * - The setup UI controls on-chain authorities + runtime config.
 * - A MITM during setup can swap addresses/policies and steal control permanently.
 * - Browsers don't expose "certificate trusted" reliably to JS; this is verified from the server side.
 *
 * @return array{mode:'dev'|'prod',host:string,port:int,trusted:bool,error:?string}
 */
function blackcat_setup_tls_gate(string $stateDir): array
{
    blackcat_ensure_state_dir($stateDir);

    $hostPort = blackcat_normalize_http_host($_SERVER['HTTP_HOST'] ?? null);
    $host = $hostPort['host'];
    $port = $hostPort['port'];
    $mode = blackcat_is_dev_host($host) ? 'dev' : 'prod';

    $cachePath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'tls.trust.cache.json';
    $cache = null;
    if (is_file($cachePath)) {
        $raw = file_get_contents($cachePath);
        if (is_string($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $cache = $decoded;
            }
        }
    }

    $cacheOk = false;
    if (is_array($cache)) {
        $ts = $cache['checked_at'] ?? null;
        $ch = $cache['host'] ?? null;
        $cp = $cache['port'] ?? null;
        if (is_int($ts) && is_string($ch) && is_int($cp)) {
            if ($ch === $host && $cp === $port && (time() - $ts) < 60) {
                $cacheOk = true;
            }
        }
    }

    if ($cacheOk) {
        return [
            'mode' => $mode,
            'host' => $host,
            'port' => $port,
            'trusted' => (bool) ($cache['trusted'] ?? false),
            'error' => is_string($cache['error'] ?? null) ? (string) $cache['error'] : null,
        ];
    }

    [$trusted, $err] = blackcat_tls_is_publicly_trusted($host, $port);

    $payload = [
        'checked_at' => time(),
        'host' => $host,
        'port' => $port,
        'trusted' => $trusted,
        'error' => $err,
    ];
    @file_put_contents($cachePath, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    if (DIRECTORY_SEPARATOR !== '\\') {
        @chmod($cachePath, 0600);
    }

    return [
        'mode' => $mode,
        'host' => $host,
        'port' => $port,
        'trusted' => $trusted,
        'error' => $err,
    ];
}

/**
 * @return array{host:string,port:int}
 */
function blackcat_normalize_http_host(mixed $raw): array
{
    $fallback = ['host' => '', 'port' => 443];

    if (!is_string($raw)) {
        return $fallback;
    }

    $raw = trim($raw);
    if ($raw === '' || str_contains($raw, "\0") || str_contains($raw, '/') || str_contains($raw, '\\')) {
        return $fallback;
    }

    // IPv6 in brackets: [::1]:443
    if (str_starts_with($raw, '[')) {
        $end = strpos($raw, ']');
        if ($end === false) {
            return $fallback;
        }
        $host = substr($raw, 1, $end - 1);
        $rest = substr($raw, $end + 1);
        $port = 443;
        if (str_starts_with($rest, ':')) {
            $portRaw = substr($rest, 1);
            if ($portRaw !== '' && ctype_digit($portRaw)) {
                $p = (int) $portRaw;
                if ($p >= 1 && $p <= 65535) {
                    $port = $p;
                }
            }
        }
        return ['host' => strtolower(trim($host)), 'port' => $port];
    }

    $host = $raw;
    $port = 443;
    if (preg_match('/^(.+):(\\d{1,5})$/', $raw, $m) === 1) {
        $host = $m[1];
        $p = (int) $m[2];
        if ($p >= 1 && $p <= 65535) {
            $port = $p;
        }
    }

    return ['host' => strtolower(trim($host)), 'port' => $port];
}

function blackcat_is_dev_host(string $host): bool
{
    $host = strtolower(trim($host));
    if ($host === '' || str_contains($host, "\0")) {
        return false;
    }

    if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
        return true;
    }

    if (@filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        return str_starts_with($host, '127.');
    }

    if (@filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        return $host === '::1';
    }

    return false;
}

/**
 * Installer UI policy selector (enforcement).
 *
 * - strict: production default (fail-closed)
 * - less-strict: still fail-closed, but allows a limited set of probe-based waivers
 * - warn: compatibility mode (do not use for production)
 *
 * @return 'strict'|'less-strict'|'warn'
 */
function blackcat_setup_policy(): string
{
    $raw = $_GET['policy'] ?? null;
    if (is_string($raw)) {
        $v = strtolower(trim($raw));
        if ($v === 'warn' || $v === 'dev') {
            return 'warn';
        }
        if ($v === 'less-strict' || $v === 'less_strict' || $v === 'lessstrict' || $v === 'ls') {
            return 'less-strict';
        }
        if ($v === 'strict' || $v === 'prod') {
            return 'strict';
        }
    }
    return 'strict';
}

/**
 * @return array{0:bool,1:?string} (trusted, error_code)
 */
function blackcat_tls_is_publicly_trusted(string $host, int $port): array
{
    $host = strtolower(trim($host));
    if ($host === '' || str_contains($host, "\0")) {
        return [false, 'invalid_host'];
    }

    // SSRF hardening: reject private/reserved IP literals (except localhost dev).
    if (@filter_var($host, FILTER_VALIDATE_IP) !== false) {
        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        if (@filter_var($host, FILTER_VALIDATE_IP, $flags) === false) {
            return [false, 'host_is_private_ip'];
        }
    } else {
        // Conservative hostname validation to avoid Host-header tricks.
        if (preg_match('/^[a-z0-9.-]+$/', $host) !== 1 || strlen($host) > 253) {
            return [false, 'invalid_hostname'];
        }

        $ips = [];
        $a = @gethostbynamel($host);
        if (is_array($a)) {
            foreach ($a as $ip) {
                if (is_string($ip)) {
                    $ips[] = $ip;
                }
            }
        }
        if (function_exists('dns_get_record')) {
            $aaaa = @dns_get_record($host, DNS_AAAA);
            if (is_array($aaaa)) {
                foreach ($aaaa as $row) {
                    $ip = $row['ipv6'] ?? null;
                    if (is_string($ip)) {
                        $ips[] = $ip;
                    }
                }
            }
        }

        if ($ips === []) {
            return [false, 'dns_no_records'];
        }

        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        foreach ($ips as $ip) {
            if (@filter_var($ip, FILTER_VALIDATE_IP, $flags) === false) {
                return [false, 'dns_resolves_to_private_ip'];
            }
        }
    }

    $connectHost = $host;
    if (@filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        $connectHost = '[' . $host . ']';
    }

    // Prefer OpenSSL extension (stream_socket_client + strict peer verification).
    if (extension_loaded('openssl')) {
        $ctx = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false,
                'SNI_enabled' => true,
                'peer_name' => $host,
                'disable_compression' => true,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $timeout = 2.0;
        $fp = @stream_socket_client(
            'ssl://' . $connectHost . ':' . $port,
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $ctx
        );

        if (!is_resource($fp)) {
            return [false, 'tls_connect_failed'];
        }

        @stream_set_timeout($fp, 2);
        @fclose($fp);
        return [true, null];
    }

    // Fallback: cURL HTTPS verification (does not require PHP OpenSSL extension).
    $hasCurl = extension_loaded('curl') && function_exists('curl_init') && function_exists('curl_version');
    $hasCurlSsl = false;
    if ($hasCurl) {
        $v = @curl_version();
        if (is_array($v)) {
            $features = $v['features'] ?? null;
            $sslVersion = $v['ssl_version'] ?? null;
            if (is_int($features) && defined('CURL_VERSION_SSL') && (($features & CURL_VERSION_SSL) !== 0)) {
                $hasCurlSsl = true;
            } elseif (is_string($sslVersion) && $sslVersion !== '') {
                $hasCurlSsl = true;
            }
        }
    }
    if (!$hasCurlSsl) {
        return [false, 'tls_verify_unavailable'];
    }

    $url = 'https://' . $connectHost . ':' . $port . '/';
    $ch = @curl_init();
    if ($ch === false) {
        return [false, 'tls_verify_unavailable'];
    }

    @curl_setopt($ch, CURLOPT_URL, $url);
    @curl_setopt($ch, CURLOPT_NOBODY, true);
    @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    @curl_setopt($ch, CURLOPT_HEADER, false);
    @curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    @curl_setopt($ch, CURLOPT_MAXREDIRS, 0);
    @curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
    @curl_setopt($ch, CURLOPT_TIMEOUT, 2);
    @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    @curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    if (defined('CURLPROTO_HTTPS')) {
        @curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        @curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    }

    $ok = @curl_exec($ch);
    if ($ok !== false) {
        @curl_close($ch);
        return [true, null];
    }

    $errno = @curl_errno($ch);
    @curl_close($ch);
    if (is_int($errno) && $errno !== 0) {
        // 60 = CURLE_PEER_FAILED_VERIFICATION (common "untrusted cert" case).
        if ($errno === 60) {
            return [false, 'tls_not_trusted'];
        }
        return [false, 'curl_error_' . (string) $errno];
    }

    return [false, 'tls_connect_failed'];
}

/**
 * @param array{mode:'dev'|'prod',host:string,port:int,trusted:bool,error:?string} $tlsGate
 */

function blackcat_setup_render_tls_not_trusted_page(array $tlsGate): void
{
    http_response_code(400);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    $host = htmlspecialchars($tlsGate['host'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $port = (int) $tlsGate['port'];
    $err = $tlsGate['error'] !== null ? htmlspecialchars($tlsGate['error'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') : 'unknown';

    $detailsHtml = '<div class="muted small">CA-trusted TLS verification failed for <code>'
        . $host
        . '</code>:<code>'
        . (string) $port
        . '</code>.</div>'
        . '<div class="muted small">Error: <code>'
        . $err
        . '</code></div>';

    $gridHtml = '<div class="panel">'
        . '<strong>Fix:</strong>'
        . '<ol>'
        . '<li>Install a CA-trusted certificate (Let’s Encrypt).</li>'
        . '<li>Confirm the browser lock has no warnings.</li>'
        . '<li>Reload this page.</li>'
        . '</ol>'
        . '</div>'
        . '<div class="panel">'
        . '<strong>Details (server-side TLS check):</strong>'
        . $detailsHtml
        . '</div>';

    if (function_exists('blackcat_error_ui_render_page')) {
        echo blackcat_error_ui_render_page([
            'title' => 'BlackCat Setup — Trusted TLS Required',
            'h1_prefix' => 'BlackCat Setup',
            'pill' => 'trusted TLS required',
            'lede_html' => '<strong>Blocked:</strong> the TLS certificate is not publicly trusted. BlackCat refuses to continue to prevent MITM during setup.',
            'grid_html' => $gridHtml,
            'style_vars' => [
                'accent_rgb' => '255, 212, 107',
                'accent2_rgb' => '86, 116, 255',
                'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                'mascot_primary_url' => '/_blackcat/assets/tls-not-trusted-cat.png',
            ],
        ]);
        return;
    }

    echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — Trusted TLS Required</title><h1>Trusted TLS required</h1>';
}

function blackcat_setup_preflight(array $paths): array
{
    $errors = [];
    $warnings = [];

    $policy = blackcat_setup_policy();
    $isWarnPolicy = ($policy === 'warn');
    $isLessStrictPolicy = ($policy === 'less-strict');

    $iniBool = static function (string $key): bool {
        $raw = @ini_get($key);
        if ($raw === false) {
            return false;
        }
        $v = strtolower(trim((string) $raw));
        if ($v === '' || $v === '0' || $v === 'off' || $v === 'false' || $v === 'no') {
            return false;
        }
        return true;
    };

    $iniStr = static function (string $key): ?string {
        $raw = @ini_get($key);
        if ($raw === false) {
            return null;
        }
        $v = trim((string) $raw);
        return $v !== '' ? $v : null;
    };

    // --- Runtime hardening gate (align with TrustKernel strict policy) ---

    if ($iniBool('allow_url_include')) {
        $errors[] = 'php.ini hardening: allow_url_include is enabled. Disable it (high-risk remote file include).';
    }

    $displayErrorsEnabled = $iniBool('display_errors') || $iniBool('display_startup_errors');
    if ($displayErrorsEnabled) {
        // Best-effort: detect whether the runtime can override this (ini_set) like HttpKernel does.
        $canOverride = false;
        if (function_exists('ini_set')) {
            @ini_set('display_errors', '0');
            @ini_set('display_startup_errors', '0');
            $afterErrors = $iniBool('display_errors');
            $afterStartup = $iniBool('display_startup_errors');
            $canOverride = !$afterErrors && !$afterStartup;
        }

        $msg = 'php.ini hardening: display_errors/display_startup_errors is enabled. Disable them to prevent information disclosure (use log_errors instead).'
            . ($canOverride ? ' Note: it appears overrideable at runtime (ini_set), but you should still disable it in hosting settings.' : '');

        if ($isWarnPolicy || $canOverride) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    $logErrors = $iniBool('log_errors');
    if (!$logErrors) {
        $warnings[] = 'php.ini hardening: log_errors is disabled. Enable it so errors are logged instead of displayed.';
    }

    $openBasedir = $iniStr('open_basedir');
    if ($openBasedir === null) {
        $msg = 'php.ini hardening: open_basedir is not set. Set it to restrict filesystem access (required for a strict trust-kernel deployment).';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    } else {
        $allowed = array_filter(array_map('trim', explode(PATH_SEPARATOR, $openBasedir)), static fn (string $p): bool => $p !== '');

        $bundleRoot = $paths['bundle_root'];
        $stateDir = $paths['state_dir'];
        $configPath = $paths['config_path'];

        $mustAllow = [
            'bundle_root' => $bundleRoot,
            '.blackcat' => $stateDir,
            'config.runtime.json dir' => dirname($configPath),
        ];

        $allowedOk = static function (string $required, array $allowedList): bool {
            $req = @realpath($required);
            $req = is_string($req) && $req !== '' ? $req : $required;
            $req = rtrim($req, "/\\") . DIRECTORY_SEPARATOR;

            foreach ($allowedList as $base) {
                $b = @realpath($base);
                $b = is_string($b) && $b !== '' ? $b : $base;
                $b = rtrim($b, "/\\") . DIRECTORY_SEPARATOR;
                if (str_starts_with($req, $b)) {
                    return true;
                }
            }
            return false;
        };

        foreach ($mustAllow as $label => $path) {
            if (!$allowedOk($path, $allowed)) {
                $msg = 'php.ini hardening: open_basedir blocks access to ' . $label . '. Adjust open_basedir or deploy the bundle under an allowed path.';
                if ($isWarnPolicy) {
                    $warnings[] = $msg;
                } else {
                    $errors[] = $msg;
                }
            }
        }
    }

    $pharReadonly = $iniStr('phar.readonly');
    if ($pharReadonly !== null && $pharReadonly !== '1') {
        $msg = 'php.ini hardening: phar.readonly is disabled. Set phar.readonly=1 to reduce PHAR deserialization risks.';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    if ($iniBool('enable_dl')) {
        $msg = 'php.ini hardening: enable_dl is enabled. Disable it (runtime extension loading increases attack surface).';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    $autoPrepend = $iniStr('auto_prepend_file');
    if ($autoPrepend !== null) {
        $msg = 'php.ini hardening: auto_prepend_file is set. Remove it (hidden code injection risk).';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    $autoAppend = $iniStr('auto_append_file');
    if ($autoAppend !== null) {
        $msg = 'php.ini hardening: auto_append_file is set. Remove it (hidden code injection risk).';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    $cgiFixPathinfo = $iniBool('cgi.fix_pathinfo');
    if ($cgiFixPathinfo && in_array(PHP_SAPI, ['fpm-fcgi', 'cgi', 'cgi-fcgi'], true)) {
        if ($isWarnPolicy) {
            $warnings[] = 'php.ini hardening: cgi.fix_pathinfo is enabled. This increases risk in some CGI/FPM configurations.';
        } elseif ($isLessStrictPolicy) {
            $warnings[] = 'php.ini hardening: cgi.fix_pathinfo is enabled. less-strict can proceed only with a best-effort NO EXEC probe + a locked on-chain waiver attestation; otherwise the kernel will fail-closed.';
        } else {
            $errors[] = 'php.ini hardening: cgi.fix_pathinfo is enabled. Set cgi.fix_pathinfo=0 for strict deployments on FPM/CGI.';
        }
    }

    $disableFunctionsRaw = $iniStr('disable_functions');
    $parseCsv = static function (?string $raw): array {
        if ($raw === null || trim($raw) === '') {
            return [];
        }
        $out = [];
        foreach (preg_split('/[\\s,]+/', trim($raw)) ?: [] as $part) {
            $p = strtolower(trim((string) $part));
            if ($p === '' || str_contains($p, "\0")) {
                continue;
            }
            $out[$p] = true;
        }
        return array_keys($out);
    };
    $disabled = $parseCsv($disableFunctionsRaw);
    $dangerous = ['exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec'];
    $callable = [];
    foreach ($dangerous as $fn) {
        // If disabled (disable_functions) or unavailable (extension not loaded),
        // function_exists() should be false. Treat "callable" as the actual risk.
        if (function_exists($fn)) {
            $callable[] = $fn;
        }
    }
    if ($callable !== []) {
        $msg = 'php.ini hardening: dangerous process-exec functions are callable: ' . implode(', ', $callable) . '. Disable them (recommended: disable_functions=' . implode(',', $dangerous) . ').';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    } elseif ($disabled === [] && $isWarnPolicy) {
        // Informational: some hostings disable these at another layer; strict prod should still disable explicitly.
        $warnings[] = 'php.ini hardening: disable_functions is empty, but no dangerous process-exec functions appear callable in this runtime.';
    }

    $hasOpenSsl = extension_loaded('openssl');
    $hasCurl = extension_loaded('curl') && function_exists('curl_init') && function_exists('curl_version');
    $hasCurlSsl = false;
    if ($hasCurl) {
        $v = @curl_version();
        if (is_array($v)) {
            $features = $v['features'] ?? null;
            $sslVersion = $v['ssl_version'] ?? null;
            if (is_int($features) && defined('CURL_VERSION_SSL') && (($features & CURL_VERSION_SSL) !== 0)) {
                $hasCurlSsl = true;
            } elseif (is_string($sslVersion) && $sslVersion !== '') {
                // Some builds expose ssl_version but not features reliably.
                $hasCurlSsl = true;
            }
        }
    }
    if (!$hasOpenSsl && !$hasCurlSsl) {
        $errors[] = 'Missing TLS verification capability (OpenSSL extension or PHP curl with HTTPS support). BlackCat crypto uses libsodium, but setup still requires CA-trusted TLS verification to prevent MITM.';
    }

    // Web3 transport (align with TrustKernel expectations).
    $allowUrlFopen = $iniBool('allow_url_fopen');
    $web3TransportOk = $hasCurlSsl || ($allowUrlFopen && $hasOpenSsl);
    if (!$web3TransportOk) {
        $msg = 'Web3 transport is unavailable: no HTTPS-capable client detected (need cURL with SSL or OpenSSL + allow_url_fopen). TrustKernel cannot read on-chain state on this hosting.';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    $docroot = $paths['docroot'];
    $bundleRoot = $paths['bundle_root'];
    $stateDir = $paths['state_dir'];
    $configPath = $paths['config_path'];

    $docrootReal = @realpath($docroot);
    $bundleReal = @realpath($bundleRoot);
    if (is_string($docrootReal) && is_string($bundleReal)) {
        $docrootReal = rtrim($docrootReal, "/\\") . DIRECTORY_SEPARATOR;
        $bundleReal = rtrim($bundleReal, "/\\") . DIRECTORY_SEPARATOR;
        if (str_starts_with($bundleReal, $docrootReal)) {
            $errors[] = 'Misconfigured web root: bundle_root must not be inside docroot (sensitive files could be web-accessible).';
        }
    }

    // Ensure state dir is writable and not world-writable (POSIX).
    if (!is_dir($stateDir)) {
        $errors[] = 'State directory is missing (.blackcat).';
        return ['errors' => $errors, 'warnings' => $warnings];
    }

    if (!is_writable($stateDir)) {
        $errors[] = 'State directory is not writable (.blackcat).';
    }

    if (DIRECTORY_SEPARATOR !== '\\') {
        $perms = @fileperms($stateDir);
        if (is_int($perms)) {
            $mode = $perms & 0777;
            if (($mode & 0002) !== 0) {
                $errors[] = 'State directory is world-writable (.blackcat). Fix permissions (recommended: 0700).';
            } elseif (($mode & 0020) !== 0) {
                $warnings[] = 'State directory is group-writable (.blackcat). Consider tightening permissions (recommended: 0700).';
            }
        }
    }

    // Ensure bundle root is writable for config.runtime.json.
    $configDir = dirname($configPath);
    if (!is_dir($configDir) || !is_writable($configDir)) {
        $errors[] = 'Bundle root is not writable (needed to write config.runtime.json).';
    }

    if (is_file($configPath) && !is_writable($configPath)) {
        $errors[] = 'config.runtime.json exists but is not writable.';
    }

    return ['errors' => $errors, 'warnings' => $warnings];
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 * @param list<string> $errors
 * @param list<string> $warnings
 */

function blackcat_setup_render_preflight_page(array $paths, array $errors, array $warnings): void
{
    http_response_code(503);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    $errItems = '';
    foreach ($errors as $e) {
        $errItems .= '<li><strong class="bad">ERROR</strong> ' . htmlspecialchars($e, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</li>';
    }
    $warnItems = '';
    foreach ($warnings as $w) {
        $warnItems .= '<li><strong class="warn">WARN</strong> ' . htmlspecialchars($w, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</li>';
    }

    $gridHtml = '<div class="panel">'
        . '<strong>Checklist:</strong>'
        . '<ul>'
        . $errItems
        . $warnItems
        . '</ul>'
        . '<div class="footer muted">Preflight is intentionally strict — it prevents writing secrets into unsafe paths/permissions.</div>'
        . '</div>'
        . '<div class="panel">'
        . '<strong>Common fixes:</strong>'
        . '<ul class="muted">'
        . '<li>Ensure server-side TLS verification works (OpenSSL extension or PHP <code>curl</code> with HTTPS support).</li>'
        . '<li>Harden php.ini (disable <code>display_errors</code>, set <code>open_basedir</code>, and disable dangerous functions via <code>disable_functions</code>).</li>'
        . '<li>Ensure <code>.blackcat/</code> is writable and not world-writable.</li>'
        . '<li>Ensure the bundle root is writable for <code>config.runtime.json</code>.</li>'
        . '<li>Reload <code>/_blackcat/setup</code> after fixing permissions.</li>'
        . '</ul>'
        . '</div>';

    if (function_exists('blackcat_error_ui_render_page')) {
        echo blackcat_error_ui_render_page([
            'title' => 'BlackCat Setup — Preflight Failed',
            'h1_prefix' => 'BlackCat Setup',
            'pill' => 'preflight failed',
            'lede_html' => '<strong>Fix the server environment</strong> before continuing. This protects the installer from writing secrets/config into unsafe locations.',
            'grid_html' => $gridHtml,
            'style_vars' => [
                'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                'mascot_primary_url' => '/_blackcat/assets/preflight-failed-cat.png',
            ],
        ]);
        return;
    }

    echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — Preflight Failed</title><h1>Preflight failed</h1>';
}


function blackcat_setup_render_disabled_page(array $paths): void
{
    http_response_code(404);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    $gridHtml = '<div class="panel">'
        . '<strong>What this means:</strong>'
        . '<ul class="muted">'
        . '<li>This instance has already been initialized.</li>'
        . '<li>The web installer is intentionally locked after setup.</li>'
        . '</ul>'
        . '</div>'
        . '<div class="panel">'
        . '<strong>Next steps:</strong>'
        . '<ul class="muted">'
        . '<li>Use the signed upgrade/recovery flow to make changes.</li>'
        . '<li>If you need a clean install, deploy a fresh bundle.</li>'
        . '</ul>'
        . '</div>';

    if (function_exists('blackcat_error_ui_render_page')) {
        echo blackcat_error_ui_render_page([
            'title' => 'BlackCat Setup — Disabled',
            'h1_prefix' => 'BlackCat Setup',
            'pill' => 'installer locked',
            'lede_html' => '<strong>Installer locked.</strong> This deployment is sealed to keep the web attack surface minimal.',
            'grid_html' => $gridHtml,
            'style_vars' => [
                'accent_rgb' => '255, 212, 107',
                'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                'mascot_primary_url' => '/_blackcat/assets/installer-locked-cat.png',
            ],
        ]);
        return;
    }

    echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — Disabled</title><h1>Installer locked</h1>';
}


function blackcat_setup_render_front_controller_required_page(): void
{
    http_response_code(400);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    $gridHtml = '<div class="panel">'
        . '<strong>What this means:</strong>'
        . '<ul>'
        . '<li>Your server must route all requests to the front controller (<code>index.php</code>).</li>'
        . '<li>Direct access to <code>/_blackcat/setup.php</code> is blocked by design.</li>'
        . '</ul>'
        . '</div>'
        . '<div class="panel">'
        . '<strong>Fix:</strong>'
        . '<ul class="muted">'
        . '<li>Point the document root to the directory that contains <code>index.php</code>.</li>'
        . '<li>Enable URL rewriting so all requests route through <code>index.php</code> (Apache: <code>AllowOverride All</code> / Nginx: <code>try_files</code>).</li>'
        . '<li>Reload and open <code>/_blackcat/setup</code> again.</li>'
        . '</ul>'
        . '<div class="footer warn">Front controller is a required part of BlackCat security (single entrypoint).</div>'
        . '</div>';

    if (function_exists('blackcat_error_ui_render_page')) {
        echo blackcat_error_ui_render_page([
            'title' => 'BlackCat Setup — Front Controller Required',
            'h1_prefix' => 'BlackCat Setup',
            'pill' => 'front controller required',
            'lede_html' => '<strong>Fail-closed:</strong> setup must be served through the front controller to enforce routing, HTTPS, and trust checks.',
            'grid_html' => $gridHtml,
            'style_vars' => [
                'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                'mascot_primary_url' => '/_blackcat/assets/fatal-error-cat.png',
            ],
        ]);
        return;
    }

    echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — Front Controller Required</title><h1>Front controller required</h1>';
}

function blackcat_setup_api_policy_v3(): void
{
    $raw = file_get_contents('php://input');
    $decoded = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($decoded)) {
        blackcat_json(['ok' => false, 'error' => 'Invalid JSON body.'], 400);
        return;
    }

    $mode = $decoded['mode'] ?? 'full';
    if (!is_string($mode)) {
        blackcat_json(['ok' => false, 'error' => 'mode must be a string.'], 400);
        return;
    }
    $mode = strtolower(trim($mode));
    if (!in_array($mode, ['full', 'root_uri'], true)) {
        blackcat_json(['ok' => false, 'error' => 'mode must be "full" or "root_uri".'], 400);
        return;
    }

    $maxStale = $decoded['max_stale_sec'] ?? 180;
    if (!is_int($maxStale)) {
        if (is_string($maxStale) && ctype_digit(trim($maxStale))) {
            $maxStale = (int) trim($maxStale);
        } else {
            blackcat_json(['ok' => false, 'error' => 'max_stale_sec must be an integer.'], 400);
            return;
        }
    }
    if ($maxStale <= 0) {
        blackcat_json(['ok' => false, 'error' => 'max_stale_sec must be >= 1.'], 400);
        return;
    }

    $enforcement = $decoded['enforcement'] ?? 'strict';
    if (!is_string($enforcement)) {
        blackcat_json(['ok' => false, 'error' => 'enforcement must be a string.'], 400);
        return;
    }
    $enforcement = strtolower(trim($enforcement));
    if (!in_array($enforcement, ['strict', 'less-strict', 'warn'], true)) {
        blackcat_json(['ok' => false, 'error' => 'enforcement must be "strict", "less-strict", or "warn".'], 400);
        return;
    }

    $attKey = Bytes32::normalizeHex(KernelAttestations::runtimeConfigAttestationKeyV1());
    $policy = new TrustPolicyV3($mode, $maxStale, $enforcement, $attKey);
    $policyStrict = new TrustPolicyV3($mode, $maxStale, 'strict', $attKey);
    $policyLessStrict = new TrustPolicyV3($mode, $maxStale, 'less-strict', $attKey);
    $policyWarn = new TrustPolicyV3($mode, $maxStale, 'warn', $attKey);

    blackcat_json([
        'ok' => true,
        'attestation_key_v1' => $attKey,
        'enforcement' => $enforcement,
        'policy_hash_v3' => $policy->hashBytes32(),
        'policy_hash_v3_strict' => $policyStrict->hashBytes32(),
        'policy_hash_v3_less_strict' => $policyLessStrict->hashBytes32(),
        'policy_hash_v3_warn' => $policyWarn->hashBytes32(),
        'note' => 'Policy hash does not depend on runtime config contents (only mode/max_stale/enforcement + attestation key).',
    ]);
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_api_status(array $paths): void
{
    $suggestedHost = null;
    $rawHost = $_SERVER['HTTP_HOST'] ?? null;
    if (is_string($rawHost) && $rawHost !== '' && !str_contains($rawHost, "\0")) {
        $suggestedHost = preg_replace('/:\\d+$/', '', strtolower(trim($rawHost)));
    }

    $suggested = [
        'rpc_endpoints' => [
            'https://rpc.layeredge.io',
            'https://edgenscan.io/api/eth-rpc',
        ],
        'allowed_hosts' => $suggestedHost !== null ? [$suggestedHost] : [],
    ];

    $stateDir = $paths['state_dir'];
    $manifestPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'integrity.manifest.json';
    $summaryPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.summary.json';

    $summary = null;
    if (is_file($summaryPath)) {
        $raw = file_get_contents($summaryPath);
        if (is_string($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $summary = $decoded;
            }
        }
    }

    blackcat_json([
        'ok' => true,
        'paths' => [
            'docroot' => $paths['docroot'],
            'site_dir' => $paths['site_dir'],
            'bundle_root' => $paths['bundle_root'],
            'state_dir' => $paths['state_dir'],
            'config_path' => $paths['config_path'],
            'manifest_path' => $manifestPath,
        ],
        'exists' => [
            'manifest' => is_file($manifestPath),
            'config' => is_file($paths['config_path']),
            'installed_flag' => blackcat_setup_is_disabled($stateDir),
            'summary' => $summary !== null,
        ],
        'summary' => $summary,
        'suggested' => $suggested,
    ]);
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_api_build_manifest(array $paths): void
{
    $stateDir = $paths['state_dir'];
    blackcat_ensure_state_dir($stateDir);

    $siteDir = $paths['site_dir'];
    if (!is_dir($siteDir) || is_link($siteDir)) {
        blackcat_json(['ok' => false, 'error' => 'Invalid integrity root directory: ' . $siteDir], 500);
        return;
    }

    $out = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'integrity.manifest.json';
    $summaryPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.summary.json';

    try {
        $res = IntegrityManifestBuilder::build($siteDir);
        $manifest = $res['manifest'];

        $json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            throw new RuntimeException('Unable to encode manifest JSON.');
        }

        if (@file_put_contents($out, $json . "\n") === false) {
            throw new RuntimeException('Unable to write manifest: ' . $out);
        }

        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($out, 0640);
        }

        $summary = [
            'ok' => true,
            'root' => $res['root'],
            'uri_hash' => $res['uri_hash'],
            'files_count' => $res['files_count'],
            'generated_at' => gmdate('c'),
        ];
        @file_put_contents($summaryPath, json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($summaryPath, 0640);
        }

        blackcat_json($summary);
    } catch (Throwable $e) {
        blackcat_json(['ok' => false, 'error' => $e->getMessage()], 500);
    }
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_api_write_config(array $paths): void
{
    $stateDir = $paths['state_dir'];
    $manifestPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'integrity.manifest.json';
    if (!is_file($manifestPath)) {
        blackcat_json(['ok' => false, 'error' => 'Missing manifest. Run build-manifest first.'], 400);
        return;
    }

    $raw = file_get_contents('php://input');
    $decoded = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($decoded)) {
        blackcat_json(['ok' => false, 'error' => 'Invalid JSON body.'], 400);
        return;
    }

    $instance = $decoded['instance_controller'] ?? null;
    if (!is_string($instance) || !preg_match('/^0x[a-fA-F0-9]{40}$/', $instance)) {
        blackcat_json(['ok' => false, 'error' => 'Invalid instance_controller (expected 0x + 40 hex).'], 400);
        return;
    }

    $rpcEndpoints = $decoded['rpc_endpoints'] ?? null;
    if (!is_array($rpcEndpoints) || $rpcEndpoints === []) {
        blackcat_json(['ok' => false, 'error' => 'rpc_endpoints must be a non-empty list.'], 400);
        return;
    }
    $endpoints = [];
    foreach ($rpcEndpoints as $i => $v) {
        if (!is_string($v)) {
            blackcat_json(['ok' => false, 'error' => 'rpc_endpoints[' . $i . '] must be a string.'], 400);
            return;
        }
        $v = trim($v);
        if ($v === '' || str_contains($v, "\0")) {
            blackcat_json(['ok' => false, 'error' => 'rpc_endpoints[' . $i . '] is invalid.'], 400);
            return;
        }
        $endpoints[] = $v;
    }

    $quorum = $decoded['rpc_quorum'] ?? 1;
    if (!is_int($quorum)) {
        if (is_string($quorum) && ctype_digit(trim($quorum))) {
            $quorum = (int) trim($quorum);
        } else {
            blackcat_json(['ok' => false, 'error' => 'rpc_quorum must be an integer.'], 400);
            return;
        }
    }
    if ($quorum < 1) {
        blackcat_json(['ok' => false, 'error' => 'rpc_quorum must be >= 1.'], 400);
        return;
    }
    if ($quorum > count($endpoints)) {
        blackcat_json(['ok' => false, 'error' => 'rpc_quorum must be <= number of rpc_endpoints.'], 400);
        return;
    }

    $enforcement = $decoded['enforcement'] ?? 'strict';
    if (!is_string($enforcement)) {
        blackcat_json(['ok' => false, 'error' => 'enforcement must be a string.'], 400);
        return;
    }
    $enforcement = strtolower(trim($enforcement));
    if (!in_array($enforcement, ['strict', 'less-strict', 'warn'], true)) {
        blackcat_json(['ok' => false, 'error' => 'enforcement must be "strict", "less-strict", or "warn".'], 400);
        return;
    }

    // Strict + less-strict require redundant RPC quorum (avoid single-endpoint trust).
    if ($enforcement !== 'warn') {
        if (count($endpoints) < 2) {
            blackcat_json(['ok' => false, 'error' => 'At least 2 rpc_endpoints are required (quorum trust needs redundancy).'], 400);
            return;
        }
        if ($quorum < 2) {
            blackcat_json(['ok' => false, 'error' => 'rpc_quorum must be >= 2 for a strict/less-strict trust kernel deployment.'], 400);
            return;
        }
    }

    $mode = $decoded['mode'] ?? 'full';
    if (!is_string($mode)) {
        blackcat_json(['ok' => false, 'error' => 'mode must be a string.'], 400);
        return;
    }
    $mode = strtolower(trim($mode));
    if (!in_array($mode, ['full', 'root_uri'], true)) {
        blackcat_json(['ok' => false, 'error' => 'mode must be "full" or "root_uri".'], 400);
        return;
    }

    $maxStale = $decoded['max_stale_sec'] ?? 180;
    if (!is_int($maxStale)) {
        if (is_string($maxStale) && ctype_digit(trim($maxStale))) {
            $maxStale = (int) trim($maxStale);
        } else {
            blackcat_json(['ok' => false, 'error' => 'max_stale_sec must be an integer.'], 400);
            return;
        }
    }

    $allowedHostsRaw = $decoded['allowed_hosts'] ?? [];
    $allowedHosts = [];
    if (is_array($allowedHostsRaw)) {
        foreach ($allowedHostsRaw as $v) {
            if (!is_string($v)) {
                continue;
            }
            $v = trim($v);
            if ($v !== '' && !str_contains($v, "\0")) {
                $allowedHosts[] = $v;
            }
        }
    }

    $txOutboxDir = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'tx-outbox';
    if (!is_dir($txOutboxDir)) {
        @mkdir($txOutboxDir, 0770, true);
        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($txOutboxDir, 0770);
        }
    }

    $payload = [
        'trust' => [
            'integrity' => [
                'root_dir' => 'site',
                'manifest' => '.blackcat/integrity.manifest.json',
                'image_digest_file' => '.blackcat/image.digest',
            ],
            'web3' => [
                'chain_id' => 4207,
                'rpc_endpoints' => $endpoints,
                'rpc_quorum' => $quorum,
                'max_stale_sec' => $maxStale,
                'timeout_sec' => 5,
                'mode' => $mode,
                'tx_outbox_dir' => '.blackcat/tx-outbox',
                'contracts' => [
                    'instance_controller' => $instance,
                    'release_registry' => '0x22681Ee2153B7B25bA6772B44c160BB60f4C333E',
                    'instance_factory' => '0x92C80Cff5d75dcD3846EFb5DF35957D5Aed1c7C5',
                ],
            ],
        ],
    ];

    if ($allowedHosts !== []) {
        $payload['http'] = [
            'allowed_hosts' => $allowedHosts,
        ];
    }

    $path = $paths['config_path'];

    $existedBefore = file_exists($path);
    try {
        RuntimeConfigInstaller::init($payload, $path, true);
        $repo = ConfigRepository::fromJsonFile($path);

        $runtimeConfig = $repo->toArray();
        $attKey = Bytes32::normalizeHex(KernelAttestations::runtimeConfigAttestationKeyV1());
        $attValue = Bytes32::normalizeHex(KernelAttestations::runtimeConfigAttestationValueV1($runtimeConfig));

        $policy = new TrustPolicyV3($mode, $maxStale, $enforcement, $attKey);
        $policyStrict = new TrustPolicyV3($mode, $maxStale, 'strict', $attKey);
        $policyLessStrict = new TrustPolicyV3($mode, $maxStale, 'less-strict', $attKey);
        $policyWarn = new TrustPolicyV3($mode, $maxStale, 'warn', $attKey);
        $policyHash = $policy->hashBytes32();

        blackcat_json([
            'ok' => true,
            'config_path' => $path,
            'runtime_config_attestation' => [
                'key' => $attKey,
                'value' => $attValue,
                'enforcement' => $enforcement,
                'policy_hash_v3' => $policyHash,
                'policy_hash_v3_strict' => $policyStrict->hashBytes32(),
                'policy_hash_v3_less_strict' => $policyLessStrict->hashBytes32(),
                'policy_hash_v3_warn' => $policyWarn->hashBytes32(),
            ],
            'note' => 'Commit the manifest root + policy hash on-chain, then set+lock the runtime config attestation key/value on the InstanceController.',
        ]);
    } catch (Throwable $e) {
        // Avoid leaving an invalid/unsafe config behind if validation fails.
        if (!$existedBefore && is_file($path)) {
            @unlink($path);
        }
        blackcat_json(['ok' => false, 'error' => $e->getMessage()], 500);
    }
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_api_finish(array $paths): void
{
    $stateDir = $paths['state_dir'];
    blackcat_ensure_state_dir($stateDir);

    $flag = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'installed.flag';
    if (@file_put_contents($flag, gmdate('c') . "\n") === false) {
        blackcat_json(['ok' => false, 'error' => 'Unable to write installed.flag'], 500);
        return;
    }
    if (DIRECTORY_SEPARATOR !== '\\') {
        @chmod($flag, 0600);
    }

    $tokenPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.token';
    $tokenRemoved = false;
    if (is_file($tokenPath)) {
        $tokenRemoved = (@unlink($tokenPath) !== false);
    }

    blackcat_json([
        'ok' => true,
        'installed_flag' => $flag,
        'install_token_removed' => $tokenRemoved,
        'note' => 'Installer disabled. This deployment is sealed to keep the web attack surface minimal. Use the signed upgrade/recovery flow for changes; for a clean reinstall, deploy a fresh bundle.',
    ]);
}

function blackcat_setup_is_disabled(string $stateDir): bool
{
    $flag = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'installed.flag';
    return is_file($flag);
}

function blackcat_read_install_token(string $stateDir): ?string
{
    $path = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.token';
    if (!is_file($path)) {
        return null;
    }
    $raw = file_get_contents($path);
    if (!is_string($raw)) {
        return null;
    }
    $token = trim($raw);
    return $token !== '' && !str_contains($token, "\0") ? $token : null;
}

function blackcat_read_provided_token(): ?string
{
    $headers = [
        $_SERVER['HTTP_X_BLACKCAT_INSTALL_TOKEN'] ?? null,
        $_SERVER['HTTP_AUTHORIZATION'] ?? null,
    ];

    foreach ($headers as $raw) {
        if (!is_string($raw)) {
            continue;
        }
        $raw = trim($raw);
        if ($raw === '' || str_contains($raw, "\0")) {
            continue;
        }
        if (str_starts_with(strtolower($raw), 'bearer ')) {
            $raw = trim(substr($raw, 7));
        }
        if ($raw !== '' && !str_contains($raw, "\0")) {
            return $raw;
        }
    }

    return null;
}

function blackcat_is_https_request(): bool
{
    $https = $_SERVER['HTTPS'] ?? null;
    if (is_string($https) && ($https === 'on' || $https === '1')) {
        return true;
    }
    if (is_int($https) && $https === 1) {
        return true;
    }

    $port = $_SERVER['SERVER_PORT'] ?? null;
    if (is_string($port) && trim($port) === '443') {
        return true;
    }
    if (is_int($port) && $port === 443) {
        return true;
    }

    // Only honor forwarded HTTPS indicators when the immediate peer is a local, trusted proxy.
    // This prevents clients from spoofing X-Forwarded-Proto / Forwarded on plain HTTP requests.
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? null;
    if (!blackcat_is_loopback_ip($remoteAddr)) {
        return false;
    }

    $xfp = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null;
    if (is_string($xfp)) {
        $first = trim(explode(',', $xfp, 2)[0] ?? '');
        if (strtolower($first) === 'https') {
            return true;
        }
    }

    $forwarded = $_SERVER['HTTP_FORWARDED'] ?? null;
    if (is_string($forwarded) && stripos($forwarded, 'proto=') !== false) {
        // RFC 7239: Forwarded: proto=https;host=example.com
        foreach (explode(',', $forwarded) as $part) {
            foreach (explode(';', $part) as $kv) {
                $kv = trim($kv);
                if (stripos($kv, 'proto=') !== 0) {
                    continue;
                }
                $val = trim(substr($kv, 6));
                $val = trim($val, "\"'");
                if (strtolower($val) === 'https') {
                    return true;
                }
            }
        }
    }

    return false;
}

function blackcat_is_loopback_ip(mixed $ip): bool
{
    if (!is_string($ip)) {
        return false;
    }
    $ip = trim($ip);
    if ($ip === '') {
        return false;
    }

    if (@filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        return str_starts_with($ip, '127.');
    }

    if (@filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        return strtolower($ip) === '::1';
    }

    return false;
}

function blackcat_ensure_state_dir(string $stateDir): void
{
    if (is_dir($stateDir)) {
        return;
    }
    @mkdir($stateDir, 0700, true);
    if (DIRECTORY_SEPARATOR !== '\\') {
        @chmod($stateDir, 0700);
    }
}

function blackcat_request_path(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $path = parse_url(is_string($uri) ? $uri : '/', PHP_URL_PATH);
    $path = is_string($path) && $path !== '' ? $path : '/';
    if (str_contains($path, "\0")) {
        return '/';
    }
    return $path;
}

/**
 * @param array<string,mixed> $data
 */
function blackcat_json(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        echo "{\"ok\":false,\"error\":\"json_encode failed\"}\n";
        return;
    }
    echo $json . "\n";
}

// If this file is executed directly (misconfigured docroot), fail closed with a clear message.
if (PHP_SAPI !== 'cli') {
    $script = $_SERVER['SCRIPT_FILENAME'] ?? null;
    $scriptReal = is_string($script) ? @realpath($script) : null;
    $selfReal = @realpath(__FILE__);
    if (is_string($scriptReal) && is_string($selfReal) && $scriptReal === $selfReal) {
        blackcat_setup_render_front_controller_required_page();
        exit;
    }
}
