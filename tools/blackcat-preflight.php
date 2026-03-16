<?php

declare(strict_types=1);

/**
 * BlackCat Hosting Preflight (single-file, no Composer).
 *
 * Upload this file to the target hosting and open it in a browser to determine
 * whether a Stage 3 “kernel minimal bundle” install is feasible.
 *
 * SECURITY NOTE:
 * - This page reveals environment details (versions/extensions). Delete it after use.
 * - No user-controlled URLs are fetched (SSRF-safe by design). The optional PathInfo probe
 *   only performs same-origin requests derived from server-provided host/port (not query input).
 */

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
// Default CSP is script-less. `?probe=pathinfo` enables a minimal inline script to run same-origin fetches.
$probe = $_GET['probe'] ?? null;
$probeRequested = is_string($probe) && strtolower(trim($probe)) === 'pathinfo';
// Auto-enable the PathInfo probe when cgi.fix_pathinfo is enabled on FPM/CGI (so users don't need extra steps).
$autoPathinfoProbe = false;
$cgiFixRaw = ini_get('cgi.fix_pathinfo');
if ($cgiFixRaw !== false) {
    $v = strtolower(trim((string) $cgiFixRaw));
    $cgiFixEnabled = !($v === '' || $v === '0' || $v === 'off' || $v === 'false' || $v === 'no');
    if ($cgiFixEnabled && in_array(PHP_SAPI, ['fpm-fcgi', 'cgi', 'cgi-fcgi'], true)) {
        $autoPathinfoProbe = true;
    }
}
$allowInlineScript = $probeRequested || $autoPathinfoProbe;
$csp = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
if ($allowInlineScript) {
    $csp .= "; script-src 'unsafe-inline'; connect-src 'self'";
}
header('Content-Security-Policy: ' . $csp);

/**
 * Kernel-minimal bundle currently depends on blackcat-config, which requires PHP 8.3+.
 * Keep this in sync with `blackcat-config/composer.json`.
 */
const BLACKCAT_PREFLIGHT_MIN_PHP = 80300; // 8.3.0

/**
 * The default chain used in the demo/docs is Edgen (chain_id=4207).
 * Keep this list small to avoid accidental rate limits.
 *
 * @var list<string>
 */
const BLACKCAT_PREFLIGHT_RPC_URLS = [
    'https://rpc.layeredge.io',
];

/**
 * @return array{policy:'strict'|'less-strict'|'warn',value:string}
 */
function blackcat_preflight_policy(): array
{
    $raw = $_GET['policy'] ?? null;
    if (is_string($raw)) {
        $v = strtolower(trim($raw));
        if ($v === 'warn' || $v === 'dev') {
            return ['policy' => 'warn', 'value' => $v];
        }
        if ($v === 'less-strict' || $v === 'less_strict' || $v === 'lessstrict' || $v === 'ls') {
            return ['policy' => 'less-strict', 'value' => $v];
        }
        if ($v === 'strict' || $v === 'prod') {
            return ['policy' => 'strict', 'value' => $v];
        }
    }
    return ['policy' => 'strict', 'value' => 'strict'];
}

/**
 * @return 'pathinfo'|null
 */
function blackcat_preflight_probe(): ?string
{
    $raw = $_GET['probe'] ?? null;
    if (!is_string($raw)) {
        return null;
    }
    $v = strtolower(trim($raw));
    return $v === 'pathinfo' ? 'pathinfo' : null;
}

function blackcat_preflight_probe_deep(): bool
{
    $raw = $_GET['deep'] ?? null;
    if (!is_string($raw)) {
        // If we're auto-probing, default to deep mode for better confidence.
        $cgiFixRaw = ini_get('cgi.fix_pathinfo');
        if ($cgiFixRaw !== false) {
            $v = strtolower(trim((string) $cgiFixRaw));
            $cgiFixEnabled = !($v === '' || $v === '0' || $v === 'off' || $v === 'false' || $v === 'no');
            if ($cgiFixEnabled && in_array(PHP_SAPI, ['fpm-fcgi', 'cgi', 'cgi-fcgi'], true)) {
                return true;
            }
        }
        return false;
    }
    $v = strtolower(trim($raw));
    return $v === '1' || $v === 'true' || $v === 'yes';
}

function blackcat_preflight_random_id(): string
{
    try {
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes(8));
        }
    } catch (\Throwable $e) {
        // ignore
    }
    return substr(hash('sha256', (string) microtime(true) . '-' . (string) getmypid()), 0, 16);
}

/**
 * Canonical JSON encoding (match `blackcat-config` CanonicalJson::encode()).
 *
 * This preflight runs on constrained hostings (no Composer), but it must output values that
 * exactly match kernel attestations (bytes32 sha256 of canonical JSON).
 *
 * @throws \InvalidArgumentException
 */
function blackcat_preflight_canonical_json_encode(mixed $value): string
{
    $normalized = blackcat_preflight_canonical_json_normalize($value);
    $json = json_encode($normalized, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (!is_string($json)) {
        throw new \RuntimeException('Unable to encode canonical JSON.');
    }
    return $json;
}

function blackcat_preflight_canonical_json_is_list(array $value): bool
{
    $expected = 0;
    foreach (array_keys($value) as $k) {
        if (!is_int($k) || $k !== $expected) {
            return false;
        }
        $expected++;
    }
    return true;
}

/**
 * @throws \InvalidArgumentException
 */
function blackcat_preflight_canonical_json_normalize(mixed $value): mixed
{
    if (is_array($value)) {
        if (blackcat_preflight_canonical_json_is_list($value)) {
            $out = [];
            foreach ($value as $v) {
                $out[] = blackcat_preflight_canonical_json_normalize($v);
            }
            return $out;
        }

        $keys = array_keys($value);
        sort($keys, SORT_STRING);
        $out = [];
        foreach ($keys as $k) {
            if (!is_string($k) && !is_int($k)) {
                throw new \InvalidArgumentException('Canonical JSON only supports string/int array keys.');
            }
            $out[(string) $k] = blackcat_preflight_canonical_json_normalize($value[$k]);
        }
        return $out;
    }

    if (is_object($value)) {
        throw new \InvalidArgumentException('Objects are not supported in canonical JSON.');
    }

    return $value;
}

function blackcat_preflight_sha256_bytes32(mixed $value): string
{
    return '0x' . hash('sha256', blackcat_preflight_canonical_json_encode($value));
}

/**
 * Canonical waiver attestation required for `policy=less-strict` when `cgi.fix_pathinfo` is enabled.
 *
 * Keep in sync with:
 * - `blackcat-config/src/Security/KernelAttestations.php`
 * - `blackcat-core/src/TrustKernel/TrustKernelConfig.php`
 *
 * @return array{key_label:string,key_bytes32:string,payload:array{schema_version:int,type:string,result:string},value_bytes32:string,must_be_locked:bool}
 */
function blackcat_preflight_pathinfo_no_exec_waiver_attestation(): array
{
    $keyLabel = 'blackcat.hosting.cgi_fix_pathinfo.probe.canonical_sha256.v1';
    $payload = [
        'schema_version' => 1,
        'type' => 'blackcat.hosting.cgi_fix_pathinfo.probe',
        'result' => 'no_exec',
    ];

    return [
        'key_label' => $keyLabel,
        'key_bytes32' => '0x' . hash('sha256', $keyLabel),
        'payload' => $payload,
        'value_bytes32' => blackcat_preflight_sha256_bytes32($payload),
        'must_be_locked' => true,
    ];
}

/**
 * @return string
 */
function blackcat_preflight_script_dir_url_path(): string
{
    $script = $_SERVER['SCRIPT_NAME'] ?? null;
    if (!is_string($script) || $script === '' || str_contains($script, "\0")) {
        return '/';
    }

    $dir = str_replace('\\', '/', dirname($script));
    if ($dir === '.' || $dir === '') {
        return '/';
    }
    if ($dir[0] !== '/') {
        $dir = '/' . $dir;
    }
    return rtrim($dir, '/') . '/';
}

/**
 * @return string
 */
function blackcat_preflight_request_dir_url_path(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? null;
    if (!is_string($uri) || $uri === '' || str_contains($uri, "\0")) {
        return '/';
    }

    $path = parse_url($uri, PHP_URL_PATH);
    if (!is_string($path) || $path === '' || str_contains($path, "\0")) {
        return '/';
    }

    $dir = str_replace('\\', '/', dirname($path));
    if ($dir === '.' || $dir === '') {
        return '/';
    }
    if ($dir[0] !== '/') {
        $dir = '/' . $dir;
    }
    return rtrim($dir, '/') . '/';
}

/**
 * @return string
 */
function blackcat_preflight_request_url_path(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? null;
    if (!is_string($uri) || $uri === '' || str_contains($uri, "\0")) {
        return '/';
    }

    $path = parse_url($uri, PHP_URL_PATH);
    if (!is_string($path) || $path === '' || str_contains($path, "\0")) {
        return '/';
    }
    if ($path[0] !== '/') {
        $path = '/' . $path;
    }
    return $path;
}

/**
 * @return string|null
 */
function blackcat_preflight_request_origin(): ?string
{
    $host = $_SERVER['HTTP_HOST'] ?? null;
    if (!is_string($host) || $host === '' || str_contains($host, "\0")) {
        $host = $_SERVER['SERVER_NAME'] ?? null;
    }
    if (!is_string($host) || $host === '' || str_contains($host, "\0")) {
        return null;
    }
    // Allow host[:port] with sane characters only.
    if (!preg_match('/^[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?$/i', $host)) {
        return null;
    }

    $scheme = null;
    $https = $_SERVER['HTTPS'] ?? null;
    if (is_string($https) && $https !== '' && strtolower($https) !== 'off') {
        $scheme = 'https';
    }
    $requestScheme = $_SERVER['REQUEST_SCHEME'] ?? null;
    if ($scheme === null && is_string($requestScheme) && ($requestScheme === 'http' || $requestScheme === 'https')) {
        $scheme = $requestScheme;
    }
    if ($scheme === null) {
        $scheme = 'http';
    }

    return $scheme . '://' . $host;
}

/**
 * @param string $relative
 * @return string|null
 */
function blackcat_preflight_absolute_url(string $relative): ?string
{
    $origin = blackcat_preflight_request_origin();
    if ($origin === null) {
        return null;
    }
    if ($relative !== '' && $relative[0] === '?') {
        return $origin . blackcat_preflight_request_url_path() . $relative;
    }
    $dir = blackcat_preflight_request_dir_url_path();
    $rel = ltrim($relative, '/');
    return $origin . $dir . $rel;
}

/**
 * Server-side same-origin origin builder for the PathInfo probe (best-effort).
 *
 * Important: Do NOT use HTTP_HOST here (attacker-controlled). Prefer SERVER_NAME + SERVER_PORT.
 *
 * @return string|null
 */
function blackcat_preflight_server_self_origin(): ?string
{
    $host = $_SERVER['SERVER_NAME'] ?? null;
    if (!is_string($host) || $host === '' || str_contains($host, "\0")) {
        return null;
    }
    if (!preg_match('/^[a-z0-9][a-z0-9.-]*$/i', $host)) {
        return null;
    }

    $scheme = null;
    $https = $_SERVER['HTTPS'] ?? null;
    if (is_string($https) && $https !== '' && strtolower($https) !== 'off') {
        $scheme = 'https';
    }
    $requestScheme = $_SERVER['REQUEST_SCHEME'] ?? null;
    if ($scheme === null && is_string($requestScheme) && ($requestScheme === 'http' || $requestScheme === 'https')) {
        $scheme = $requestScheme;
    }
    if ($scheme === null) {
        $scheme = 'http';
    }

    $portRaw = $_SERVER['SERVER_PORT'] ?? null;
    $port = null;
    if (is_string($portRaw) && $portRaw !== '' && ctype_digit($portRaw)) {
        $port = (int) $portRaw;
    } elseif (is_int($portRaw)) {
        $port = $portRaw;
    }

    $portSuffix = '';
    if (is_int($port) && $port >= 1 && $port <= 65535) {
        $isDefault = ($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443);
        if (!$isDefault) {
            $portSuffix = ':' . (string) $port;
        }
    }

    return $scheme . '://' . $host . $portSuffix;
}

/**
 * Fetch a URL as text (best-effort). Used only for same-origin PathInfo probe.
 *
 * @return array{fetched:bool,status:int,ok:bool,text:string,error?:string}
 */
function blackcat_preflight_fetch_text(string $url): array
{
    $timeoutSec = 4;

    $isHttps = str_starts_with($url, 'https://');
    if (function_exists('curl_init') && (!$isHttps || blackcat_preflight_curl_supports_ssl())) {
        /** @var \CurlHandle|false $ch */
        $ch = curl_init($url);
        if ($ch !== false) {
            curl_setopt_array($ch, [
                CURLOPT_HTTPGET => true,
                CURLOPT_HTTPHEADER => [
                    'Accept: text/plain, */*',
                ],
                CURLOPT_CONNECTTIMEOUT => $timeoutSec,
                CURLOPT_TIMEOUT => $timeoutSec,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_MAXREDIRS => 0,
                CURLOPT_RETURNTRANSFER => true,
                // Best-effort probe: disable TLS verification to avoid false negatives on self-signed certs.
                // This probe does not transmit secrets.
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => 0,
            ]);
            $body = curl_exec($ch);
            if ($body === false) {
                // Fall through to stream wrapper if available (some environments have cURL but restrict it).
                unset($ch);
            } else {
                $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                unset($ch);
                return ['fetched' => true, 'status' => $status, 'ok' => $status >= 200 && $status < 300, 'text' => is_string($body) ? $body : ''];
            }
        }
    }

    if (blackcat_preflight_ini_flag('allow_url_fopen')) {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => "Accept: text/plain, */*\r\n",
                'timeout' => $timeoutSec,
                'follow_location' => 0,
                'max_redirects' => 0,
                // Ensure we can observe the response body for non-2xx status codes.
                'ignore_errors' => true,
            ],
            'ssl' => [
                // Best-effort probe: disable TLS verification to avoid false negatives on self-signed certs.
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
                'SNI_enabled' => true,
                'disable_compression' => true,
            ],
        ]);

        /** @var array<int,string>|null $http_response_header */
        $http_response_header = null;
        $body = @file_get_contents($url, false, $context);
        $status = 0;
        $statusLine = is_array($http_response_header) ? ($http_response_header[0] ?? null) : null;
        if (is_string($statusLine) && preg_match('/^HTTP\\/\\d+\\.\\d+\\s+(\\d{3})\\b/', $statusLine, $m)) {
            $status = (int) $m[1];
        }
        if (!is_string($body)) {
            return ['fetched' => false, 'status' => $status, 'ok' => false, 'text' => '', 'error' => 'stream request failed'];
        }
        return ['fetched' => true, 'status' => $status, 'ok' => $status >= 200 && $status < 300, 'text' => $body];
    }

    return ['fetched' => false, 'status' => 0, 'ok' => false, 'text' => '', 'error' => 'no HTTP client available (curl/allow_url_fopen disabled)'];
}

/**
 * Server-side CGI PathInfo probe runner (best-effort).
 *
 * @return array{plan:array<string,mixed>,result:array<string,mixed>}
 */
function blackcat_preflight_run_pathinfo_probe_server(bool $deep): array
{
    $p = blackcat_preflight_prepare_pathinfo_probe();
    $dir = blackcat_preflight_request_dir_url_path();
    $origin = blackcat_preflight_server_self_origin();

    $variantsRel = $deep ? [
        $p['url_path'] . '/x.php',
        $p['url_path'] . '/index.php',
        $p['url_path'] . '/a.php',
        $p['url_path'] . ';x.php',
        $p['url_path'] . '%3bx.php',
    ] : [
        $p['url_path'] . '/x.php',
    ];

    $plan = [
        'mode' => 'server_side',
        'deep' => $deep,
        'control' => [
            'relative' => $p['url_path'],
            'absolute' => $origin !== null ? ($origin . $dir . $p['url_path']) : null,
            'expected_http_status' => 200,
            'marker' => $p['marker'],
            'expected_output_token' => $p['expected'],
        ],
        'variants' => array_map(static function (string $rel) use ($origin, $dir): array {
            return [
                'relative' => $rel,
                'absolute' => $origin !== null ? ($origin . $dir . ltrim($rel, '/')) : null,
            ];
        }, $variantsRel),
        'cleanup' => [
            'required' => false,
            'performed' => true,
        ],
        'notes' => [
            'This probe is best-effort and cannot prove 100% safety.',
            'It uses only same-origin requests derived from SERVER_NAME/SERVER_PORT.',
        ],
    ];

    $result = [
        'status' => 'warn',
        'code' => 'inconclusive',
        'summary' => 'Probe not executed.',
        'control' => null,
        'variants' => [],
    ];

    try {
        if (!is_file($p['file_path'])) {
            $result = [
                'status' => 'warn',
                'code' => 'probe_file_unavailable',
                'summary' => 'Probe file could not be created (no write access or filesystem restrictions).',
                'control' => null,
                'variants' => [],
            ];
            return ['plan' => $plan, 'result' => $result];
        }

        if ($origin === null) {
            $result = [
                'status' => 'warn',
                'code' => 'self_origin_unavailable',
                'summary' => 'Probe could not run (unable to determine same-origin base URL). Open this page in a browser to run the client-side probe.',
                'control' => null,
                'variants' => [],
            ];
            return ['plan' => $plan, 'result' => $result];
        }

        $controlUrl = $origin . $dir . $p['url_path'];
        $control = blackcat_preflight_fetch_text($controlUrl);
        $controlIsReachable = $control['fetched'] && $control['status'] === 200 && str_contains($control['text'], $p['marker']);
        $controlExec = $control['fetched'] && str_contains($control['text'], $p['expected']);

        $variants = [];
        $variantExec = false;
        foreach ($variantsRel as $rel) {
            $abs = $origin . $dir . ltrim($rel, '/');
            $res = blackcat_preflight_fetch_text($abs);
            $exec = $res['fetched'] && str_contains($res['text'], $p['expected']);
            if ($exec) {
                $variantExec = true;
            }
            $variants[] = [
                'relative' => $rel,
                'absolute' => $abs,
                'fetched' => $res['fetched'],
                'http_status' => $res['status'],
                'executed_php' => $exec,
            ];
        }

        if (!$control['fetched']) {
            $result = [
                'status' => 'warn',
                'code' => 'control_fetch_failed',
                'summary' => 'Probe could not run (server-side fetch failed). Open this page in a browser to run the client-side probe.',
                'control' => [
                    'absolute' => $controlUrl,
                    'fetched' => false,
                    'http_status' => 0,
                    'error' => $control['error'] ?? 'unknown error',
                ],
                'variants' => $variants,
            ];
        } elseif (!$controlIsReachable) {
            $result = [
                'status' => 'warn',
                'code' => 'control_unreachable',
                'summary' => 'Probe inconclusive: control file was not reachable as expected (HTTP 200 with marker).',
                'control' => [
                    'absolute' => $controlUrl,
                    'fetched' => $control['fetched'],
                    'http_status' => $control['status'],
                    'has_marker' => str_contains($control['text'], $p['marker']),
                ],
                'variants' => $variants,
            ];
        } elseif ($controlExec) {
            $result = [
                'status' => 'fail',
                'code' => 'executed_txt_as_php',
                'summary' => 'CRITICAL: The server executed a .txt file as PHP.',
                'control' => [
                    'absolute' => $controlUrl,
                    'fetched' => true,
                    'http_status' => $control['status'],
                    'executed_php' => true,
                ],
                'variants' => $variants,
            ];
        } elseif ($variantExec) {
            $result = [
                'status' => 'fail',
                'code' => 'pathinfo_exec_surface',
                'summary' => 'VULNERABLE: A PathInfo-style request caused PHP execution (cgi.fix_pathinfo exploit surface).',
                'control' => [
                    'absolute' => $controlUrl,
                    'fetched' => true,
                    'http_status' => $control['status'],
                    'executed_php' => false,
                ],
                'variants' => $variants,
            ];
        } else {
            $result = [
                'status' => 'pass',
                'code' => 'no_exec_observed',
                'summary' => 'No PHP execution observed for the tested PathInfo variants in this probe.',
                'control' => [
                    'absolute' => $controlUrl,
                    'fetched' => true,
                    'http_status' => $control['status'],
                    'executed_php' => false,
                ],
                'variants' => $variants,
            ];
        }

        return ['plan' => $plan, 'result' => $result];
    } finally {
        if (is_file($p['file_path'])) {
            @unlink($p['file_path']);
        }
    }
}

/**
 * @return array{id:string, filename:string, file_path:string, url_path:string, expected:string, marker:string}
 */
function blackcat_preflight_prepare_pathinfo_probe(): array
{
    $id = blackcat_preflight_random_id();
    $filename = 'blackcat-pathinfo-probe.' . $id . '.txt';
    $filePath = __DIR__ . DIRECTORY_SEPARATOR . $filename;
    // Use a relative URL for probes: some hostings populate SCRIPT_NAME with a filesystem-like path.
    // The browser will resolve this relative to the currently opened preflight URL.
    $urlPath = $filename;
    $expected = 'BLACKCAT_PATHINFO_PROBE_' . $id;
    $marker = 'BLACKCAT_PATHINFO_PROBE_FILE_' . $id;

    // Avoid embedding the expected output string verbatim in the source file.
    $php = "<?php /* " . $marker . " */ echo 'BLACKCAT_PATHINFO_' . 'PROBE_' . '" . $id . "'; ?>\n";
    @file_put_contents($filePath, $php, LOCK_EX);

    return [
        'id' => $id,
        'filename' => $filename,
        'file_path' => $filePath,
        'url_path' => $urlPath,
        'expected' => $expected,
        'marker' => $marker,
    ];
}

/**
 * @return array{ok:bool, error?:string}
 */
function blackcat_preflight_cleanup_pathinfo_probe(): array
{
    $probe = blackcat_preflight_probe();
    if ($probe !== 'pathinfo') {
        return ['ok' => false, 'error' => 'probe not enabled'];
    }

    $token = $_GET['token'] ?? null;
    $file = $_GET['file'] ?? null;
    if (!is_string($token) || $token === '' || !preg_match('/^[a-f0-9]{16}$/', $token)) {
        return ['ok' => false, 'error' => 'invalid token'];
    }
    if (!is_string($file) || $file === '' || str_contains($file, "\0")) {
        return ['ok' => false, 'error' => 'invalid file'];
    }

    $expectedName = 'blackcat-pathinfo-probe.' . $token . '.txt';
    if (!hash_equals($expectedName, $file)) {
        return ['ok' => false, 'error' => 'file mismatch'];
    }

    $path = __DIR__ . DIRECTORY_SEPARATOR . $file;
    if (is_file($path)) {
        @unlink($path);
    }

    return ['ok' => true];
}

/**
 * @return array{ok:bool, code?:string, details?:string, hints?:list<string>}
 */
function blackcat_preflight_check_php_version(): array
{
    if (PHP_VERSION_ID < BLACKCAT_PREFLIGHT_MIN_PHP) {
        return [
            'ok' => false,
            'code' => 'php_version_too_low',
            'details' => 'Detected PHP ' . PHP_VERSION . '. Kernel-minimal bundle requires PHP 8.3+ (blackcat-config).',
            'hints' => [
                'Switch the hosting to PHP 8.3+ (often a control-panel setting).',
                'If the hosting cannot run PHP 8.3, use a different hosting/VPS for BlackCat.',
            ],
        ];
    }

    return [
        'ok' => true,
        'details' => 'PHP ' . PHP_VERSION,
    ];
}

/**
 * @return bool
 */
function blackcat_preflight_ini_flag(string $name): bool
{
    $raw = ini_get($name);
    if ($raw === false) {
        return false;
    }
    $value = strtolower(trim((string) $raw));
    if ($value === '' || $value === '0' || $value === 'off' || $value === 'false' || $value === 'no') {
        return false;
    }
    return true;
}

/**
 * @return list<string>
 */
function blackcat_preflight_disabled_functions(): array
{
    $raw = ini_get('disable_functions');
    if (!is_string($raw) || trim($raw) === '') {
        return [];
    }
    $parts = array_map('trim', explode(',', $raw));
    $out = [];
    foreach ($parts as $part) {
        if ($part !== '') {
            $out[] = strtolower($part);
        }
    }
    return array_values(array_unique($out));
}

/**
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_required_extensions(): array
{
    $missing = [];
    foreach (['json', 'sodium', 'pdo'] as $ext) {
        if (!extension_loaded($ext)) {
            $missing[] = $ext;
        }
    }

    if ($missing !== []) {
        return [
            'ok' => false,
            'code' => 'missing_extensions',
            'details' => 'Missing required PHP extensions: ' . implode(', ', array_map(static fn (string $e): string => "ext-{$e}", $missing)),
            'hints' => [
                'Enable the missing extensions in your hosting control panel (or ask your provider).',
                'BlackCat crypto uses libsodium (ext-sodium) by default.',
            ],
        ];
    }

    return [
        'ok' => true,
        'details' => 'ext-json, ext-sodium, ext-pdo: OK',
    ];
}

/**
 * @return bool
 */
function blackcat_preflight_curl_supports_ssl(): bool
{
    if (!function_exists('curl_version')) {
        return false;
    }
    /** @var array<string,mixed> $v */
    $v = curl_version();
    $features = $v['features'] ?? 0;
    if (!is_int($features)) {
        return false;
    }
    return defined('CURL_VERSION_SSL') && (($features & CURL_VERSION_SSL) === CURL_VERSION_SSL);
}

/**
 * TLS verification is required for secure setup flows.
 *
 * Note: BlackCat crypto uses libsodium, but TLS/PKI verification is a separate concern.
 *
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_tls_verify_capability(): array
{
    $hasOpenssl = extension_loaded('openssl');
    $hasCurl = function_exists('curl_init') && blackcat_preflight_curl_supports_ssl();

    if ($hasOpenssl && $hasCurl) {
        return ['ok' => true, 'details' => 'TLS verification: OpenSSL + cURL(SSL) available'];
    }
    if ($hasOpenssl) {
        return ['ok' => true, 'details' => 'TLS verification: OpenSSL available'];
    }
    if ($hasCurl) {
        return ['ok' => true, 'details' => 'TLS verification: cURL(SSL) available'];
    }

    return [
        'ok' => false,
        'code' => 'tls_verify_unavailable',
        'details' => 'No server-side TLS verification capability detected (missing ext-openssl and cURL SSL support).',
        'hints' => [
            'Enable OpenSSL or cURL with SSL in your hosting (common names: ext-openssl, ext-curl).',
            'If your hosting cannot provide TLS verification, do not run the web setup there. Use the offline preparation flow and upload prepared artifacts via FTP.',
        ],
    ];
}

/**
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_web3_transport_capability(): array
{
    $hasCurl = function_exists('curl_init') && blackcat_preflight_curl_supports_ssl();
    if ($hasCurl) {
        return [
            'ok' => true,
            'details' => 'Web3 transport: cURL(SSL) available',
        ];
    }

    $hasOpenssl = extension_loaded('openssl');
    $allowUrlFopen = blackcat_preflight_ini_flag('allow_url_fopen');
    if ($hasOpenssl && $allowUrlFopen) {
        return [
            'ok' => true,
            'details' => 'Web3 transport: HTTPS stream wrapper available (OpenSSL + allow_url_fopen)',
        ];
    }

    $hints = [];
    if (!$hasOpenssl) {
        $hints[] = 'Enable OpenSSL or enable cURL (with SSL).';
    }
    if (!$allowUrlFopen) {
        $hints[] = 'Enable allow_url_fopen or enable cURL (with SSL).';
    }

    return [
        'ok' => false,
        'code' => 'web3_transport_unavailable',
        'details' => 'Cannot establish an outbound HTTPS client for RPC (no cURL SSL; and HTTPS streams are unavailable).',
        'hints' => $hints !== [] ? $hints : ['Enable cURL(SSL) or OpenSSL + allow_url_fopen.'],
    ];
}

/**
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_basic_hardening(): array
{
    $policy = blackcat_preflight_policy()['policy'];
    $fails = [];
    $warns = [];
    $info = [];
    $failIds = [];
    $warnIds = [];
    $meta = [
        'cgi_fix_pathinfo_enabled' => false,
        'cgi_fix_pathinfo_only_fail' => false,
        'cgi_fix_pathinfo_probe_supported' => true, // browser probe (same-origin fetch)
        'cgi_fix_pathinfo_probe_mode' => 'browser',
    ];

    if (blackcat_preflight_ini_flag('allow_url_include')) {
        $fails[] = 'allow_url_include is enabled (unsafe).';
        $failIds[] = 'allow_url_include';
    }

    $displayErrors = blackcat_preflight_ini_flag('display_errors');
    $displayStartupErrors = blackcat_preflight_ini_flag('display_startup_errors');
    if ($displayErrors || $displayStartupErrors) {
        // Best-effort: detect whether the runtime can override this (ini_set) like HttpKernel does.
        $canOverride = false;
        if (function_exists('ini_set')) {
            @ini_set('display_errors', '0');
            @ini_set('display_startup_errors', '0');
            $afterErrors = blackcat_preflight_ini_flag('display_errors');
            $afterStartup = blackcat_preflight_ini_flag('display_startup_errors');
            $canOverride = !$afterErrors && !$afterStartup;
        }

        if ($policy !== 'warn' && !$canOverride) {
            $fails[] = 'display_errors/display_startup_errors is enabled (information disclosure).';
            $failIds[] = 'display_errors';
        } else {
            $warns[] = 'display_errors/display_startup_errors is enabled (information disclosure).'
                . ($canOverride ? ' Note: it appears overrideable at runtime (ini_set), but production should still disable it in hosting settings.' : '');
            $warnIds[] = 'display_errors';
        }
    }

    $pharReadonly = ini_get('phar.readonly');
    if (is_string($pharReadonly) && trim($pharReadonly) !== '' && trim($pharReadonly) !== '1') {
        if ($policy !== 'warn') {
            $fails[] = 'phar.readonly is disabled (PHAR deserialization risk).';
            $failIds[] = 'phar_readonly';
        } else {
            $warns[] = 'phar.readonly is disabled (PHAR deserialization risk).';
            $warnIds[] = 'phar_readonly';
        }
    }

    if (blackcat_preflight_ini_flag('enable_dl')) {
        if ($policy !== 'warn') {
            $fails[] = 'enable_dl is enabled (runtime extension loading increases attack surface).';
            $failIds[] = 'enable_dl';
        } else {
            $warns[] = 'enable_dl is enabled (runtime extension loading increases attack surface).';
            $warnIds[] = 'enable_dl';
        }
    }

    $autoPrepend = ini_get('auto_prepend_file');
    if (is_string($autoPrepend) && trim($autoPrepend) !== '') {
        if ($policy !== 'warn') {
            $fails[] = 'auto_prepend_file is set (hidden code injection risk).';
            $failIds[] = 'auto_prepend_file';
        } else {
            $warns[] = 'auto_prepend_file is set (hidden code injection risk).';
            $warnIds[] = 'auto_prepend_file';
        }
    }

    $autoAppend = ini_get('auto_append_file');
    if (is_string($autoAppend) && trim($autoAppend) !== '') {
        if ($policy !== 'warn') {
            $fails[] = 'auto_append_file is set (hidden code injection risk).';
            $failIds[] = 'auto_append_file';
        } else {
            $warns[] = 'auto_append_file is set (hidden code injection risk).';
            $warnIds[] = 'auto_append_file';
        }
    }

    $cgiFixPathinfo = blackcat_preflight_ini_flag('cgi.fix_pathinfo');
    if ($cgiFixPathinfo && in_array(PHP_SAPI, ['fpm-fcgi', 'cgi', 'cgi-fcgi'], true)) {
        $meta['cgi_fix_pathinfo_enabled'] = true;
        if ($policy === 'warn') {
            $warns[] = 'cgi.fix_pathinfo is enabled (detected via ini_get). A best-effort PathInfo probe will run automatically below.';
            $warnIds[] = 'cgi_fix_pathinfo';
        } else {
            // strict + less-strict are fail-closed here; less-strict may be allowed only if the probe shows NO EXEC.
            $fails[] = 'cgi.fix_pathinfo is enabled (detected via ini_get). A best-effort PathInfo probe will run automatically below.';
            $failIds[] = 'cgi_fix_pathinfo';
        }
    }

    $openBasedir = ini_get('open_basedir');
    if (!is_string($openBasedir) || trim($openBasedir) === '') {
        if ($policy !== 'warn') {
            $fails[] = 'open_basedir is not set (required hardening control).';
            $failIds[] = 'open_basedir';
        } else {
            $warns[] = 'open_basedir is not set (recommended hardening control).';
            $warnIds[] = 'open_basedir';
        }
    } else {
        $info[] = 'open_basedir is set. Ensure it includes your BlackCat bundle root (config.runtime.json + .blackcat) and any OS paths you use (/etc/blackcat, /var/lib/blackcat).';
    }

    $disabled = blackcat_preflight_disabled_functions();
    $dangerous = ['exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec'];
    $callable = [];
    foreach ($dangerous as $fn) {
        // If the function is disabled (disable_functions) or unavailable (extension not loaded),
        // function_exists() should be false. Treat "callable" as the real risk.
        if (function_exists($fn)) {
            $callable[] = $fn;
        }
    }

    if ($callable !== []) {
        $msg = 'Dangerous process-exec functions are callable: ' . implode(', ', $callable) . '. Disable them (recommended: disable_functions=' . implode(',', $dangerous) . ').';
        if ($policy !== 'warn') {
            $fails[] = $msg;
            $failIds[] = 'dangerous_exec';
        } else {
            $warns[] = $msg;
            $warnIds[] = 'dangerous_exec';
        }
    } elseif ($disabled === []) {
        // Informational only: some hostings may disable exec primitives at another layer.
        $info[] = 'disable_functions is empty, but no dangerous process-exec functions appear callable in this runtime.';
    }

    $meta['cgi_fix_pathinfo_only_fail'] = $meta['cgi_fix_pathinfo_enabled'] && ($failIds !== [] && $failIds === ['cgi_fix_pathinfo']);

    if ($fails !== []) {
        $hints = [
            'Harden php.ini (hosting settings) to remove the unsafe flags above.',
        ];
        if ($meta['cgi_fix_pathinfo_enabled']) {
            $hints[] = 'If you cannot change php.ini, you may use ?policy=less-strict (fail-closed; requires a clean PathInfo probe + a locked on-chain probe attestation).';
        }
        $hints[] = 'Use ?policy=warn to evaluate a non-strict deployment.';
        return [
            'ok' => false,
            'code' => 'php_ini_unsafe',
            'details' => implode(' ', $fails),
            'hints' => $hints,
            'meta' => $meta,
        ];
    }

    if ($warns !== []) {
        return [
            'ok' => true,
            'code' => 'php_ini_warn',
            'details' => implode(' ', array_merge($warns, $info)),
            'hints' => [
                'Align php.ini with the TrustKernel policy you intend to run.',
                'If open_basedir is set, ensure the BlackCat bundle root is inside the allowed directories.',
            ],
            'meta' => $meta,
        ];
    }

    if ($info !== []) {
        return [
            'ok' => true,
            'code' => 'php_ini_info',
            'details' => implode(' ', $info),
            'hints' => [
                'Ensure the BlackCat bundle root is inside open_basedir.',
            ],
            'meta' => $meta,
        ];
    }

    return [
        'ok' => true,
        'details' => 'php.ini hardening: OK',
        'meta' => $meta,
    ];
}

/**
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_write_access(): array
{
    $dir = __DIR__;
    $probeName = '.blackcat_preflight_' . blackcat_preflight_random_id() . '.tmp';
    $probePath = $dir . DIRECTORY_SEPARATOR . $probeName;
    $ok = @file_put_contents($probePath, "blackcat_preflight\n");
    if ($ok === false) {
        return [
            'ok' => false,
            'code' => 'write_blocked',
            'details' => 'PHP cannot write files in this directory.',
            'hints' => [
                'Ensure the hosting allows PHP file writes for BlackCat state/config.',
                'If you uploaded this file into a read-only directory, move it to a writable location and re-run.',
                'The Stage 3 bundle writes state/config in the bundle root; ensure that directory is writable too.',
            ],
        ];
    }

    @unlink($probePath);
    return [
        'ok' => true,
        'details' => 'Write access: OK (temporary probe file created and removed)',
    ];
}

/**
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_outbound_rpc(): array
{
    $payload = '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}';
    $timeoutSec = 4;

    foreach (BLACKCAT_PREFLIGHT_RPC_URLS as $url) {
        $url = trim($url);
        if ($url === '') {
            continue;
        }

        $err = null;
        $status = null;
        $body = null;

        if (function_exists('curl_init') && blackcat_preflight_curl_supports_ssl()) {
            /** @var \CurlHandle|false $ch */
            $ch = curl_init($url);
            if ($ch !== false) {
                curl_setopt_array($ch, [
                    CURLOPT_POST => true,
                    CURLOPT_POSTFIELDS => $payload,
                    CURLOPT_HTTPHEADER => [
                        'Content-Type: application/json',
                        'Accept: application/json',
                    ],
                    CURLOPT_CONNECTTIMEOUT => $timeoutSec,
                    CURLOPT_TIMEOUT => $timeoutSec,
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_MAXREDIRS => 0,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2,
                ]);
                $body = curl_exec($ch);
                if ($body === false) {
                    $err = curl_error($ch);
                } else {
                    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                }
                unset($ch);
            }
        } elseif (extension_loaded('openssl') && blackcat_preflight_ini_flag('allow_url_fopen')) {
            $host = parse_url($url, PHP_URL_HOST);
            $ssl = [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false,
                'SNI_enabled' => true,
                'disable_compression' => true,
            ];
            if (is_string($host) && $host !== '') {
                $ssl['peer_name'] = $host;
            }
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
                    'content' => $payload,
                    'timeout' => $timeoutSec,
                    'follow_location' => 0,
                    'max_redirects' => 0,
                ],
                'ssl' => $ssl,
            ]);

            /** @var array<int,string>|null $http_response_header */
            $http_response_header = null;
            $body = @file_get_contents($url, false, $context);
            if ($body === false) {
                $err = 'stream request failed';
            } else {
                $statusLine = is_array($http_response_header) ? ($http_response_header[0] ?? null) : null;
                if (is_string($statusLine) && preg_match('/^HTTP\\/\\d+\\.\\d+\\s+(\\d{3})\\b/', $statusLine, $m)) {
                    $status = (int) $m[1];
                }
            }
        } else {
            return [
                'ok' => false,
                'code' => 'rpc_client_unavailable',
                'details' => 'No outbound HTTPS client available to test RPC connectivity.',
                'hints' => [
                    'Enable cURL(SSL) or OpenSSL + allow_url_fopen.',
                ],
            ];
        }

        if ($status === 429) {
            return [
                'ok' => true,
                'code' => 'rpc_rate_limited',
                'details' => 'RPC reachable but rate-limited (HTTP 429). You may need multiple endpoints for production quorum.',
                'hints' => [
                    'Add 2+ RPC endpoints in runtime config for strict production.',
                    'If your hosting blocks outbound HTTPS, BlackCat cannot operate in strict mode.',
                ],
            ];
        }

        if ($status !== null && $status >= 200 && $status < 300 && is_string($body) && $body !== '') {
            /** @var mixed $decoded */
            $decoded = json_decode($body, true);
            if (is_array($decoded) && isset($decoded['result']) && is_string($decoded['result'])) {
                return [
                    'ok' => true,
                    'details' => 'Outbound RPC OK: ' . $url . ' (eth_chainId=' . $decoded['result'] . ')',
                ];
            }

            return [
                'ok' => true,
                'details' => 'Outbound RPC OK: ' . $url,
            ];
        }

        $detail = 'RPC check failed: ' . $url;
        if ($status !== null) {
            $detail .= ' (HTTP ' . $status . ')';
        }
        if (is_string($err) && $err !== '') {
            $detail .= ' — ' . $err;
        }
        return [
            'ok' => false,
            'code' => 'rpc_unreachable',
            'details' => $detail,
            'hints' => [
                'Ensure outbound HTTPS is allowed from PHP (egress firewall, hosting policy).',
                'If your hosting blocks outbound HTTPS, BlackCat cannot keep a Web3-backed trust state.',
            ],
        ];
    }

    return [
        'ok' => false,
        'code' => 'rpc_missing',
        'details' => 'No RPC endpoints configured in preflight script.',
    ];
}

/**
 * @param array{id?:string,status:string,title:string,details:string,hints:list<string>,meta?:array<string,mixed>} $check
 */
function blackcat_preflight_render_check(array $check): string
{
    $rawId = $check['id'] ?? '';
    $safeId = '';
    if (is_string($rawId) && $rawId !== '') {
        $safeId = preg_replace('/[^a-z0-9_\\-]/i', '_', $rawId) ?? '';
    }
    $rootId = $safeId !== '' ? ('bcCheck_' . $safeId) : '';
    $badgeId = $safeId !== '' ? ('bcCheckBadge_' . $safeId) : '';
    $detailsId = $safeId !== '' ? ('bcCheckDetails_' . $safeId) : '';

    $status = $check['status'];
    $badgeClass = $status === 'pass' ? 'pass' : ($status === 'warn' ? 'warn' : 'fail');
    $badgeText = strtoupper($status);

    $hintsHtml = '';
    if ($check['hints'] !== []) {
        $hintsHtml .= '<ul class="hints">';
        foreach ($check['hints'] as $hint) {
            $hintsHtml .= '<li>' . htmlspecialchars($hint, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</li>';
        }
        $hintsHtml .= '</ul>';
    }

    $attrs = '';
    if ($safeId !== '') {
        $attrs .= ' id="' . htmlspecialchars($rootId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"';
        $attrs .= ' data-check-id="' . htmlspecialchars($safeId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"';
        $attrs .= ' data-check-status="' . htmlspecialchars($status, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"';
        if (isset($check['meta']) && is_array($check['meta'])) {
            if (!empty($check['meta']['cgi_fix_pathinfo_enabled'])) {
                $attrs .= ' data-meta-cgi-fix-pathinfo-enabled="1"';
            }
            if (!empty($check['meta']['cgi_fix_pathinfo_only_fail'])) {
                $attrs .= ' data-meta-cgi-fix-pathinfo-only-fail="1"';
            }
        }
    }

    return '<div class="check"' . $attrs . '>'
        . '<div class="checkHead">'
        . '<span class="badge ' . $badgeClass . '"' . ($badgeId !== '' ? ' id="' . htmlspecialchars($badgeId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"' : '') . '>' . $badgeText . '</span>'
        . '<div class="checkTitle">' . htmlspecialchars($check['title'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</div>'
        . '</div>'
        . '<div class="checkBody">'
        . '<div class="checkDetails"' . ($detailsId !== '' ? ' id="' . htmlspecialchars($detailsId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"' : '') . '>' . htmlspecialchars($check['details'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</div>'
        . $hintsHtml
        . '</div>'
        . '</div>';
}

$checks = [];

$phpCheck = blackcat_preflight_check_php_version();
$checks[] = [
    'id' => 'php_version',
    'title' => 'PHP version',
    'status' => $phpCheck['ok'] ? 'pass' : 'fail',
    'details' => $phpCheck['details'] ?? 'Unknown',
    'hints' => $phpCheck['hints'] ?? [],
];

$extCheck = blackcat_preflight_check_required_extensions();
$checks[] = [
    'id' => 'extensions',
    'title' => 'Required extensions (core)',
    'status' => $extCheck['ok'] ? 'pass' : 'fail',
    'details' => $extCheck['details'] ?? 'Unknown',
    'hints' => $extCheck['hints'] ?? [],
];

$tlsCheck = blackcat_preflight_check_tls_verify_capability();
$checks[] = [
    'id' => 'tls_verify',
    'title' => 'TLS verification capability',
    'status' => $tlsCheck['ok'] ? 'pass' : 'fail',
    'details' => $tlsCheck['details'] ?? 'Unknown',
    'hints' => $tlsCheck['hints'] ?? [],
];

$transportCheck = blackcat_preflight_check_web3_transport_capability();
$checks[] = [
    'id' => 'web3_transport',
    'title' => 'Web3 RPC transport (outbound HTTPS client)',
    'status' => $transportCheck['ok'] ? 'pass' : 'fail',
    'details' => $transportCheck['details'] ?? 'Unknown',
    'hints' => $transportCheck['hints'] ?? [],
];

$rpcCheck = blackcat_preflight_check_outbound_rpc();
$checks[] = [
    'id' => 'rpc_outbound',
    'title' => 'Outbound RPC connectivity (Edgen)',
    'status' => ($rpcCheck['ok'] && ($rpcCheck['code'] ?? '') === 'rpc_rate_limited') ? 'warn' : ($rpcCheck['ok'] ? 'pass' : 'fail'),
    'details' => $rpcCheck['details'] ?? 'Unknown',
    'hints' => $rpcCheck['hints'] ?? [],
];

$iniCheck = blackcat_preflight_check_basic_hardening();
$checks[] = [
    'id' => 'php_ini',
    'title' => 'php.ini safety posture',
    'status' => ($iniCheck['ok'] && ($iniCheck['code'] ?? '') === 'php_ini_warn') ? 'warn' : ($iniCheck['ok'] ? 'pass' : 'fail'),
    'details' => $iniCheck['details'] ?? 'Unknown',
    'hints' => $iniCheck['hints'] ?? [],
    'meta' => $iniCheck['meta'] ?? [],
];

$writeCheck = blackcat_preflight_check_write_access();
$checks[] = [
    'id' => 'write_access',
    'title' => 'Filesystem write access',
    'status' => $writeCheck['ok'] ? 'pass' : 'fail',
    'details' => $writeCheck['details'] ?? 'Unknown',
    'hints' => $writeCheck['hints'] ?? [],
];

$overall = 'pass';
foreach ($checks as $check) {
    if ($check['status'] === 'fail') {
        $overall = 'fail';
        break;
    }
    if ($check['status'] === 'warn') {
        $overall = 'warn';
    }
}

$wantJson = false;
$format = $_GET['format'] ?? null;
if (is_string($format) && strtolower(trim($format)) === 'json') {
    $wantJson = true;
}
if (!$wantJson) {
    $accept = $_SERVER['HTTP_ACCEPT'] ?? null;
    if (is_string($accept) && str_contains(strtolower($accept), 'application/json')) {
        $wantJson = true;
    }
}

$probeMode = blackcat_preflight_probe();
$cleanup = $_GET['cleanup'] ?? null;
if ($probeMode === 'pathinfo' && is_string($cleanup) && trim($cleanup) === '1') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(blackcat_preflight_cleanup_pathinfo_probe(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    exit;
}

if ($wantJson) {
    $policyInfo = blackcat_preflight_policy();
    // Mirror HTML behavior: auto-run the best-effort probe in JSON mode too (when relevant).
    if ($probeMode !== 'pathinfo' && $autoPathinfoProbe) {
        $probeMode = 'pathinfo';
    }
    $probe = null;
    if ($probeMode === 'pathinfo') {
        $deep = blackcat_preflight_probe_deep();
        $probeRun = blackcat_preflight_run_pathinfo_probe_server($deep);
        $probe = [
            'pathinfo' => array_merge($probeRun['plan'], [
                'auto' => $autoPathinfoProbe,
                'waiver_attestation' => blackcat_preflight_pathinfo_no_exec_waiver_attestation(),
                'result' => $probeRun['result'],
            ]),
        ];

        $probeStatus = $probeRun['result']['status'] ?? null;

        // If the probe indicates an execution surface, fail regardless of policy.
        if ($probeStatus === 'fail') {
            foreach ($checks as $idx => $check) {
                if (($check['id'] ?? null) !== 'php_ini') {
                    continue;
                }
                $checks[$idx]['status'] = 'fail';
                $checks[$idx]['details'] = 'PathInfo probe indicates a PHP execution surface. This hosting is unsafe for TrustKernel deployments.';
                $checks[$idx]['hints'] = [
                    'Disable cgi.fix_pathinfo (php.ini) and use correct webserver routing (try_files / SCRIPT_FILENAME).',
                    'If you cannot harden this hosting, do not deploy TrustKernel here.',
                ];
                break;
            }
        }

        // If this hosting fails ONLY due to cgi.fix_pathinfo, less-strict may be allowed when the probe is NO EXEC.
        if ($probeStatus === 'pass' && $policyInfo['policy'] === 'less-strict') {
            foreach ($checks as $idx => $check) {
                if (($check['id'] ?? null) !== 'php_ini') {
                    continue;
                }
                $meta = $check['meta'] ?? null;
                if (!is_array($meta) || empty($meta['cgi_fix_pathinfo_only_fail'])) {
                    break;
                }
                $checks[$idx]['status'] = 'pass';
                $checks[$idx]['details'] = 'cgi.fix_pathinfo is enabled, but the PathInfo probe observed NO EXEC for tested variants. Note: less-strict still requires a locked on-chain probe attestation to satisfy TrustKernel.';
                $checks[$idx]['hints'] = [
                    'Proceed only with less-strict and lock the PathInfo probe waiver attestation on-chain (rootAuthority).',
                    'If you can change php.ini, prefer cgi.fix_pathinfo=0 for strict production.',
                ];
                break;
            }
        }

        // Recompute overall after the probe may have adjusted php_ini.
        $overall = 'pass';
        foreach ($checks as $check) {
            if (($check['status'] ?? '') === 'fail') {
                $overall = 'fail';
                break;
            }
            if (($check['status'] ?? '') === 'warn') {
                $overall = 'warn';
            }
        }
    }

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'generated_at' => gmdate('c'),
        'policy' => $policyInfo['policy'],
        'php_sapi' => PHP_SAPI,
        'overall' => $overall,
        'checks' => $checks,
        'probe' => $probe,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    exit;
}

// HTML mode: if cgi.fix_pathinfo is enabled on FPM/CGI, auto-run the best-effort probe (no extra steps).
if ($probeMode !== 'pathinfo' && $autoPathinfoProbe) {
    $probeMode = 'pathinfo';
}

$overallBadgeClass = $overall === 'pass' ? 'pass' : ($overall === 'warn' ? 'warn' : 'fail');
$overallTitle = $overall === 'pass' ? 'READY' : ($overall === 'warn' ? 'WARNINGS' : 'BLOCKED');

$checksHtml = '';
foreach ($checks as $check) {
    $checksHtml .= blackcat_preflight_render_check($check);
}

$docLink = 'blackcat-installer/docs/STAGE3_KERNEL_MINIMAL_BUNDLE.md';
$policy = blackcat_preflight_policy()['policy'];

$policyNav = '';
if (!$wantJson) {
    $currentPath = blackcat_preflight_request_url_path();
    $qs = $_GET;
    unset($qs['policy']);
    $mk = static function (string $p) use ($currentPath, $qs): string {
        $next = $qs;
        $next['policy'] = $p;
        $href = $currentPath . '?' . http_build_query($next);
        return htmlspecialchars($href, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    };

    $policyNav = '<div class="policyNav">'
        . '<span class="policyLabel">Policy</span>'
        . '<a class="pill' . ($policy === 'strict' ? ' active' : '') . '" href="' . $mk('strict') . '">strict</a>'
        . '<a class="pill' . ($policy === 'less-strict' ? ' active' : '') . '" href="' . $mk('less-strict') . '">less-strict</a>'
        . '<a class="pill' . ($policy === 'warn' ? ' active' : '') . '" href="' . $mk('warn') . '">warn</a>'
        . '</div>';
}

$probePanel = '';
if ($probeMode === 'pathinfo') {
    $p = blackcat_preflight_prepare_pathinfo_probe();
    $deep = blackcat_preflight_probe_deep();
    $phpIniMeta = [];
    foreach ($checks as $c) {
        if (($c['id'] ?? '') === 'php_ini' && isset($c['meta']) && is_array($c['meta'])) {
            $phpIniMeta = $c['meta'];
            break;
        }
    }
    $probeConfig = [
        'id' => $p['id'],
        'filename' => $p['filename'],
        'url' => $p['url_path'],
        'variants' => $deep ? [
            $p['url_path'] . '/x.php',
            $p['url_path'] . '/index.php',
            $p['url_path'] . '/a.php',
            $p['url_path'] . ';x.php',
            $p['url_path'] . '%3bx.php',
        ] : [
            $p['url_path'] . '/x.php',
        ],
        'expected' => $p['expected'],
        'marker' => $p['marker'] ?? null,
        'cleanup_url' => '?probe=pathinfo&cleanup=1&token=' . rawurlencode($p['id']) . '&file=' . rawurlencode($p['filename']),
        'deep' => $deep,
        'policy' => $policy,
        'affects_check_id' => 'php_ini',
        'less_strict_can_clear' => !empty($phpIniMeta['cgi_fix_pathinfo_only_fail']),
        'waiver_attestation' => blackcat_preflight_pathinfo_no_exec_waiver_attestation(),
    ];

    $probePanel = '<div class="check" style="margin-top:12px;">'
        . '<div class="checkHead"><span class="badge warn" id="bcProbeBadge">RUNNING</span>'
        . '<div><div class="checkTitle">CGI PathInfo Probe (best-effort)</div>'
        . '<div class="sub">This simulates the classic <code>file.txt/x.php</code> exploit surface when <code>cgi.fix_pathinfo</code> is enabled.</div></div></div>'
        . '<div class="checkBody">'
        . '<div class="checkDetails" id="bcProbeSummary">Running probe…</div>'
        . '<ul class="hints" id="bcProbeHints">'
        . '<li>Note: This probe is <strong>informational</strong>. Strict production should still disable <code>cgi.fix_pathinfo</code> where possible.</li>'
        . ($deep ? '<li>Deep mode: multiple variants are tested (<code>deep=1</code>).</li>' : '<li>Tip: add <code>&amp;deep=1</code> to test more variants.</li>')
        . '</ul>'
        . '</div>'
        . '</div>'
        . '<script>'
        . '(() => {'
        . 'const cfg = ' . json_encode($probeConfig, JSON_UNESCAPED_SLASHES) . ';'
        . 'const badge = document.getElementById("bcProbeBadge");'
        . 'const summary = document.getElementById("bcProbeSummary");'
        . 'const hints = document.getElementById("bcProbeHints");'
        . 'const set = (cls, txt) => { badge.className = "badge " + cls; badge.textContent = txt; };'
        . 'const addHint = (t) => { const li = document.createElement("li"); li.textContent = t; hints.appendChild(li); };'
        . 'const setCheck = (status, detail) => {'
        . '  if (!cfg.affects_check_id) return;'
        . '  const id = String(cfg.affects_check_id);'
        . '  const safeId = id.replace(/[^a-z0-9_\\-]/gi, "_");'
        . '  const badgeEl = document.getElementById("bcCheckBadge_" + safeId);'
        . '  const detailsEl = document.getElementById("bcCheckDetails_" + safeId);'
        . '  const rootEl = document.getElementById("bcCheck_" + safeId);'
        . '  if (rootEl) rootEl.dataset.checkStatus = status;'
        . '  if (badgeEl) { badgeEl.className = "badge " + (status === "pass" ? "pass" : (status === "warn" ? "warn" : "fail")); badgeEl.textContent = status.toUpperCase(); }'
        . '  if (detailsEl && typeof detail === "string" && detail) detailsEl.textContent = detail;'
        . '};'
        . 'const recomputeOverall = () => {'
        . '  const overall = document.getElementById("bcOverallBadge");'
        . '  if (!overall) return;'
        . '  const checks = Array.from(document.querySelectorAll(".check[data-check-id]"));'
        . '  let anyFail = false;'
        . '  let anyWarn = false;'
        . '  for (const c of checks) {'
        . '    const s = c.dataset.checkStatus || "";'
        . '    if (s === "fail") { anyFail = true; break; }'
        . '    if (s === "warn") anyWarn = true;'
        . '  }'
        . '  const next = anyFail ? { s: "fail", t: "BLOCKED", cls: "fail" } : (anyWarn ? { s: "warn", t: "WARNINGS", cls: "warn" } : { s: "pass", t: "READY", cls: "pass" });'
        . '  overall.className = "badge " + next.cls;'
        . '  overall.textContent = next.t;'
        . '  overall.dataset.overallStatus = next.s;'
        . '};'
        . 'const readText = async (url) => {'
        . '  try {'
        . '    const res = await fetch(url, { cache: "no-store", credentials: "same-origin" });'
        . '    const text = await res.text();'
        . '    return { fetched: true, status: res.status, ok: res.ok, text };'
        . '  } catch (e) {'
        . '    return { fetched: false, status: 0, ok: false, text: "", error: String(e && e.message ? e.message : e) };'
        . '  }'
        . '};'
        . '(async () => {'
        . '  const control = await readText(cfg.url);'
        . '  const variants = Array.isArray(cfg.variants) ? cfg.variants : [];'
        . '  const results = [];'
        . '  for (const u of variants) { results.push({ url: u, res: await readText(u) }); }'
        . '  const marker = (typeof cfg.marker === "string" && cfg.marker) ? cfg.marker : null;'
        . '  const controlIsReachable = control.fetched && control.status === 200 && (!marker || control.text.includes(marker));'
        . '  const controlExec = control.fetched && control.text.includes(cfg.expected);'
        . '  const variantExec = results.some((r) => r.res.fetched && r.res.text.includes(cfg.expected));'
        . '  if (!control.fetched) {'
        . '    set("warn", "INCONCLUSIVE");'
        . '    summary.textContent = "Probe could not run (browser could not fetch the control file).";'
        . '    addHint("Control fetch failed: " + (control.error || "unknown error"));'
        . '  } else if (!controlIsReachable) {'
        . '    set("warn", "INCONCLUSIVE");'
        . '    summary.textContent = "Probe is inconclusive: the control probe file was not reachable (expected HTTP 200).";'
        . '    addHint("Control URL: " + cfg.url + " (HTTP " + String(control.status) + ")");'
        . '    addHint("Ensure this preflight file is served from a normal web-accessible directory (not rewritten), then re-run the probe.");'
        . '  } else if (controlExec) {'
        . '    set("fail", "VULNERABLE");'
        . '    summary.textContent = "CRITICAL: The server executed a .txt file as PHP. This hosting is unsafe for TrustKernel deployments.";' 
        . '    setCheck("fail", "cgi.fix_pathinfo probe indicates a critical execution surface; this hosting is unsafe."); recomputeOverall();'
        . '  } else if (variantExec) {'
        . '    set("fail", "VULNERABLE");'
        . '    summary.textContent = "VULNERABLE: A PathInfo-style request caused PHP execution (cgi.fix_pathinfo-style exploit surface).";'
        . '    addHint("Fix: Set php.ini cgi.fix_pathinfo=0 and ensure webserver uses try_files / correct SCRIPT_FILENAME routing.");'
        . '    setCheck("fail", "cgi.fix_pathinfo probe indicates a PathInfo execution surface; this hosting is unsafe."); recomputeOverall();'
        . '  } else {'
        . '    set("pass", "NO EXEC");'
        . '    summary.textContent = "No PHP execution observed for the tested PathInfo variants in this probe.";' 
        . '    addHint("This does not guarantee safety; it only indicates this specific probe did not trigger execution.");'
        . '    if (cfg.policy === "less-strict") {'
        . '      if (cfg.less_strict_can_clear) {'
        . '        setCheck("pass", "cgi.fix_pathinfo is enabled, but the PathInfo probe observed NO EXEC for tested variants.");'
        . '        addHint("Note: less-strict still requires a locked on-chain probe attestation to satisfy TrustKernel.");'
        . '        const w = cfg.waiver_attestation || null;'
        . '        if (w && typeof w.key_bytes32 === "string" && typeof w.value_bytes32 === "string") {'
        . '          addHint("Waiver attestation (rootAuthority): key=" + w.key_bytes32 + " value=" + w.value_bytes32 + " (must be locked)");'
        . '        }'
        . '      }'
        . '      recomputeOverall();'
        . '    }'
        . '    if (cfg.policy === "strict") {'
        . '      addHint("Strict remains blocked when cgi.fix_pathinfo is enabled. Consider policy=less-strict if you accept probe-based gating.");'
        . '    }'
        . '  }'
        . '  if (cfg.deep) {'
        . '    for (const r of results) {'
        . '      const safe = r.res.fetched && !r.res.text.includes(cfg.expected);'
        . '      addHint((safe ? "PASS" : "CHECK") + ": " + r.url + " (HTTP " + String(r.res.status) + ")");'
        . '    }'
        . '  }'
        . '  try { await fetch(cfg.cleanup_url, { cache: "no-store", credentials: "same-origin" }); } catch (e) {}'
        . '})();'
        . '})();'
        . '</script>';
}

echo '<!doctype html>'
    . '<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />'
    . '<title>BlackCat Hosting Preflight</title>'
    . '<style>'
    . ':root{color-scheme:dark;}'
    . 'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;'
    . 'font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;'
    . 'background:radial-gradient(900px 420px at 15% 0%,rgba(86,116,255,.22),transparent 55%),'
    . 'radial-gradient(900px 420px at 85% 0%,rgba(118,227,157,.14),transparent 60%),#0b0f17;color:#e7eefc;}'
    . '.wrap{width:min(980px,100%);} '
    . '.card{background:rgba(15,21,36,.75);border:1px solid rgba(31,42,68,.95);border-radius:16px;'
    . 'box-shadow:0 24px 80px rgba(0,0,0,.35);overflow:hidden;}'
    . '.head{padding:16px 18px;border-bottom:1px solid rgba(31,42,68,.95);display:flex;align-items:center;justify-content:space-between;gap:12px;}'
    . '.title{margin:0;font-size:18px;letter-spacing:.2px;}'
    . '.sub{margin:4px 0 0;color:#9fb0d0;font-size:12px;}'
    . '.policyNav{margin-top:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}'
    . '.policyLabel{color:#9fb0d0;font-size:12px;margin-right:6px;}'
    . '.pill{display:inline-flex;align-items:center;border:1px solid rgba(31,42,68,.95);border-radius:999px;padding:4px 10px;font-weight:700;font-size:12px;color:#e7eefc;text-decoration:none;}'
    . '.pill.active{background:rgba(138,180,255,.12);border-color:rgba(138,180,255,.35);color:#8ab4ff;}'
    . '.badge{display:inline-flex;align-items:center;gap:8px;border-radius:999px;padding:6px 10px;'
    . 'border:1px solid rgba(31,42,68,.95);font-weight:700;letter-spacing:.6px;font-size:11px;}'
    . '.badge.pass{background:rgba(118,227,157,.12);border-color:rgba(118,227,157,.28);color:#76e39d;}'
    . '.badge.warn{background:rgba(255,212,107,.12);border-color:rgba(255,212,107,.28);color:#ffd46b;}'
    . '.badge.fail{background:rgba(255,123,114,.12);border-color:rgba(255,123,114,.28);color:#ff7b72;}'
    . '.body{padding:16px 18px;}'
    . '.note{background:rgba(255,123,114,.10);border:1px solid rgba(255,123,114,.25);border-radius:12px;padding:10px 12px;color:#ffb4ae;margin-bottom:12px;}'
    . '.note strong{color:#ff7b72;}'
    . '.grid{display:grid;gap:10px;}'
    . '.check{border:1px solid rgba(31,42,68,.95);border-radius:14px;background:rgba(11,15,23,.35);overflow:hidden;}'
    . '.checkHead{display:flex;gap:10px;align-items:center;padding:10px 12px;border-bottom:1px solid rgba(31,42,68,.95);} '
    . '.checkTitle{font-weight:700;}'
    . '.checkBody{padding:10px 12px;color:#9fb0d0;}'
    . '.checkDetails{color:#e7eefc;margin-bottom:8px;}'
    . '.hints{margin:0;padding-left:18px;}'
    . '.hints li{margin:4px 0;}'
    . '.footer{margin-top:14px;color:#9fb0d0;font-size:12px;}'
    . 'a{color:#8ab4ff;text-decoration:none;} a:hover{text-decoration:underline;}'
    . 'code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#ffd46b;}'
    . '</style>'
    . '</head><body>'
    . '<div class="wrap"><div class="card">'
    . '<div class="head">'
    . '<div><h1 class="title">BlackCat Hosting Preflight</h1>'
    . '<div class="sub">Single-file diagnostics for constrained hosting (FTP / no Composer). Policy: <code>' . htmlspecialchars($policy, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code>. Delete this file after use.</div>'
    . $policyNav
    . '</div>'
    . '<div class="badge ' . $overallBadgeClass . '" id="bcOverallBadge" data-overall-status="' . htmlspecialchars($overall, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">' . $overallTitle . '</div>'
    . '</div>'
    . '<div class="body">'
    . '<div class="note"><strong>Action:</strong> remove this file after you finish checking. It should not remain publicly accessible.</div>'
    . '<div class="grid">' . $checksHtml . '</div>'
    . $probePanel
    . '<div class="footer">'
    . 'Next steps: if this is <span class="badge ' . $overallBadgeClass . '">' . $overallTitle . '</span>, follow the Stage 3 docs: '
    . '<code>' . htmlspecialchars($docLink, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code>. '
    . 'For machine-readable output: add <code>?format=json</code>.'
    . '</div>'
    . '</div></div></div>'
    . '</body></html>';
