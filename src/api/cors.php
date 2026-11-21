<?php
/**
 * DevTalk API extension — Cross-Origin Resource Sharing (CORS) policy.
 *
 * Called once, at the top of public/api/index.php, before any route runs.
 *
 * DevTalk's own pages (including messages.php) are the SAME origin as the API,
 * so they need no CORS at all. The only cross-origin front end that may read
 * API responses is the planned product UI at http://localhost:5173.
 *
 * LAB 8, PART A (Patch #A1): the reflected-origin policy was replaced with an
 * explicit allowlist and an exact string comparison.
 */

function api_cors(): void
{
    // Exact allowlist. Add future trusted front ends here, never reflect input.
    $allowed_origins = [
        'http://localhost:5173',
    ];

    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    // A shared cache must never hand one origin's CORS headers to another.
    header('Vary: Origin');

    // Exact string match only — no str_contains / str_ends_with / regex, and
    // the literal "null" origin is never on the list, so it is never allowed.
    $is_allowed = $origin !== '' && in_array($origin, $allowed_origins, true);

    if ($is_allowed) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Credentials: true');
    }

    // Answer CORS preflight requests. Only an allowed origin is told which
    // methods and headers it may use; any other origin gets no CORS headers.
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        if ($is_allowed) {
            header('Access-Control-Allow-Methods: GET, POST, PATCH, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization');
            header('Access-Control-Max-Age: 600');
        }
        http_response_code(204);
        exit;
    }
}
