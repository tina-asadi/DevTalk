<?php
require_once __DIR__ . '/db.php';

/* -------------------------------------------------------------------------
 * Lab 8 — security headers (added before session_start() and before output).
 * The CSP was rolled out in -Report-Only first; every violation was fixed in
 * the app (the inline onsubmit="confirm()" handlers moved to assets/devtalk.js),
 * so no 'unsafe-inline' is needed, and the header now enforces.
 * ---------------------------------------------------------------------- */
header("Content-Security-Policy: default-src 'self'; "
    . "script-src 'self' https://cdn.jsdelivr.net; "
    . "style-src 'self' https://cdn.jsdelivr.net; "
    . "img-src 'self' data:; "
    . "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains'); // only honoured over HTTPS
header_remove('X-Powered-By');

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        // 'secure' => true,   // enable once served over HTTPS
    ]);
    session_start();
}

function is_logged_in(): bool
{
    return isset($_SESSION['user_id']);
}

function current_user(): ?array
{
    if (!is_logged_in()) {
        return null;
    }
    $stmt = db()->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    return $user ?: null;
}

function require_login(): void
{
    if (!is_logged_in()) {
        header('Location: login.php');
        exit;
    }
}

/**
 * Return the session's anti-CSRF token, creating one on first use.
 */
function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

/**
 * Hidden form field carrying the anti-CSRF token.
 */
function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . htmlspecialchars(csrf_token()) . '">';
}

/**
 * Abort unless the request is a POST carrying a valid anti-CSRF token.
 * Defeats cross-site request forgery and GET-based state changes.
 */
function require_post_with_csrf(): void
{
    $token = $_POST['csrf'] ?? '';
    if ($_SERVER['REQUEST_METHOD'] !== 'POST'
        || !is_string($token)
        || !hash_equals(csrf_token(), $token)) {
        http_response_code(403);
        exit('Invalid or missing CSRF token.');
    }
}

function render_header(string $title = APP_NAME): void
{
    $user = current_user();
?>
    <!doctype html>
    <html lang="en">

    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title><?= htmlspecialchars($title) ?> · <?= APP_NAME ?></title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="assets/app.css" rel="stylesheet">
    </head>

    <body class="bg-body-tertiary">
        <nav class="navbar navbar-expand-lg bg-dark" data-bs-theme="dark">
            <div class="container">
                <a class="navbar-brand fw-semibold" href="index.php">💬 <?= APP_NAME ?></a>
                <div class="d-flex align-items-center gap-2">
                    <form class="d-flex me-2" role="search" action="search.php" method="get">
                        <input class="form-control form-control-sm" type="search" name="q"
                            placeholder="Search topics…" aria-label="Search">
                    </form>
                    <?php if ($user): ?>
                        <a class="btn btn-sm btn-primary" href="create_topic.php">New Topic</a>
                        <a class="btn btn-sm btn-outline-light" href="profile.php?id=<?= $user['id'] ?>">
                            <?= htmlspecialchars($user['username']) ?>
                        </a>
                        <a class="btn btn-sm btn-outline-light" href="logout.php">Log out</a>
                    <?php else: ?>
                        <a class="btn btn-sm btn-outline-light" href="login.php">Log in</a>
                        <a class="btn btn-sm btn-primary" href="register.php">Register</a>
                    <?php endif; ?>
                </div>
            </div>
        </nav>
        <main class="container py-4">
        <?php
    }

    function render_footer(): void
    {
        ?>
        </main>
        <footer class="container text-center text-body-secondary py-4 small">
            <?= APP_NAME ?> — CST8265 lab application. For educational use only.
        </footer>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
        <script src="assets/devtalk.js"></script>
    </body>

    </html>
<?php
    }

    function fmt_date(?string $ts): string
    {
        if (!$ts) {
            return '';
        }
        return date('M j, Y g:i A', strtotime($ts));
    }
