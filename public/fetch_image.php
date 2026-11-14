<?php
require_once __DIR__ . '/../src/config.php';

$url = $_GET['url'] ?? '';

if ($url === '') {
    http_response_code(400);
    exit('No url provided.');
}

/**
 * Only fetch remote http/https images, and never an address that points
 * back at the server or the internal network. This stops the endpoint from
 * being used to read local files (file://) or reach internal services.
 */
function image_url_is_allowed(string $url): bool
{
    $parts = parse_url($url);
    if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
        return false;
    }
    if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
        return false; // blocks file://, gopher://, ftp://, php://, etc.
    }

    // Resolve the host and reject private, loopback, link-local or reserved IPs.
    $ips = gethostbynamel($parts['host']);
    if ($ips === false) {
        // Host may already be a literal IP.
        $ips = filter_var($parts['host'], FILTER_VALIDATE_IP) ? [$parts['host']] : [];
    }
    if (!$ips) {
        return false;
    }
    foreach ($ips as $ip) {
        if (!filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        )) {
            return false;
        }
    }
    return true;
}

if (!image_url_is_allowed($url)) {
    http_response_code(400);
    exit('That image address is not allowed.');
}

// Fetch without following redirects, so a 302 cannot bounce us to a blocked
// target after the check has passed.
$context = stream_context_create([
    'http' => ['timeout' => 5, 'follow_location' => 0, 'max_redirects' => 0],
]);
$data = @file_get_contents($url, false, $context);

if ($data === false) {
    http_response_code(502);
    exit('Could not fetch the image.');
}

// Only ever serve something that really is an image.
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->buffer($data) ?: 'application/octet-stream';
if (!str_starts_with($mime, 'image/')) {
    http_response_code(415);
    exit('The fetched content is not an image.');
}

header('Content-Type: ' . $mime);
echo $data;
