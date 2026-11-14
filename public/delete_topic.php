<?php
require_once __DIR__ . '/../src/helpers.php';
require_login();
require_post_with_csrf();

$id = $_POST['id'] ?? '';

// Load the topic and confirm the current user owns it (admins may delete any).
$stmt = db()->prepare('SELECT user_id FROM topics WHERE id = ?');
$stmt->execute([$id]);
$topic = $stmt->fetch();

$me = current_user();
if (!$topic || ((int) $topic['user_id'] !== (int) $me['id'] && !$me['is_admin'])) {
    http_response_code(403);
    render_header('Forbidden');
    echo '<div class="alert alert-danger">You are not allowed to delete this topic.</div>';
    render_footer();
    exit;
}

$del = db()->prepare('DELETE FROM topics WHERE id = ?');
$del->execute([$id]);

header('Location: index.php');
exit;
