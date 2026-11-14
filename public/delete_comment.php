<?php
require_once __DIR__ . '/../src/helpers.php';
require_login();
require_post_with_csrf();

$id      = $_POST['id'] ?? '';
$topicId = $_POST['topic_id'] ?? '';

// Confirm ownership: the comment author, the topic owner, or an admin.
$stmt = db()->prepare(
    'SELECT c.user_id AS comment_owner, t.user_id AS topic_owner
     FROM comments c JOIN topics t ON t.id = c.topic_id
     WHERE c.id = ?'
);
$stmt->execute([$id]);
$row = $stmt->fetch();

$me = current_user();
$allowed = $row && (
    (int) $row['comment_owner'] === (int) $me['id'] ||
    (int) $row['topic_owner']   === (int) $me['id'] ||
    $me['is_admin']
);

if (!$allowed) {
    http_response_code(403);
    render_header('Forbidden');
    echo '<div class="alert alert-danger">You are not allowed to delete this comment.</div>';
    render_footer();
    exit;
}

$del = db()->prepare('DELETE FROM comments WHERE id = ?');
$del->execute([$id]);

header('Location: topic.php?id=' . (int) $topicId);
exit;
