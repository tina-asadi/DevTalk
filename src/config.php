<?php
// Do not leak PHP errors, stack traces or SQL to the browser. Log them
// server-side instead, where only the operator can read them.
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');

define('DB_PATH', __DIR__ . '/../database/forum.sqlite');
define('UPLOAD_DIR', __DIR__ . '/../public/uploads');
define('APP_NAME', 'DevTalk Forum');
