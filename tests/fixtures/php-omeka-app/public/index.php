<?php
// Synthetic front-controller entry point (plain-PHP layer fixture).

require_once __DIR__ . '/../config/application.config.php';

session_start();

if (isset($_GET['lang'])) {
    // Observed: request input concatenated into a response redirect target.
    header('Location: /switch/lang?next=' . $_GET['lang']);
    exit;
}

if (!isset($_SESSION['visitor_id'])) {
    session_regenerate_id(true);
    $_SESSION['visitor_id'] = bin2hex(random_bytes(16));
}

setcookie('board_theme', 'dark', ['expires' => time() + 3600, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);

$app = new Laminas\Mvc\Application(
    include __DIR__ . '/../config/application.config.php',
    Laminas\Stdlib\ArrayUtils::merge(
        include __DIR__ . '/../config/modules.config.php',
        []
    )
);
$app->run();
