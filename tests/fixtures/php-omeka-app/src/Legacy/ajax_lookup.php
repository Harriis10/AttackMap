<?php
// Synthetic legacy AJAX endpoint (plain-PHP layer fixture).

require_once __DIR__ . '/db.php';

$q = isset($_GET['q']) ? $_GET['q'] : '';

if ($q === '') {
    http_response_code(400);
    exit('missing q');
}

// Observed: request input concatenated into a PDO query call.
$stmt = $pdo->query('SELECT id, title FROM board_items WHERE title LIKE ' . $pdo->quote('%' . $q . '%'));

if (isset($_POST['format']) && $_POST['format'] === 'raw') {
    // Observed: request input concatenated into a shell command.
    echo shell_exec('board-search --format raw ' . $_POST['format']);
}

foreach ($stmt as $row) {
    echo htmlspecialchars($row['title'], ENT_QUOTES, 'UTF-8'), "\n";
}
