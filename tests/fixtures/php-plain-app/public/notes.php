<?php
// Synthetic plain-PHP page (no framework markers).

require_once __DIR__ . '/../lib/notes_store.php';

session_start();

$note = $_POST['note'] ?? '';

if ($note !== '') {
    save_note($note);
}

echo '<ul>';
foreach (list_notes() as $line) {
    echo '<li>', htmlspecialchars($line, ENT_QUOTES, 'UTF-8'), '</li>';
}
echo '</ul>';
