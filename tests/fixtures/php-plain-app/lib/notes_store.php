<?php
// Synthetic plain-PHP storage helper (no framework markers).

function save_note(string $note): void
{
    file_put_contents(__DIR__ . '/notes.jsonl', json_encode(['note' => $note]) . "\n", FILE_APPEND);
}

function list_notes(): array
{
    $path = __DIR__ . '/notes.jsonl';
    if (!is_file($path)) {
        return [];
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES);
    return array_map(fn ($row) => json_decode($row, true)['note'] ?? '', $lines);
}
