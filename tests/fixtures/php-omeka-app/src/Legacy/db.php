<?php
// Synthetic shared database handle (plain-PHP layer fixture).

$dsn = 'mysql:host=127.0.0.1;dbname=contact_board;charset=utf8mb4';
$pdo = new PDO($dsn, 'board_app', 'board_app_password');

$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

return $pdo;
