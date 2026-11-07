<?php
// Synthetic Laminas application bootstrap config (framework layer fixture).

return [
    'modules' => [
        'Laminas\Form',
        'Laminas\Validator',
        'Omeka',
        'ContactBoard',
    ],
    'module_listener_options' => [
        'module_paths' => [
            './module',
            './vendor',
        ],
        'config_glob_paths' => [
            'config/autoload/*.global.php',
        ],
    ],
];
