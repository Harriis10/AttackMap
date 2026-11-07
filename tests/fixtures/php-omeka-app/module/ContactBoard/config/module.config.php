<?php
namespace ContactBoard;

return [
    'controllers' => [
        'factories' => [
            Controller\BoardAdminController::class => Infrastructure\BoardAdminControllerFactory::class,
            Controller\BoardSiteController::class => Infrastructure\BoardSiteControllerFactory::class,
        ],
    ],
    'service_manager' => [
        'factories' => [
            Service\BoardMailer::class => Infrastructure\BoardMailerFactory::class,
            Infrastructure\BoardRateLimiter::class => InvokableFactory::class,
        ],
        'invokables' => [
            Service\BoardSlugger::class => Service\BoardSlugger::class,
        ],
    ],
    'api_adapters' => [
        'invokables' => [
            'board_items' => Api\Adapter\BoardItemAdapter::class,
        ],
    ],
    'media_ingesters' => [
        'factories' => [
            'board_upload' => Media\Ingester\BoardUpload::class,
        ],
    ],
    'media_renderers' => [
        'invokables' => [
            'board_upload' => Media\Renderer\BoardUploadRenderer::class,
        ],
    ],
    'router' => [
        'routes' => [
            'admin-board' => [
                'type' => \Laminas\Router\Http\Literal::class,
                'options' => [
                    'route' => '/admin/contact-board',
                    'defaults' => [
                        '__NAMESPACE__' => 'Controller',
                        'controller' => 'BoardAdmin',
                        'action' => 'index',
                    ],
                ],
                'may_terminate' => true,
                'child_routes' => [
                    'admin-board-item' => [
                        'type' => \Laminas\Router\Http\Segment::class,
                        'options' => [
                            'route' => '/item/:id',
                            'defaults' => [
                                'action' => 'item',
                            ],
                            'constraints' => [
                                'id' => '\d+',
                            ],
                        ],
                    ],
                ],
            ],
            'site-board' => [
                'type' => \Laminas\Router\Http\Segment::class,
                'options' => [
                    'route' => '/s/:site-slug/board',
                    'defaults' => [
                        '__NAMESPACE__' => 'Controller',
                        'controller' => 'BoardSite',
                        'action' => 'show',
                    ],
                ],
            ],
            'site-board-submit' => [
                'type' => \Laminas\Router\Http\Literal::class,
                'options' => [
                    'route' => '/s/:site-slug/board/submit',
                    'defaults' => [
                        'controller' => 'BoardSite',
                        'action' => 'submit',
                    ],
                ],
            ],
        ],
    ],
    'view_manager' => [
        'template_path_stack' => [
            __DIR__ . '/../view',
        ],
    ],
    'board' => [
        'upload_dir' => OMEKA_PATH . '/files/board_uploads',
        'max_upload_bytes' => 5242880,
    ],
];
