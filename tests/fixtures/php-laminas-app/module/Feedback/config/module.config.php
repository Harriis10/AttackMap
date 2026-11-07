<?php
namespace Feedback;

return [
    'controllers' => [
        'factories' => [
            Controller\FeedbackController::class => Infrastructure\FeedbackControllerFactory::class,
        ],
    ],
    'service_manager' => [
        'factories' => [
            Service\FeedbackQueue::class => Infrastructure\FeedbackQueueFactory::class,
        ],
    ],
    'router' => [
        'routes' => [
            'feedback' => [
                'type' => \Laminas\Router\Http\Literal::class,
                'options' => [
                    'route' => '/feedback',
                    'defaults' => [
                        'controller' => 'Feedback',
                        'action' => 'index',
                    ],
                ],
                'may_terminate' => true,
                'child_routes' => [
                    'feedback-submit' => [
                        'type' => \Laminas\Router\Http\Literal::class,
                        'options' => [
                            'route' => '/submit',
                            'defaults' => [
                                'action' => 'submit',
                            ],
                        ],
                    ],
                ],
            ],
        ],
    ],
];
