<?php
namespace ContactBoard\Infrastructure;

use ContactBoard\Service\BoardMailer;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

/**
 * Synthetic laminas service-manager factory (framework layer fixture).
 */
class BoardMailerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, ?array $options = null): BoardMailer
    {
        $config = $container->get('Config');
        $webhookUrl = $config['board']['moderation_webhook'] ?? 'https://moderation.example.invalid/hook';

        return new BoardMailer($webhookUrl);
    }
}
