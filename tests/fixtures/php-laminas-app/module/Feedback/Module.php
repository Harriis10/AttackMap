<?php
namespace Feedback;

use Laminas\ModuleManager\Feature\ConfigProviderInterface;

/**
 * Synthetic plain-Laminas module (no Omeka S markers).
 */
class Module implements ConfigProviderInterface
{
    public function getConfig()
    {
        return include __DIR__ . '/config/module.config.php';
    }
}
