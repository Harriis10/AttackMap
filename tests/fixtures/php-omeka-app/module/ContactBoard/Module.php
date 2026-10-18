<?php
namespace ContactBoard;

use Omeka\Module\AbstractModule;
use Laminas\EventManager\SharedEventManagerInterface;

/**
 * Synthetic Omeka S module (application-overlay layer fixture).
 */
class Module extends AbstractModule
{
    const VERSION = '1.2.3';

    public function getConfig()
    {
        return include __DIR__ . '/config/module.config.php';
    }

    public function attachListeners(SharedEventManagerInterface $sharedEventManager): void
    {
        $sharedEventManager->attach(
            'Omeka\Controller\Site\Index',
            'view.browse.after',
            [$this, 'renderBoardFooter']
        );
    }

    public function renderBoardFooter($event): void
    {
        // Intentionally minimal; view logic lives in the view scripts.
    }
}
