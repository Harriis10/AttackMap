<?php
namespace ContactBoard\Controller;

use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\View\Model\ViewModel;
use Omeka\Api\Manager as ApiManager;

/**
 * Synthetic admin controller (application-overlay layer fixture).
 * Mirrors real Omeka S module controllers: identity() guard plus the
 * api() manager for persistence.
 */
class BoardAdminController extends AbstractActionController
{
    protected ApiManager $api;

    public function __construct(ApiManager $api)
    {
        $this->api = $api;
    }

    public function indexAction(): ViewModel
    {
        // Observed positive control: authenticated identity required.
        $identity = $this->identity();
        if ($identity === null) {
            return $this->redirect()->toRoute('admin-board');
        }

        $items = $this->api->search('board_items', ['sort_by' => 'created'])->getContent();

        return new ViewModel(['items' => $items, 'identity' => $identity]);
    }

    public function itemAction(): ViewModel
    {
        $identity = $this->identity();
        if ($identity === null) {
            return $this->redirect()->toRoute('admin-board');
        }

        // Observed: route parameter flows into an API read.
        $id = $this->params()->fromRoute('id');
        $item = $this->api->read('board_items', $id)->getContent();

        return new ViewModel(['item' => $item]);
    }
}
