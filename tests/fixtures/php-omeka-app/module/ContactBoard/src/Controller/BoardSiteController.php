<?php
namespace ContactBoard\Controller;

use ContactBoard\Form\BoardForm;
use ContactBoard\Service\BoardMailer;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\View\Model\ViewModel;
use Omeka\Api\Manager as ApiManager;

/**
 * Synthetic public site controller (application-overlay layer fixture).
 * Site routes in Omeka S are public: no identity() guard here, which is
 * exactly the trust-boundary contrast the overlay should surface.
 */
class BoardSiteController extends AbstractActionController
{
    protected ApiManager $api;
    protected BoardForm $form;
    protected BoardMailer $mailer;

    public function __construct(ApiManager $api, BoardForm $form, BoardMailer $mailer)
    {
        $this->api = $api;
        $this->form = $form;
        $this->mailer = $mailer;
    }

    public function showAction(): ViewModel
    {
        $page = (int) $this->params()->fromQuery('page', 1);

        $items = $this->api->search('board_items', ['page' => $page])->getContent();

        return new ViewModel(['items' => $items]);
    }

    public function submitAction(): ViewModel
    {
        $form = $this->form;

        if ($this->getRequest()->isPost()) {
            $data = $this->params()->fromPost();
            $form->setData($data);
            if ($form->isValid()) {
                $clean = $form->getData();
                $this->api->create('board_items', $clean);
                $this->mailer->notifyModerators($clean);
            }
        }

        return new ViewModel(['form' => $form]);
    }
}
