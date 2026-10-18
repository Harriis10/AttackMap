<?php
namespace Feedback\Controller;

use Feedback\Form\FeedbackForm;
use Feedback\Service\FeedbackQueue;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\View\Model\ViewModel;

/**
 * Synthetic plain-Laminas controller (no Omeka S markers).
 */
class FeedbackController extends AbstractActionController
{
    protected FeedbackQueue $queue;
    protected FeedbackForm $form;

    public function __construct(FeedbackQueue $queue, FeedbackForm $form)
    {
        $this->queue = $queue;
        $this->form = $form;
    }

    public function indexAction(): ViewModel
    {
        return new ViewModel(['form' => $this->form]);
    }

    public function submitAction(): ViewModel
    {
        if ($this->getRequest()->isPost()) {
            $this->form->setData($this->params()->fromPost());
            if ($this->form->isValid()) {
                $this->queue->push($this->form->getData());
            }
        }
        return $this->redirect()->toRoute('feedback');
    }
}
