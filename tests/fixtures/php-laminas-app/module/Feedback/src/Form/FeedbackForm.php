<?php
namespace Feedback\Form;

use Laminas\Filter\StringTrim;
use Laminas\Form\Form;
use Laminas\InputFilter\InputFilter;
use Laminas\Validator\StringLength;

/**
 * Synthetic plain-Laminas form with input validation (no Omeka S markers).
 */
class FeedbackForm extends Form
{
    public function init(): void
    {
        $this->add([
            'name' => 'message',
            'type' => 'Textarea',
        ]);
    }

    public function getInputFilter(): InputFilter
    {
        $inputFilter = new InputFilter();
        $inputFilter->add([
            'name' => 'message',
            'required' => true,
            'filters' => [
                ['name' => StringTrim::class],
            ],
            'validators' => [
                ['name' => StringLength::class, 'options' => ['min' => 1, 'max' => 500]],
            ],
        ]);
        return $inputFilter;
    }
}
