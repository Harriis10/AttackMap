<?php
namespace ContactBoard\Form;

use Laminas\Filter\StringTrim;
use Laminas\Filter\StripTags;
use Laminas\Form\Form;
use Laminas\InputFilter\InputFilter;
use Laminas\Validator\Regex;
use Laminas\Validator\StringLength;

/**
 * Synthetic input form (framework layer fixture): validators and filters
 * applied to public submission input are the positive control the
 * framework layer should surface.
 */
class BoardForm extends Form
{
    public function __construct(?string $name = null)
    {
        parent::__construct('board_form');
    }

    public function init(): void
    {
        $this->add([
            'name' => 'o:title',
            'type' => 'Text',
            'options' => ['label' => 'Item title'],
        ]);

        $this->add([
            'name' => 'o:site_note',
            'type' => 'Textarea',
            'options' => ['label' => 'Public note'],
        ]);
    }

    public function getInputFilter(): InputFilter
    {
        $inputFilter = new InputFilter();

        $title = $inputFilter->get('o:title') ?? null;
        $inputFilter->add([
            'name' => 'o:title',
            'required' => true,
            'filters' => [
                ['name' => StringTrim::class],
                ['name' => StripTags::class],
            ],
            'validators' => [
                ['name' => StringLength::class, 'options' => ['min' => 3, 'max' => 200]],
            ],
        ]);

        $inputFilter->add([
            'name' => 'o:site_note',
            'required' => false,
            'filters' => [
                ['name' => StripTags::class],
            ],
            'validators' => [
                ['name' => Regex::class, 'options' => ['pattern' => '/^[\p{L}\p{N} .,!-]+$/u']],
            ],
        ]);

        return $inputFilter;
    }
}
