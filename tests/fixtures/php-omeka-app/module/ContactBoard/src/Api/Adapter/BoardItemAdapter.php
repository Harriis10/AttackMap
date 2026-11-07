<?php
namespace ContactBoard\Api\Adapter;

use Omeka\Api\Adapter\AbstractEntityAdapter;
use Omeka\Api\Representation\BoardItemRepresentation;
use Omeka\Stdlib\ErrorStore;

/**
 * Synthetic API adapter (application-overlay layer fixture).
 * Adapters back Omeka S REST-ish API resources (observed marker:
 * Omeka\Api\Adapter\AbstractEntityAdapter).
 */
class BoardItemAdapter extends AbstractEntityAdapter
{
    public function getResourceName(): string
    {
        return 'board_items';
    }

    public function getRepresentationClass(): string
    {
        return BoardItemRepresentation::class;
    }

    public function hydrate(array $data, $entity, ErrorStore $errorStore): void
    {
        if (isset($data['o:title'])) {
            $entity->setTitle($data['o:title']);
        }
        if (isset($data['o:is_public'])) {
            $entity->setIsPublic((bool) $data['o:is_public']);
        }
    }
}
