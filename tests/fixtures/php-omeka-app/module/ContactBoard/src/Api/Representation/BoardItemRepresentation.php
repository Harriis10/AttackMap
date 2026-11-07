<?php
namespace ContactBoard\Api\Representation;

use Omeka\Api\Representation\AbstractEntityRepresentation;

/**
 * Synthetic API representation (application-overlay layer fixture).
 */
class BoardItemRepresentation extends AbstractEntityRepresentation
{
    public function getJsonLdType(): string
    {
        return 'o:BoardItem';
    }

    public function getJsonLd(): array
    {
        return [
            'o:id' => $this->id(),
            'o:title' => $this->title(),
            'o:is_public' => $this->isPublic(),
            'o:created' => $this->getDateTime($this->resource->getCreated()),
        ];
    }
}
