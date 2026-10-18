<?php
namespace ContactBoard\Media\Ingester;

use Laminas\Form\Element as FormElement;
use Laminas\InputFilter\InputFilter;
use Omeka\Api\Request;
use Omeka\Entity\Media;
use Omeka\File\StoreManager;
use Omeka\Stdlib\ErrorStore;

/**
 * Synthetic media ingester (application-overlay layer fixture):
 * handles uploaded files for the board module.
 */
class BoardUpload
{
    protected StoreManager $storeManager;

    public function __construct(StoreManager $storeManager)
    {
        $this->storeManager = $storeManager;
    }

    public function ingest(Media $media, Request $request, ErrorStore $errorStore): void
    {
        $files = $request->getFileData();

        if (!isset($files['file']['name']) || $files['file']['name'] === '') {
            $errorStore->addError('upload', 'No file uploaded.');
            return;
        }

        $originalName = (string) $files['file']['name'];
        $storedName = 'board_' . bin2hex(random_bytes(8));

        $this->storeManager->getStore()->put($files['file']['tmp_name'], $storedName);

        $media->setStorageId($storedName);
        $media->setSourceType('board_upload');
        $media->setOriginalFilename($originalName);
    }
}
