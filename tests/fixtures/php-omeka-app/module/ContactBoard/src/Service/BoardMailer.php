<?php
namespace ContactBoard\Service;

use ContactBoard\Api\Representation\BoardItemRepresentation;

/**
 * Synthetic outbound notifier (framework + application layer fixture):
 * laminas service wiring plus an outbound HTTP call to a moderation webhook.
 */
class BoardMailer
{
    protected string $webhookUrl;

    public function __construct(string $webhookUrl)
    {
        $this->webhookUrl = $webhookUrl;
    }

    public function notifyModerators(BoardItemRepresentation $item): bool
    {
        $payload = json_encode(['title' => $item->title()], JSON_THROW_ON_ERROR);

        $ch = curl_init($this->webhookUrl);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return $status >= 200 && $status < 300;
    }
}
