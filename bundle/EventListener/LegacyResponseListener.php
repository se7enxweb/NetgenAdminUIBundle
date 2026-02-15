<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use eZ\Bundle\EzPublishLegacyBundle\LegacyResponse;
use eZ\Bundle\EzPublishLegacyBundle\Routing\FallbackRouter;
use Netgen\Bundle\AdminUIBundle\Exception\NotFoundHttpException;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class LegacyResponseListener implements EventSubscriberInterface
{
    private bool $legacyMode;

    public function __construct(bool $legacyMode = false)
    {
        $this->legacyMode = $legacyMode;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }

    /**
     * Converts legacy 404 response to proper Symfony exception.
     *
     * @throws \Symfony\Component\HttpKernel\Exception\NotFoundHttpException
     */
    public function onKernelResponse(FilterResponseEvent $event): void
    {
        $routeName = $event->getRequest()->attributes->get('_route');
        if ($routeName !== FallbackRouter::ROUTE_NAME) {
            return;
        }

        $response = $event->getResponse();
        if (!$response instanceof LegacyResponse) {
            return;
        }

        if (!$this->legacyMode && (int)$response->getStatusCode() === Response::HTTP_NOT_FOUND) {
            $moduleResult = $response->getModuleResult();
            $exception = new NotFoundHttpException(
                isset($moduleResult['errorMessage']) ? $moduleResult['errorMessage'] : 'Not Found'
            );

            $exception->setOriginalResponse($response);
            throw $exception;
        }
    }
}