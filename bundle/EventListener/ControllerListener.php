<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Controller\ControllerResolverInterface;
use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

class ControllerListener implements EventSubscriberInterface
{
    private ControllerResolverInterface $controllerResolver;
    private bool $isAdminSiteAccess;
    private array $legacyRoutes;

    public function __construct(
        ControllerResolverInterface $controllerResolver,
        bool $isAdminSiteAccess = false,
        array $legacyRoutes = []
    ) {
        $this->controllerResolver = $controllerResolver;
        $this->isAdminSiteAccess = $isAdminSiteAccess;
        $this->legacyRoutes = $legacyRoutes;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::CONTROLLER => ['onKernelController', 255],
        ];
    }

    /**
     * Redirects configured routes to eZ legacy.
     */
    public function onKernelController(FilterControllerEvent $event): void
    {
        if ($event->getRequestType() !== HttpKernelInterface::MASTER_REQUEST) {
            return;
        }

        if (!$this->isAdminSiteAccess) {
            return;
        }

        $currentRoute = $event->getRequest()->attributes->get('_route');
        foreach ($this->legacyRoutes as $legacyRoute) {
            if (is_string($currentRoute) && stripos($currentRoute, $legacyRoute) === 0) {
                $event->getRequest()->attributes->set('_controller', 'ezpublish_legacy.controller:indexAction');
                $event->setController($this->controllerResolver->getController($event->getRequest()));
                return;
            }
        }
    }
}
