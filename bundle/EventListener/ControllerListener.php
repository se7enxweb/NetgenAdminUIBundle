<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Controller\ControllerResolverInterface;
use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Exception\ResourceNotFoundException;

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
            KernelEvents::REQUEST => ['onKernelRequest', 1],
            KernelEvents::CONTROLLER => ['onKernelController', 255],
        ];
    }

    /**
     * Intercept REQUEST phase - log all requests to verify listener is running.
     */
    public function onKernelRequest(GetResponseEvent $event): void
    {
        if ($event->getRequestType() !== HttpKernelInterface::MASTER_REQUEST) {
            return;
        }

        $request = $event->getRequest();
        $route = $request->attributes->get('_route');
        $pathInfo = $request->getPathInfo();
    }

    /**
     * Handle ez_urlalias routes - override controller to use content view rendering.
     */
    public function onKernelController(FilterControllerEvent $event): void
    {
        if ($event->getRequestType() !== HttpKernelInterface::MASTER_REQUEST) {
            return;
        }

        if (!$this->isAdminSiteAccess) {
            return;
        }

        $request = $event->getRequest();
        $currentRoute = $request->attributes->get('_route');

        // Intercept ez_urlalias route and use content view controller instead of legacy
        if ($currentRoute === 'ez_urlalias') {
            // Override the legacy controller with modern content view
            // The ez_content:viewAction will use configured content_view to render
            $request->attributes->set('_controller', 'ez_content:viewAction');
            $request->attributes->set('viewType', 'full');
            $event->setController($this->controllerResolver->getController($request));
            return;
        }
    }
}
