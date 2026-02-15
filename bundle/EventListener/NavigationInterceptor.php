<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Controller\ControllerResolverInterface;
use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Netgen\Bundle\AdminUIBundle\Service\AdminUIConfiguration;

/**
 * Consolidated navigation interceptor for admin UI
 *
 * Handles:
 * - Shortcut path resolution: /Media /Design /Users → content view pages
 * - Legacy route controller resolution: redirects legacy patterns to eZ legacy
 *
 * Configuration-driven, uses AdminUIConfiguration service
 */
class NavigationInterceptor implements EventSubscriberInterface
{
    private ControllerResolverInterface $controllerResolver;
    private bool $isAdminSiteAccess;
    private array $legacyRoutes;
    private ?LoggerInterface $logger;
    private ?AdminUIConfiguration $adminUIConfig;
    private bool $requestDebugLog = false;

    public function __construct(
        ControllerResolverInterface $controllerResolver,
        bool $isAdminSiteAccess = false,
        array $legacyRoutes = [],
        ?AdminUIConfiguration $adminUIConfig = null,
        ?LoggerInterface $logger = null
    ) {
        $this->controllerResolver = $controllerResolver;
        $this->isAdminSiteAccess = $isAdminSiteAccess;
        $this->legacyRoutes = $legacyRoutes;
        $this->adminUIConfig = $adminUIConfig;
        $this->logger = $logger;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => [
                ['onShortcutResolution', 256],
            ],
            KernelEvents::CONTROLLER => [
                ['onLegacyControllerResolution', 255],
            ],
        ];
    }

    /**
     * Resolves admin UI shortcut paths to content view pages
     * Provides convenient shortcuts to configured content locations
     */
    public function onShortcutResolution(GetResponseEvent $event): void
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        // Configuration service is optional for backward compatibility
        if (!$this->adminUIConfig) {
            return;
        }

        $request = $event->getRequest();
        $pathInfo = $request->getPathInfo();
        $configuredShortcuts = $this->adminUIConfig->getShortcuts();

        // Define all shortcuts including variants (trailing/non-trailing slashes)
        $shortcuts = [
            '/Media' => $configuredShortcuts['/Media'],
            '/Media/' => $configuredShortcuts['/Media'],
            '/media' => '/Media',
            '/media/' => '/Media/',
            '/Design' => $configuredShortcuts['/Design'],
            '/Design/' => $configuredShortcuts['/Design'],
            '/design' => '/Design',
            '/design/' => '/Design/',
            '/Users' => $configuredShortcuts['/Users'],
            '/Users/' => $configuredShortcuts['/Users'],
            '/users' => '/Users',
            '/users/' => '/Users/',
        ];

        if (!isset($shortcuts[$pathInfo])) {
            return;
        }

        $targetPath = $shortcuts[$pathInfo];
        $response = new RedirectResponse($targetPath, 302);
        $event->setResponse($response);
    }

    /**
     * Resolves legacy route patterns and redirects to eZ legacy system.
     * Runs at CONTROLLER event (after routing, priority 255)
     */
    public function onLegacyControllerResolution(FilterControllerEvent $event): void
    {
        if ($event->getRequestType() !== HttpKernelInterface::MASTER_REQUEST) {
            return;
        }

        $request = $event->getRequest();
        $currentRoute = $request->attributes->get('_route');
        $pathInfo = $request->getPathInfo();
        
        // Skip "/" - let admin UI handle it
        if ($pathInfo === '/' || $pathInfo === '/content/dashboard') {
            return;
        }

        // Check if this is an admin siteaccess
        if (!$this->isAdminSiteAccess) {
            return;
        }

        // Check if this is a legacy route by route name pattern
        if (is_string($currentRoute)) {
            foreach ($this->legacyRoutes as $legacyRoute) {
                if (stripos($currentRoute, $legacyRoute) === 0) {
                    $request->attributes->set('_controller', 'ezpublish_legacy.controller:indexAction');
                    $event->setController($this->controllerResolver->getController($request));
                    return;
                }
            }
        }

        // Also check if path starts with configured legacy path prefixes
        foreach ($this->legacyRoutes as $legacyRoute) {
            // Pattern starting with '/' is a path prefix pattern
            if (strpos($legacyRoute, '/') === 0 && stripos($pathInfo, $legacyRoute) === 0) {
                $moduleUri = substr($pathInfo, 1); // Remove leading /
                $request->attributes->set('module_uri', $moduleUri);
                $request->attributes->set('_controller', 'ezpublish_legacy.controller:indexAction');
                $event->setController($this->controllerResolver->getController($request));
                return;
            }
        }
    }
}
