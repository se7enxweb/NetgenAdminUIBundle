<?php

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Controller\ControllerResolverInterface;
use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Consolidated navigation interceptor for admin UI
 *
 * Handles:
 * - Shortcut path resolution (from AdminUIShortcutsListener)
 *   - /Media, /Design, /Users → content view pages
 *   - Both with and without trailing slashes
 *
 * - Controller resolution for legacy routes (from ControllerListener)
 *   - Redirects legacy route patterns to eZ legacy system
 *   - Validates controller resolution for admin siteaccess
 */
class NavigationInterceptor implements EventSubscriberInterface
{
    /**
     * @var \Symfony\Component\HttpKernel\Controller\ControllerResolverInterface
     */
    protected $controllerResolver;

    /**
     * @var bool
     */
    protected $isAdminSiteAccess;

    /**
     * @var array
     */
    protected $legacyRoutes;

    /**
     * Constructor.
     *
     * @param \Symfony\Component\HttpKernel\Controller\ControllerResolverInterface $controllerResolver
     * @param bool $isAdminSiteAccess
     * @param array $legacyRoutes
     */
    public function __construct(
        ControllerResolverInterface $controllerResolver,
        $isAdminSiteAccess = false,
        $legacyRoutes = array()
    ) {
        $this->controllerResolver = $controllerResolver;
        $this->isAdminSiteAccess = $isAdminSiteAccess;
        $this->legacyRoutes = $legacyRoutes;
    }

    /**
     * Returns subscribed events.
     *
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return array(
            // Shortcut resolution - very early REQUEST (priority 256, before routing at 32)
            KernelEvents::REQUEST => [
                ['onShortcutResolution', 256], // Resolve shortcuts like /Media, /Design, /Users
            ],
            
            // Controller resolution for legacy routes - runs after routing (priority 255)
            KernelEvents::CONTROLLER => [
                ['onLegacyControllerResolution', 255],
            ],
        );
    }

    /**
     * Resolves admin UI shortcut paths to content view pages
     * (from AdminUIShortcutsListener)
     *
     * Provides convenient shortcuts to commonly accessed content locations:
     * - /Media and /media → Node 43 (Media folder)
     * - /Design and /design → Node 58 (Design root)
     * - /Users and /users → Node 5 (Users)
     *
     * Handles both trailing and non-trailing slash variants
     *
     * @param \Symfony\Component\HttpKernel\Event\GetResponseEvent $event
     */
    public function onShortcutResolution(GetResponseEvent $event)
    {
        // Don't process subrequests
        if (!$event->isMasterRequest()) {
            return;
        }

        $request = $event->getRequest();
        $pathInfo = $request->getPathInfo();

        // Define shortcuts for admin UI (with both trailing and non-trailing versions)
        // Node IDs: 5 = Users, 43 = Media folder, 58 = Design root
        $shortcuts = [
            '/Media' => '/content/view/full/43',
            '/Media/' => '/content/view/full/43',
            '/media' => '/Media',
            '/media/' => '/Media/',
            '/Design' => '/content/view/full/58',
            '/Design/' => '/content/view/full/58',
            '/design' => '/Design',
            '/design/' => '/Design/',
            '/Users' => '/content/view/full/5',
            '/Users/' => '/content/view/full/5',
            '/users' => '/Users',
            '/users/' => '/Users/',
        ];

        if (!isset($shortcuts[$pathInfo])) {
            return;
        }

        $targetPath = $shortcuts[$pathInfo];

        // Create redirect response
        $response = new RedirectResponse($targetPath, 302);
        $event->setResponse($response);
    }

    /**
     * Resolves legacy route patterns and redirects them to eZ legacy system
     * (from ControllerListener)
     *
     * Runs at CONTROLLER event (after routing, priority 255).
     * Checks if current route or path matches configured legacy patterns.
     * If so, routes to eZ legacy system controller.
     *
     * @param \Symfony\Component\HttpKernel\Event\FilterControllerEvent $event
     */
    public function onLegacyControllerResolution(FilterControllerEvent $event)
    {
        if ($event->getRequestType() !== HttpKernelInterface::MASTER_REQUEST) {
            return;
        }

        if (!$this->isAdminSiteAccess) {
            return;
        }

        $request = $event->getRequest();
        $currentRoute = $request->attributes->get('_route');
        $pathInfo = $request->getPathInfo();

        // First, check if this is a legacy route by route name (e.g., ez_urlalias)
        foreach ($this->legacyRoutes as $legacyRoute) {
            if (stripos($currentRoute, $legacyRoute) === 0) {
                $request->attributes->set('_controller', 'ezpublish_legacy.controller:indexAction');
                $event->setController($this->controllerResolver->getController($request));
                return;
            }
        }

        // Also check if path starts with any of the configured legacy path prefixes
        // These patterns match path-based routes like /visual/*, /setup/*, etc.
        foreach ($this->legacyRoutes as $legacyRoute) {
            // If pattern starts with '/', it's a path prefix pattern
            if (strpos($legacyRoute, '/') === 0) {
                if (stripos($pathInfo, $legacyRoute) === 0) {
                    // Set the module_uri - remove leading slash and pass to legacy
                    $moduleUri = substr($pathInfo, 1); // Remove leading /
                    $request->attributes->set('module_uri', $moduleUri);
                    $request->attributes->set('_controller', 'ezpublish_legacy.controller:indexAction');
                    $event->setController($this->controllerResolver->getController($request));
                    return;
                }
            }
        }
    }
}
