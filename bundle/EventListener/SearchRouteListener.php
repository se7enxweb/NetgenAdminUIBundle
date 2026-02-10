<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use eZ\Publish\Core\MVC\Symfony\Event\PostSiteAccessMatchEvent;
use eZ\Publish\Core\MVC\Symfony\MVCEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;

/**
 * Listener that routes /content/search to legacy controller for admin siteaccesses
 * but allows it to pass through to ngsite for user siteaccesses.
 */
class SearchRouteListener implements EventSubscriberInterface
{
    private RouterInterface $router;
    private array $siteaccessGroups;

    public function __construct(RouterInterface $router, array $siteaccessGroups = [])
    {
        $this->router = $router;
        $this->siteaccessGroups = $siteaccessGroups;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            MVCEvents::SITEACCESS => ['onSiteAccessMatch', 200],
        ];
    }

    public function onSiteAccessMatch(PostSiteAccessMatchEvent $event): void
    {
        $siteaccess = $event->getSiteAccess();
        $request = $event->getRequest();

        // Check if this is a search route request for an admin siteaccess
        if ($this->isSearchRoute($request) && $this->isAdminSiteaccess($siteaccess->name)) {
            // Mark request so we can route to legacy controller
            $request->attributes->set('_use_legacy_search', true);
        }
    }

    private function isSearchRoute(Request $request): bool
    {
        $pathInfo = $request->getPathInfo();
        return strpos($pathInfo, '/content/search') === 0;
    }

    private function isAdminSiteaccess(string $siteaccessName): bool
    {
        // Check if siteaccess is in any admin group (admin_group, ngadmin_group, legacy_group)
        foreach ($this->siteaccessGroups as $groupName => $groupSiteaccesses) {
            if (in_array($groupName, ['admin_group', 'ngadmin_group', 'legacy_group'], true)) {
                if (in_array($siteaccessName, $groupSiteaccesses, true)) {
                    return true;
                }
            }
        }
        return false;
    }
}

