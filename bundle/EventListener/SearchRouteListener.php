<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use eZ\Publish\Core\MVC\Symfony\Event\PostSiteAccessMatchEvent;
use eZ\Publish\Core\MVC\Symfony\MVCEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Netgen\Bundle\AdminUIBundle\Service\AdminUIConfiguration;

/**
 * Listener that routes /content/search to legacy controller for admin siteaccesses
 * but allows it to pass through to ngsite for user siteaccesses.
 */
class SearchRouteListener implements EventSubscriberInterface
{
    private RouterInterface $router;
    private array $siteaccessGroups;
    private ?AdminUIConfiguration $adminUIConfig;

    public function __construct(RouterInterface $router, array $siteaccessGroups = [], AdminUIConfiguration $adminUIConfig = null)
    {
        $this->router = $router;
        $this->siteaccessGroups = $siteaccessGroups;
        $this->adminUIConfig = $adminUIConfig;
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
        $searchPath = $this->adminUIConfig ? $this->adminUIConfig->getSearchRoutePath() : '/content/search';
        return strpos($pathInfo, $searchPath) === 0;
    }

    private function isAdminSiteaccess(string $siteaccessName): bool
    {
        // Check if siteaccess is in any admin group using configuration service
        foreach ($this->siteaccessGroups as $groupName => $groupSiteaccesses) {
            // Use configuration service to check admin groups (never hardcoded)
            if ($this->adminUIConfig && $this->adminUIConfig->isAdminGroupName($groupName)) {
                if (in_array($siteaccessName, $groupSiteaccesses, true)) {
                    return true;
                }
            }
        }
        return false;
    }
}

