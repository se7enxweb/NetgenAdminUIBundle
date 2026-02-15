<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Sets admin page layout configuration for various admin UI plugins
 *
 * Consolidated from SetInformationCollectionAdminPageLayoutListener and SetTagsAdminPageLayoutListener
 * Handles layout configuration for information collection and tags plugins
 * Configuration-driven and reusable for other admin plugins
 */
class AdminPageLayoutListener implements EventSubscriberInterface
{
    private object $globalVariable;
    private string $pageLayoutTemplate;
    private bool $isAdminSiteAccess = false;
    private string $routePrefix;

    public function __construct(
        object $globalVariable,
        string $pageLayoutTemplate,
        string $routePrefix
    ) {
        $this->globalVariable = $globalVariable;
        $this->pageLayoutTemplate = $pageLayoutTemplate;
        $this->routePrefix = $routePrefix;
    }

    /**
     * Sets if the current siteaccess is an admin UI siteaccess
     */
    public function setIsAdminSiteAccess(bool $isAdminSiteAccess = false): void
    {
        $this->isAdminSiteAccess = $isAdminSiteAccess;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => 'onKernelRequest',
        ];
    }

    /**
     * Sets admin page layout configuration for current admin UI plugin
     */
    public function onKernelRequest(GetResponseEvent $event): void
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        if (!$this->isAdminSiteAccess) {
            return;
        }

        $currentRoute = $event->getRequest()->attributes->get('_route');
        if (!is_string($currentRoute) || mb_stripos($currentRoute, $this->routePrefix) !== 0) {
            return;
        }

        $this->globalVariable->setPageLayoutTemplate($this->pageLayoutTemplate);
    }
}
