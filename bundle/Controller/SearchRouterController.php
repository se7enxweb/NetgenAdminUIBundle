<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\Controller;

use Netgen\Bundle\SiteBundle\Controller\SearchController as NgSiteSearchController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use eZ\Bundle\EzPublishLegacyBundle\Controller\LegacyKernelController;

/**
 * Search controller that routes to legacy or ngsite based on siteaccess
 */
class SearchRouterController
{
    private NgSiteSearchController $ngSiteSearchController;
    private LegacyKernelController $legacyController;

    public function __construct(
        NgSiteSearchController $ngSiteSearchController,
        LegacyKernelController $legacyController
    ) {
        $this->ngSiteSearchController = $ngSiteSearchController;
        $this->legacyController = $legacyController;
    }

    public function search(Request $request): Response
    {
        // Check if request is marked for legacy search (admin siteaccess)
        if ($request->attributes->getBoolean('_use_legacy_search', false)) {
            return $this->legacyController->indexAction($request);
        }

        // Otherwise use ngsite search (user siteaccess)
        return $this->ngSiteSearchController->search($request);
    }
}
