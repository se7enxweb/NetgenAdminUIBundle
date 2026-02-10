<?php

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use eZ\Publish\API\Repository\Repository;
use eZ\Publish\Core\MVC\ConfigResolverInterface;

class AdminUISiteAccessRootRedirectionInterceptListener implements EventSubscriberInterface
{
    private $repository;
    private $configResolver;
    private $httpKernel;
    private $siteaccessGroups;
    
    public function __construct(
        Repository $repository,
        ConfigResolverInterface $configResolver = null,
        HttpKernelInterface $httpKernel = null,
        array $siteaccessGroups = []
    ) {
        $this->repository = $repository;
        $this->configResolver = $configResolver;
        $this->httpKernel = $httpKernel;
        $this->siteaccessGroups = $siteaccessGroups;
    }

    public static function getSubscribedEvents()
    {
        return array(
            KernelEvents::RESPONSE => 'onKernelResponse',
        );
    }

    public function onKernelResponse(FilterResponseEvent $event)
    {
        // Only process master requests
        if (!$event->isMasterRequest()) {
            return;
        }

        $request = $event->getRequest();
        $pathInfo = $request->getPathInfo();
        
        // CRITICAL: Skip /logout and /login_check - these clear session state
        if ($pathInfo === '/logout' || $pathInfo === '/login_check') {
            return;
        }
        
        try {
            $siteaccess = $request->attributes->get('siteaccess');
            
            // If siteaccess is null, request hasn't been processed yet
            if (!$siteaccess) {
                return;
            }
            
            // ONLY apply auth gate to root path
            if ($pathInfo !== '/') {
                return;
            }
            
            // CRITICAL: Only handle admin siteaccesses
            if (!$this->isAdminSiteaccess($siteaccess->name)) {
                return;
            }
            
            // For ngadminui at /, check if authenticated
            // CRITICAL: Only check for eZSESSID cookie - don't check session data
            // Session data may not be fully initialized on RESPONSE event
            $hasCookie = $request->cookies && $request->cookies->has('eZSESSID');
            
            if (!$hasCookie) {
                $response = new RedirectResponse('/login', 302);
                $event->setResponse($response);
                return;
            }
        } catch (\Throwable $e) {
            // Safely ignore errors
            return;
        }
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
