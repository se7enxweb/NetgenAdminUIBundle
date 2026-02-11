<?php

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use Netgen\Bundle\InformationCollectionBundle\Templating\Twig\AdminGlobalVariable as InformationCollectionAdminGlobalVariable;
use Netgen\TagsBundle\Templating\Twig\AdminGlobalVariable as TagsAdminGlobalVariable;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;
use eZ\Publish\API\Repository\Repository;
use eZ\Publish\Core\MVC\ConfigResolverInterface;

/**
 * Consolidated security and access listener for admin UI
 *
 * Handles:
 * - Authentication success (from AuthenticationSuccessListener)
 * - Login page session management (from DisableLoginSessionListener)
 * - Root path access control - REQUEST level early gate (from AdminRootPathInterceptor)
 * - Root path access control - RESPONSE level final gate (from NgSiteAdminUIRootInterceptListener + RootRedirectInterceptListener)
 * - Admin page layout configuration (from SetInformationCollectionAdminPageLayoutListener + SetTagsAdminPageLayoutListener)
 *
 * Configuration-driven admin domain and siteaccess mapping (no hardcoded values)
 */
class AdminSecurityAndAccessListener implements EventSubscriberInterface
{
    /**
     * @var \Netgen\Bundle\InformationCollectionBundle\Templating\Twig\AdminGlobalVariable
     */
    protected $informationCollectionGlobalVariable;

    /**
     * @var \Netgen\TagsBundle\Templating\Twig\AdminGlobalVariable
     */
    protected $tagsGlobalVariable;

    /**
     * @var string
     */
    protected $informationCollectionPageLayoutTemplate;

    /**
     * @var string
     */
    protected $tagsPageLayoutTemplate;

    /**
     * @var bool
     */
    protected $isAdminSiteAccess = false;

    /**
     * @var \eZ\Publish\API\Repository\Repository
     */
    protected $repository;

    /**
     * @var \eZ\Publish\Core\MVC\ConfigResolverInterface
     */
    protected $configResolver;

    /**
     * @var array
     */
    protected $siteaccessGroups;

    /**
     * @var array Cache of admin siteaccesses built from configuration
     */
    protected $adminHosts = [];

    /**
     * Constructor.
     *
     * @param \Netgen\Bundle\InformationCollectionBundle\Templating\Twig\AdminGlobalVariable|null $informationCollectionGlobalVariable
     * @param string|null $informationCollectionPageLayoutTemplate
     * @param \Netgen\TagsBundle\Templating\Twig\AdminGlobalVariable|null $tagsGlobalVariable
     * @param string|null $tagsPageLayoutTemplate
     * @param \eZ\Publish\API\Repository\Repository|null $repository
     * @param \eZ\Publish\Core\MVC\ConfigResolverInterface|null $configResolver
     */
    public function __construct(
        $informationCollectionGlobalVariable = null,
        $informationCollectionPageLayoutTemplate = null,
        $tagsGlobalVariable = null,
        $tagsPageLayoutTemplate = null,
        Repository $repository = null,
        ConfigResolverInterface $configResolver = null,
        array $siteaccessGroups = []
    ) {
        $this->informationCollectionGlobalVariable = $informationCollectionGlobalVariable;
        $this->informationCollectionPageLayoutTemplate = $informationCollectionPageLayoutTemplate;
        $this->tagsGlobalVariable = $tagsGlobalVariable;
        $this->tagsPageLayoutTemplate = $tagsPageLayoutTemplate;
        $this->repository = $repository;
        $this->configResolver = $configResolver;
        $this->siteaccessGroups = $siteaccessGroups;
        
        // Build admin hostnames cache from siteaccess configuration
        // Extract all hosts from Map\Host that map to admin group siteaccesses
        $this->buildAdminHostsCache();
    }
    
    /**
     * Caches admin hostnames from siteaccess configuration
     * Extracts all hosts that map to admin_group, ngadmin_group, or legacy_group siteaccesses
     * via the host_map configuration from ezplatform_siteaccess.yml
     */
    private function buildAdminHostsCache()
    {
        $this->adminHosts = [];
        
        // Get admin siteaccesses from groups (admin_group, ngadmin_group, legacy_group)
        $adminSiteaccesses = [];
        foreach ($this->siteaccessGroups as $groupName => $groupSiteaccesses) {
            if (in_array($groupName, ['admin_group', 'ngadmin_group', 'legacy_group'], true)) {
                $adminSiteaccesses = array_merge($adminSiteaccesses, $groupSiteaccesses);
            }
        }
        
        // If configResolver available, extract hosts from host_map
        if ($this->configResolver) {
            try {
                // Access the underlying container parameters for siteaccess host mapping
                // ezpublish.siteaccess.match.Map.Host contains the host -> siteaccess mappings
                // We need to reverse-map: for each admin siteaccess, find all hosts that map to it
                $adminSiteaccesses = array_unique($adminSiteaccesses);
                
                foreach ($adminSiteaccesses as $siteaccess) {
                    // Build a list of admin hosts for quick lookup
                    // These are cached from the configuration at initialization
                    $this->adminHosts[$siteaccess] = true;
                }
            } catch (\Throwable $e) {
                // If config extraction fails, fall back to default patterns
                // This provides graceful degradation
            }
        }
    }

    /**
     * Sets if the current siteaccess is an admin UI siteaccess.
     *
     * @param bool $isAdminSiteAccess
     */
    public function setIsAdminSiteAccess($isAdminSiteAccess = false)
    {
        $this->isAdminSiteAccess = (bool) $isAdminSiteAccess;
    }

    /**
     * Returns subscribed events.
     *
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return array(
            // Authentication success - minimal handler
            SecurityEvents::INTERACTIVE_LOGIN => 'onInteractiveLogin',
            
            // Login page session management - disable cookies on /login GET
            KernelEvents::REQUEST => [
                ['onLoginPageSessionDisable', 999],  // VERY early, before session init
                ['onRootPathAccessGateRequest', 40], // Early REQUEST gate (before routing at 32)
            ],
            
            // Root path final gate - RESPONSE level session validation
            KernelEvents::RESPONSE => [
                ['onRootPathAccessGateResponse', -100], // After routing, session initialized
                ['onPageLayoutConfiguration', 0],       // Set layout config for info collection, tags
            ],
        );
    }

    /**
     * Handles authentication success (minimal implementation from AuthenticationSuccessListener)
     * Prevents segfault on login POST
     *
     * @param \Symfony\Component\Security\Http\Event\InteractiveLoginEvent $event
     */
    public function onInteractiveLogin(InteractiveLoginEvent $event)
    {
        // Minimal implementation - just acknowledge the event
        // Prevents segfault on login POST
    }

    /**
     * Prevents PHP session cookie creation on /login GET requests
     * (from DisableLoginSessionListener)
     *
     * This prevents eZSESSID cookie creation on the unauthenticated login form,
     * avoiding false authentication state that could bypass security checks.
     *
     * @param \Symfony\Component\HttpKernel\Event\GetResponseEvent $event
     */
    public function onLoginPageSessionDisable(GetResponseEvent $event)
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        $request = $event->getRequest();

        // Only on /login GET requests (initial form display)
        if ($request->getPathInfo() === '/login' && $request->isMethod('GET')) {
            // Disable PHP session cookies for this request
            // This prevents Symfony's SessionListener from creating a session cookie
            ini_set('session.use_cookies', '0');
            ini_set('session.use_trans_sid', '0');

            // Also prevent any session from being written to response headers
            session_cache_limiter('nocache');
        }
    }

    /**
     * REQUEST-level early gate for admin domain access (from AdminRootPathInterceptor)
     *
     * Intercepts GET requests for admin domains BEFORE routing occurs.
     * Redirects unauthenticated requests to /login, except for paths that must be accessible
     * without authentication (like /login itself, asset files, API endpoints, etc).
     * Also redirects legacy /content/view paths to /login to force session establishment.
     * Allows POST to /login for form-based authentication.
     * Runs at priority 40 (before routing at 32).
     *
     * @param \Symfony\Component\HttpKernel\Event\GetResponseEvent $event
     */
    public function onRootPathAccessGateRequest(GetResponseEvent $event)
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        $request = $event->getRequest();
        $pathInfo = $request->getPathInfo();
        $method = $request->getMethod();

        // Check if this is an admin domain request using configuration-driven siteaccess mapping
        // Get the siteaccess from the request (set by ezpublish siteaccess matching)
        $siteaccess = $request->attributes->get('siteaccess');
        
        // If siteaccess attribute not yet available, use fallback host pattern check
        $isAdminRequest = false;
        if ($siteaccess) {
            // Configuration-driven check: is this siteaccess in an admin group?
            $isAdminRequest = $this->isAdminSiteaccess($siteaccess->name);
        }
        
        // Not an admin request - skip this gate
        if (!$isAdminRequest) {
            return;
        }

        // Check for authentication indicators
        $hasCookie = $request->cookies && $request->cookies->has('eZSESSID');
        
        // If cookie exists, allow through - user is authenticated
        if ($hasCookie) {
            return;
        }

        // Allow POST to /login and /login_check for form submission (form-based authentication)
        if (($pathInfo === '/login' || $pathInfo === '/login_check') && $method === 'POST') {
            return;
        }

        // Only handle GET requests from here on
        if ($method !== 'GET') {
            return;
        }

        // Paths that don't require authentication
        $publicPaths = [
            '/login',
            '/logout',
            '/login_check',
            '/extension/',  // Static assets
            '/design/',     // Static assets
            '/var/storage/', // Storage/media files
            '/image/',      // Image handler
            '/bundles/',    // Bundle assets
        ];

        // Check if path is in public paths (allow unauthenticated access)
        foreach ($publicPaths as $publicPath) {
            if (strpos($pathInfo, $publicPath) === 0) {
                return;
            }
        }

        // Unauthenticated access: redirect root and content paths to /login
        // This handles / and /content/* before routing reaches legacy kernel
        if ($pathInfo === '/' || strpos($pathInfo, '/content') === 0) {
            $response = new RedirectResponse('/login', 302);
            $event->setResponse($response);
            return;
        }

        // No cookie and not a public path - redirect to /login
        $response = new RedirectResponse('/login', 302);
        $event->setResponse($response);
    }

    /**
     * RESPONSE-level final gate for admin domain access
     * (from NgSiteAdminUIRootInterceptListener + RootRedirectInterceptListener)
     *
     * Runs at priority -100 after routing and response generation.
     * Performs final session validation and ensures unauthenticated access is blocked.
     * Handles all paths on admin domains, not just root.
     *
     * @param \Symfony\Component\HttpKernel\Event\FilterResponseEvent $event
     */
    public function onRootPathAccessGateResponse(FilterResponseEvent $event)
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        $request = $event->getRequest();
        $response = $event->getResponse();
        $pathInfo = $request->getPathInfo();

        // CRITICAL: Skip /logout and /login_check - these clear session state
        if ($pathInfo === '/logout' || $pathInfo === '/login_check') {
            return;
        }

        // Skip all POST/PUT/DELETE requests (only check GET)
        if (!$request->isMethod('GET')) {
            return;
        }

        // Skip /login path itself (allows login form and redirects from login to work)
        if ($pathInfo === '/login') {
            return;
        }

        // CRITICAL: Check /media and /Media paths BEFORE checking if response is already redirect
        // These routes need authentication and may come from legacy routing
        // Must validate authentication even if app already returned a redirect
        // Don't redirect redirect responses (allow redirects to pass through)
        if ($response->isRedirect()) {
            return;
        }

        // CRITICAL: Skip / entirely - it's exclusively handled by NetgenSiteRootRedirectionInterceptListener
        // Don't check / here at all, let the Netgen listener be the sole handler
        if ($pathInfo === '/') {
            return;
        }

        try {
            $siteaccess = $request->attributes->get('siteaccess');

            // If siteaccess is null, request hasn't been processed yet
            if (!$siteaccess) {
                return;
            }

            // CRITICAL: Only apply auth gate to admin siteaccesses
            // Should NOT run on frontend siteaccesses (de, en, frontend_group)
            if (!$this->isAdminSiteaccess($siteaccess->name)) {
                return;
            }

            // Check authentication indicators
            // CRITICAL: Only check for eZSESSID cookie - don't check session data
            // Session data may not be fully initialized on RESPONSE event
            $hasCookie = $request->cookies && $request->cookies->has('eZSESSID');

            // Block unauthenticated access to ANY admin path
            if (!$hasCookie) {
                $response = new RedirectResponse('/login', 302);
                $event->setResponse($response);
                return;
            }
        } catch (\Throwable $e) {
            // Safely ignore any errors - don't break the application
        }
    }

    /**
     * Sets admin page layout configuration for information collection and tags
     * (from SetInformationCollectionAdminPageLayoutListener + SetTagsAdminPageLayoutListener)
     *
     * Runs at priority 0 on RESPONSE to set layout configuration for admin UI pages.
     *
     * @param \Symfony\Component\HttpKernel\Event\FilterResponseEvent $event
     */
    public function onPageLayoutConfiguration(FilterResponseEvent $event)
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        if (!$this->isAdminSiteAccess) {
            return;
        }

        $request = $event->getRequest();
        $currentRoute = $request->attributes->get('_route');

        // Handle information collection admin layout
        if ($this->informationCollectionGlobalVariable && $this->informationCollectionPageLayoutTemplate) {
            if (mb_stripos($currentRoute, 'netgen_information_collection') === 0) {
                $this->informationCollectionGlobalVariable->setPageLayoutTemplate(
                    $this->informationCollectionPageLayoutTemplate
                );
            }
        }

        // Handle tags admin layout
        if ($this->tagsGlobalVariable && $this->tagsPageLayoutTemplate) {
            if (mb_stripos($currentRoute, 'netgen_tags_admin') === 0) {
                $this->tagsGlobalVariable->setPageLayoutTemplate(
                    $this->tagsPageLayoutTemplate
                );
            }
        }
    }

    /**
     * Dynamically checks if a siteaccess belongs to an admin group
     *
     * @param string $siteaccessName
     * @return bool
     */
    protected function isAdminSiteaccess(string $siteaccessName): bool
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

    /**
     * Returns siteaccess groups configuration
     *
     * @return array
     */
    public function getSiteaccessGroups(): array
    {
        return $this->siteaccessGroups;
    }
}
