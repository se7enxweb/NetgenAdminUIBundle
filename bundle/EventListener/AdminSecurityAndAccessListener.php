<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use Netgen\Bundle\AdminUIBundle\Service\AdminUIConfiguration;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;

/**
 * AdminSecurityAndAccessListener
 *
 * Enforces authentication requirements for admin UI siteaccesses.
 *
 * Responsibilities:
 * - Checks if current request siteaccess is an admin siteaccess (admin_group, ngadmin_group, legacy_group)
 * - Blocks unauthenticated access by redirecting to login page
 * - Allows authenticated users to access protected resources
 * - Logs successful login events
 *
 * Siteaccess-based Security Model:
 * This listener is registered per-siteaccess. Each siteaccess instance checks whether its
 * current siteaccess belongs to an admin group. No hostname-based detection.
 *
 * Event Flow:
 * 1. Symfony security firewall authenticates user (loads token from session)
 * 2. REQUEST listener checks if current siteaccess is admin
 * 3. If unauthenticated and not on /login or /login_check → redirect to /login
 * 4. If authenticated or on exempted paths → allow through
 * 5. form_login configuration (security.yaml) handles login form processing and redirect
 */
class AdminSecurityAndAccessListener implements EventSubscriberInterface
{    
    private array $siteaccessGroups;
    private ?AdminUIConfiguration $adminUIConfig;
    private ?TokenStorageInterface $tokenStorage;
    private ?LoggerInterface $logger;

    public function __construct(
        array $siteaccessGroups = [],
        ?AdminUIConfiguration $adminUIConfig = null,
        ?TokenStorageInterface $tokenStorage = null,
        ?LoggerInterface $logger = null,
    ) {
        $this->siteaccessGroups = $siteaccessGroups;
        $this->adminUIConfig = $adminUIConfig;
        $this->tokenStorage = $tokenStorage;
        $this->logger = $logger;
    }

    /**
     * Check if the current request siteaccess is an admin siteaccess
     * 
     * This listener is registered per-siteaccess. Each siteaccess instance checks
     * if its own siteaccess belongs to an admin group (admin_group, ngadmin_group, legacy_group).
     * 
     * This eliminates hostname-based detection - authentication is now purely siteaccess-based.
     */
    private function isAdminSiteaccess(string $currentSiteaccess): bool
    {
        // Check if current siteaccess belongs to an admin group
        foreach ($this->siteaccessGroups as $groupName => $groupSiteaccesses) {
            if ($this->adminUIConfig?->isAdminGroupName($groupName)) {
                if (in_array($currentSiteaccess, $groupSiteaccesses, true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if the current user is authenticated
     * 
     * Validates via TokenStorage:
     * - Token exists and is authenticated
     * - Token user is not anonymous
     * - Special check for AnonymousToken (isAuthenticated() returns true but means unauthenticated)
     */
    private function isUserAuthenticated(): bool
    {
        if (!$this->tokenStorage) {
            return false;
        }

        $token = $this->tokenStorage->getToken();
        if (!$token) {
            return false;
        }

        // Explicitly reject AnonymousToken
        if (str_contains(get_class($token), 'AnonymousToken')) {
            return false;
        }

        if (!$token->isAuthenticated()) {
            return false;
        }

        // User must exist and not be a string
        $user = $token->getUser();
        return $user !== null && !is_string($user);
    }

    public static function getSubscribedEvents(): array
    {
        return [
            SecurityEvents::INTERACTIVE_LOGIN => 'onInteractiveLogin',
            KernelEvents::REQUEST => [
                ['onRootPathAccessGateRequest', -1],  // After security firewall (priority 5)
            ],
        ];
    }

    /**
     * Log successful user login with username
     */
    public function onInteractiveLogin(InteractiveLoginEvent $event): void
    {
        $user = $event->getAuthenticationToken()->getUser();
        $username = method_exists($user, 'getUsername') ? $user->getUsername() : (string)$user;
        
        $this->logger?->info('Admin UI login: ' . $username);
    }

    /**
     * Gate REQUEST: Block unauthenticated access to admin siteaccesses
     *
     * Exemptions:
     * - /login (GET/POST) - login page itself
     * - /logout (GET/POST) - logout endpoint
     * - /login_check (POST) - form_login handles this
     * - /_wdt/* - WebProfiler toolbar (dev tool, needs access)
     * - /_profiler/* - Symfony profiler (dev tool, needs access)
     * 
     * Processing:
     * 1. Get current siteaccess from request attributes
     * 2. Check if this siteaccess is an admin siteaccess
     * 3. Verify user is authenticated (via TokenStorage)
     * 4. If unauthenticated and not exempted → redirect to /login
     * 5. Otherwise → allow through
     */
    public function onRootPathAccessGateRequest(GetResponseEvent $event): void
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        $request = $event->getRequest();
        $pathInfo = $request->getPathInfo();

        // Get configured paths
        $loginPath = $this->adminUIConfig?->getLoginPath() ?? '/login';
        $logoutPath = $this->adminUIConfig?->getLogoutPath() ?? '/logout';
        $loginCheckPath = $this->adminUIConfig?->getLoginCheckPath() ?? '/login_check';

        // Exempt authentication-related paths
        if ($pathInfo === $loginPath || $pathInfo === $logoutPath || $pathInfo === $loginCheckPath) {
            return;
        }

        // Exempt dev tools (WebProfiler toolbar, Symfony profiler)
        if (str_starts_with($pathInfo, '/_wdt') || str_starts_with($pathInfo, '/_profiler')) {
            return;
        }

        // Get current siteaccess from request
        $siteAccessObj = $request->attributes->get('siteaccess');
        if (!$siteAccessObj) {
            return;  // No siteaccess in request (shouldn't happen in normal flow)
        }

        $currentSiteaccess = $siteAccessObj->name;

        // Only enforce on admin siteaccesses
        if (!$this->isAdminSiteaccess($currentSiteaccess)) {
            return;
        }

        // Block unauthenticated access
        if (!$this->isUserAuthenticated()) {
            $this->logger?->info('Blocking unauthenticated admin access: ' . $pathInfo);
            $event->setResponse(new RedirectResponse($loginPath, RedirectResponse::HTTP_FOUND));
        }
    }
}

