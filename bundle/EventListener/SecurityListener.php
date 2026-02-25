<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use eZ\Publish\API\Repository\Repository;
use eZ\Publish\Core\MVC\ConfigResolverInterface;
use eZ\Publish\Core\MVC\Legacy\Event\PostBuildKernelEvent;
use eZ\Publish\Core\MVC\Legacy\LegacyEvents;
use ezpWebBasedKernelHandler;
use Netgen\Bundle\AdminUIBundle\Service\AdminUIConfiguration;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

class SecurityListener implements EventSubscriberInterface
{
    private RequestStack $requestStack;
    private Repository $repository;
    private ConfigResolverInterface $configResolver;
    private TokenStorageInterface $tokenStorage;
    private AuthorizationCheckerInterface $authorizationChecker;
    private AdminUIConfiguration $adminUIConfiguration;
    /** @var array<string, string[]> Siteaccess groups from %ezpublish.siteaccess.groups% */
    private array $siteaccessGroups;

    public function __construct(
        RequestStack $requestStack,
        Repository $repository,
        ConfigResolverInterface $configResolver,
        TokenStorageInterface $tokenStorage,
        AuthorizationCheckerInterface $authorizationChecker,
        AdminUIConfiguration $adminUIConfiguration,
        array $siteaccessGroups = []
    ) {
        $this->requestStack = $requestStack;
        $this->repository = $repository;
        $this->configResolver = $configResolver;
        $this->tokenStorage = $tokenStorage;
        $this->authorizationChecker = $authorizationChecker;
        $this->adminUIConfiguration = $adminUIConfiguration;
        $this->siteaccessGroups = $siteaccessGroups;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            // Priority 11: must run BEFORE eZ Platform's URL-alias forward listener (priority 10).
            // That listener calls $event->getKernel()->handle($forwardRequest) and then
            // $event->stopPropagation(), which means any listener at priority ≤ 10 never fires.
            // Because we run before the security firewall context listener (priority 8), the
            // TokenStorage is not yet populated — authentication is checked via the session directly.
            KernelEvents::REQUEST                  => ['onKernelRequest', 11],
            LegacyEvents::POST_BUILD_LEGACY_KERNEL => ['onKernelBuilt', 255],
        ];
    }

    /**
     * Internal Symfony path prefixes that must never be used as a login redirect target.
     * Also covers eZ Platform internal content view paths that the user never visited
     * directly (produced by the URL-alias redirect, e.g. /content/view/full/2).
     */
    private const INTERNAL_PATH_PREFIXES = [
        '/_wdt',
        '/_profiler',
        '/_error',
        '/kernel',
        '/content/view/full/',
        '/content/view/embed/',
        '/content/view/plain/',
    ];

    /**
     * Redirects unauthenticated users to the login page for any route that
     * is not a public/static-asset path, preventing the legacy login screen
     * from appearing (e.g. on "/" or "/content/search").
     */
    public function onKernelRequest(GetResponseEvent $event): void
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        $request  = $event->getRequest();
        $pathInfo = $request->getPathInfo();

        // Only enforce the admin login redirect for siteaccesses that belong to an
        // admin group (ngadmin_group, admin_group, legacy_group — as declared in
        // app/config yaml). Frontend/user siteaccesses (e.g. 'en') are left alone.
        $siteaccess = $request->attributes->get('siteaccess');
        if ($siteaccess !== null && !$this->isAdminSiteaccess($siteaccess->name)) {
            return;
        }

        // Guard: allow auth-related paths even when they carry a siteaccess prefix.
        // e.g. /ngadminui/login must be treated the same as /login.
        // We use suffix matching so /{siteaccess}/login is recognised correctly.
        if ($this->isAuthPathWithSiteaccess($pathInfo)) {
            return;
        }

        // Skip internal Symfony paths (toolbar, profiler, error pages) entirely —
        // do not redirect and do not store them as a login target.
        foreach (self::INTERNAL_PATH_PREFIXES as $prefix) {
            if (strpos($pathInfo, $prefix) === 0) {
                return;
            }
        }

        // Allow static-asset prefixes from the public_paths config (e.g. /bundles/, /design/)
        // We skip the bare "/" entry so the root path itself is still protected.
        foreach ($this->adminUIConfiguration->getPublicPaths() as $publicPath) {
            if ($publicPath !== '/' && strpos($pathInfo, $publicPath) === 0) {
                return;
            }
        }

        if ($this->isUserAuthenticated()) {
            return;
        }

        // Build the login redirect as an absolute URL — scheme + host + siteaccess base + /login.
        // Using getSchemeAndHttpHost() + getBaseUrl() is unambiguous regardless of whether
        // the siteaccess is matched by path, host, or port.
        $loginUrl = $request->getSchemeAndHttpHost()
            . $request->getBaseUrl()
            . $this->adminUIConfiguration->getLoginPath();

        if ($request->hasSession()) {
            $session        = $request->getSession();
            $sessionKey     = '_security.ezpublish_front.target_path';
            $existingTarget = $session->get($sessionKey, '');

            // Store the full absolute URL of the original request as the post-login target.
            // getUri() returns scheme + host + path + query — no manual assembly needed.
            $originalUri = $request->getUri();

            // Only write when empty or currently an auth URL (would loop).
            if (!$existingTarget || $this->isAuthPathWithSiteaccess(parse_url($existingTarget, PHP_URL_PATH) ?? $existingTarget)) {
                // If the original URI is an eZ internal content/view path (produced by the
                // URL-alias forward), store "/" instead so the user lands on the home page.
                $storedUri = (strpos($request->getPathInfo(), '/content/view/full/2') === 0)
                    ? $request->getSchemeAndHttpHost() . $request->getBaseUrl() . '/'
                    : $originalUri;
                $session->set($sessionKey, $storedUri);
            }
        }

        $event->setResponse(new RedirectResponse($loginUrl));
    }

    /**
     * Returns true when the named siteaccess belongs to one of the configured
     * admin siteaccess groups (ngadmin_group, admin_group, legacy_group, …).
     * Mirrors the identical check in SearchRouteListener.
     */
    private function isAdminSiteaccess(string $siteaccessName): bool
    {
        foreach ($this->adminUIConfiguration->getAdminGroupNames() as $adminGroup) {
            if (
                isset($this->siteaccessGroups[$adminGroup]) &&
                in_array($siteaccessName, $this->siteaccessGroups[$adminGroup], true)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true when $path matches any auth path (login / logout / login_check),
     * supporting an optional leading siteaccess segment, e.g. /ngadminui/login.
     * Uses suffix matching: the path must end with one of the configured auth suffixes.
     */
    private function isAuthPathWithSiteaccess(string $path): bool
    {
        foreach ([
            $this->adminUIConfiguration->getLoginPath(),
            $this->adminUIConfiguration->getLogoutPath(),
            $this->adminUIConfiguration->getLoginCheckPath(),
        ] as $authSuffix) {
            // Exact match (e.g. /login) or with siteaccess prefix (e.g. /ngadminui/login)
            if ($path === $authSuffix || substr($path, -strlen($authSuffix)) === $authSuffix) {
                return true;
            }
        }

        return false;
    }

    /**
     * Performs actions related to security once the legacy kernel has been built.
     */
    public function onKernelBuilt(PostBuildKernelEvent $event): void
    {
        $currentRequest = $this->requestStack->getCurrentRequest();

        // Ignore if not in web context, if legacy_mode is active or if user is not authenticated
        if (
            $currentRequest === null
            || !$event->getKernelHandler() instanceof ezpWebBasedKernelHandler
            || $this->configResolver->getParameter('legacy_mode') === true
            || !$this->isUserAuthenticated()
        ) {
            return;
        }

        // Set eZUserLoggedInID session variable for legacy kernel
        // This is needed for RequireUserLogin to work properly in legacy views
        $currentRequest->getSession()->set(
            'eZUserLoggedInID',
            $this->repository->getCurrentUser()->id
        );
    }

    /**
     * Checks if the current user is authenticated.
     *
     * Primary: uses the TokenStorage (populated by the security firewall at priority 8).
     * Fallback: reads the serialized token directly from the session when the security
     * context listener has not run yet (i.e., when we fire at priority > 8).
     * The firewall session key for "ezpublish_front" is "_security_ezpublish_front".
     */
    protected function isUserAuthenticated(): bool
    {
        // Primary path: TokenStorage already populated (priority ≤ 8)
        $token = $this->tokenStorage->getToken();
        if ($token instanceof TokenInterface) {
            return $this->authorizationChecker->isGranted('IS_AUTHENTICATED_REMEMBERED');
        }

        // Fallback path: read the serialized token from the session directly.
        // Used when we run at priority > 8, before the security context listener.
        $request = $this->requestStack->getCurrentRequest();
        if ($request === null || !$request->hasSession()) {
            return false;
        }

        $session = $request->getSession();
        $tokenData = $session->get('_security_ezpublish_front');

        if ($tokenData === null) {
            return false;
        }

        // If the serialized token does not identify an AnonymousToken, the user
        // logged in with real credentials and is considered authenticated.
        return strpos($tokenData, 'AnonymousToken') === false;
    }
}
