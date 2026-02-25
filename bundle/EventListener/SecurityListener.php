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

    public function __construct(
        RequestStack $requestStack,
        Repository $repository,
        ConfigResolverInterface $configResolver,
        TokenStorageInterface $tokenStorage,
        AuthorizationCheckerInterface $authorizationChecker,
        AdminUIConfiguration $adminUIConfiguration
    ) {
        $this->requestStack = $requestStack;
        $this->repository = $repository;
        $this->configResolver = $configResolver;
        $this->tokenStorage = $tokenStorage;
        $this->authorizationChecker = $authorizationChecker;
        $this->adminUIConfiguration = $adminUIConfiguration;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST                  => ['onKernelRequest', 64],
            LegacyEvents::POST_BUILD_LEGACY_KERNEL => ['onKernelBuilt', 255],
        ];
    }

    /**
     * Redirects unauthenticated users visiting the root path to the login page,
     * preventing the legacy login screen from being rendered.
     */
    public function onKernelRequest(GetResponseEvent $event): void
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        $pathInfo = $event->getRequest()->getPathInfo();

        // Only intercept the root path
        if ($pathInfo !== $this->adminUIConfiguration->getRootPath()) {
            return;
        }

        // Already authenticated – let the request proceed normally
        if ($this->isUserAuthenticated()) {
            return;
        }

        // Redirect anonymous visitors of "/" to the Symfony login page
        $event->setResponse(
            new RedirectResponse($this->adminUIConfiguration->getLoginPath())
        );
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
     * Checks if user is authenticated via IS_AUTHENTICATED_REMEMBERED role
     */
    protected function isUserAuthenticated(): bool
    {
        return $this->tokenStorage->getToken() instanceof TokenInterface
            && $this->authorizationChecker->isGranted('IS_AUTHENTICATED_REMEMBERED');
    }
}
