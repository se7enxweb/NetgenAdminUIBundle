<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\EventListener;

use eZ\Publish\API\Repository\Repository;
use eZ\Publish\Core\MVC\ConfigResolverInterface;
use eZ\Publish\Core\MVC\Legacy\Event\PostBuildKernelEvent;
use eZ\Publish\Core\MVC\Legacy\LegacyEvents;
use ezpWebBasedKernelHandler;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RequestStack;
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

    public function __construct(
        RequestStack $requestStack,
        Repository $repository,
        ConfigResolverInterface $configResolver,
        TokenStorageInterface $tokenStorage,
        AuthorizationCheckerInterface $authorizationChecker
    ) {
        $this->requestStack = $requestStack;
        $this->repository = $repository;
        $this->configResolver = $configResolver;
        $this->tokenStorage = $tokenStorage;
        $this->authorizationChecker = $authorizationChecker;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LegacyEvents::POST_BUILD_LEGACY_KERNEL => ['onKernelBuilt', 255],
        ];
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
