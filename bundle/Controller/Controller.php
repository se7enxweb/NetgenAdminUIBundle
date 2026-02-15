<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\Controller;

use eZ\Bundle\EzPublishCoreBundle\Controller as BaseController;

/**
 * Base controller for admin UI
 *
 * Note: The old initialize() and setContainer() pattern is deprecated.
 * Modern Symfony uses dependency injection via constructor instead.
 * Controllers can simply extend BaseController or use DI directly.
 */
abstract class Controller extends BaseController
{
    /**
     * Sub-classes providing content access control should override and implement
     * their own permission checking logic using the AuthorizationChecker
     * or similar modern Symfony security mechanisms.
     */
    protected function checkPermissions(): void
    {
        // Legacy method kept for backward compatibility
        // Override in subclasses to implement specific permission checks
    }
}

