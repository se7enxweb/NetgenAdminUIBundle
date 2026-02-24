<?php

namespace Netgen\Bundle\AdminUIBundle\DependencyInjection\CompilerPass;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Disables the UrlAliasRouter for ngadminui siteaccess (and its group).
 *
 * In legacy_mode: false, EzPublishLegacyExtension sets url_alias_router=true
 * for the ngadminui scope. This causes UrlAliasRouter to intercept content
 * URLs (e.g. /JAC-Example/Startseite) and issue a 301 redirect instead of
 * letting the FallbackRouter (ez_legacy) serve them via LegacyKernelController.
 *
 * By forcing url_alias_router=false for the ngadmin scopes (same as what
 * legacy_mode: true does internally), content URLs fall through to FallbackRouter
 * and are rendered by the legacy kernel — exactly like /shop/orderlist works.
 *
 * This compiler pass runs after all extensions have processed their config,
 * overriding the value set by EzPublishLegacyExtension::load().
 */
class AdminUIUrlAliasRouterPass implements CompilerPassInterface
{
    // The ezsettings scope names used in ngadminui.yml for ez_publish_legacy.system
    private static $scopes = [
        'ngadmin_group',
        'ngadminui',
    ];

    public function process(ContainerBuilder $container)
    {
        foreach (self::$scopes as $scope) {
            $paramName = sprintf('ezsettings.%s.url_alias_router', $scope);
            // Force url_alias_router=false so UrlAliasRouter skips these requests
            // and FallbackRouter (ez_legacy) handles content URLs via LegacyKernelController.
            $container->setParameter($paramName, false);
        }
    }
}
