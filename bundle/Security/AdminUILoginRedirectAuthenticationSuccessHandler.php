<?php

namespace Netgen\Bundle\AdminUIBundle\Security;

use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\RouterInterface;

class AdminUILoginRedirectAuthenticationSuccessHandler implements AuthenticationSuccessHandlerInterface
{
    private $router;

    public function __construct(RouterInterface $router)
    {
        $this->router = $router;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        // Check if this is the nga admin siteaccess by checking host or attributes
        $isNgaAdminUI = false;
        
        // Method 1: Check siteaccess attribute (set if available)
        if ($request->attributes->has('siteaccess')) {
            $siteaccess = $request->attributes->get('siteaccess');
            $isNgaAdminUI = ($siteaccess->name === 'ngadminui');
        }
        
        // Method 2: Check hostname (nga.platform.cjw.alpha.se7enx.com)
        if (!$isNgaAdminUI) {
            $host = $request->getHost();
            $isNgaAdminUI = (strpos($host, 'nga.') === 0);
        }
        
        if ($isNgaAdminUI) {
            // Redirect authenticated users to /content/dashboard
            return new RedirectResponse('/content/dashboard');
        }

        // Default behavior - redirect to homepage
        return new RedirectResponse('/');
    }
}
